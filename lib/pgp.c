/*
 * Copyright (C) 2011 Red Hat, Inc. All Rights Reserved.
 * Copyright (C) 2018 Huawei Technologies Duesseldorf GmbH
 *
 * Authors:
 *   David Howells <dhowells@redhat.com>
 *   Roberto Sassu <roberto.sassu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: pgp.c
 *      Parse PGP packets.
 */
#include <unistd.h>
#include <linux/kernel.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "pgp.h"

#define BIT_WORD(nr)               ((nr) / __BITS_PER_LONG)
#define BIT_MASK(nr)            (1UL << ((nr) % __BITS_PER_LONG))

/**
 * test_bit - Determine whether a bit is set
 * @nr: bit number to test
 * @addr: Address to start counting from
 */
static inline int test_bit(int nr, const volatile unsigned long *addr)
{
        return 1UL & (addr[BIT_WORD(nr)] >> (nr & (__BITS_PER_LONG-1)));
}

static inline void __set_bit(int nr, volatile unsigned long *addr)
{
        unsigned long mask = BIT_MASK(nr);
        unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);

        *p  |= mask;
}

/**
 * pgp_parse_packet_header - Parse a PGP packet header
 * @_data: Start of the PGP packet (updated to PGP packet data)
 * @_datalen: Amount of data remaining in buffer (decreased)
 * @_type: Where the packet type will be returned
 * @_headerlen: Where the header length will be returned
 *
 * Parse a set of PGP packet header [RFC 4880: 4.2].
 *
 * Returns packet data size on success; non-zero on error.  If successful,
 * *_data and *_datalen will have been updated and *_headerlen will be set to
 * hold the length of the packet header.
 */
ssize_t pgp_parse_packet_header(const u8 **_data, size_t *_datalen,
				enum pgp_packet_tag *_type,
				u8 *_headerlen)
{
	enum pgp_packet_tag type;
	const u8 *data = *_data;
	size_t size, datalen = *_datalen;

	pr_devel("-->pgp_parse_packet_header(,%zu,,)\n", datalen);

	if (datalen < 2)
		goto short_packet;

	pr_devel("pkthdr %02x, %02x\n", data[0], data[1]);

	type = *data++;
	datalen--;
	if (!(type & 0x80)) {
		pr_debug("Packet type does not have MSB set\n");
		return -EBADMSG;
	}
	type &= ~0x80;

	if (type & 0x40) {
		/* New packet length format */
		type &= ~0x40;
		pr_devel("new format: t=%u\n", type);
		switch (data[0]) {
		case 0x00 ... 0xbf:
			/* One-byte length */
			size = data[0];
			data++;
			datalen--;
			*_headerlen = 2;
			break;
		case 0xc0 ... 0xdf:
			/* Two-byte length */
			if (datalen < 2)
				goto short_packet;
			size = (data[0] - 192) * 256;
			size += data[1] + 192;
			data += 2;
			datalen -= 2;
			*_headerlen = 3;
			break;
		case 0xff:
			/* Five-byte length */
			if (datalen < 5)
				goto short_packet;
			size =  data[1] << 24;
			size |= data[2] << 16;
			size |= data[3] << 8;
			size |= data[4];
			data += 5;
			datalen -= 5;
			*_headerlen = 6;
			break;
		default:
			pr_debug("Partial body length packet not supported\n");
			return -EBADMSG;
		}
	} else {
		/* Old packet length format */
		u8 length_type = type & 0x03;
		type >>= 2;
		pr_devel("old format: t=%u lt=%u\n", type, length_type);

		switch (length_type) {
		case 0:
			/* One-byte length */
			size = data[0];
			data++;
			datalen--;
			*_headerlen = 2;
			break;
		case 1:
			/* Two-byte length */
			if (datalen < 2)
				goto short_packet;
			size  = data[0] << 8;
			size |= data[1];
			data += 2;
			datalen -= 2;
			*_headerlen = 3;
			break;
		case 2:
			/* Four-byte length */
			if (datalen < 4)
				goto short_packet;
			size  = data[0] << 24;
			size |= data[1] << 16;
			size |= data[2] << 8;
			size |= data[3];
			data += 4;
			datalen -= 4;
			*_headerlen = 5;
			break;
		default:
			pr_debug("Indefinite length packet not supported\n");
			return -EBADMSG;
		}
	}

	pr_devel("datalen=%zu size=%zu", datalen, size);
	if (datalen < size)
		goto short_packet;
	if ((int)size < 0)
		goto too_big;

	*_data = data;
	*_datalen = datalen;
	*_type = type;
	pr_devel("Found packet type=%u size=%zd\n", type, size);
	return size;

short_packet:
	pr_debug("Attempt to parse short packet\n");
	return -EBADMSG;
too_big:
	pr_debug("Signature subpacket size >2G\n");
	return -EMSGSIZE;
}

struct pgp_parse_sig_params_ctx {
	struct pgp_parse_sig_context base;
	struct pgp_sig_parameters *params;
	bool got_the_issuer;
};

/**
 * pgp_parse_sig_subpkt_header - Parse a PGP V4 signature subpacket header
 * @_data: Start of the subpacket (updated to subpacket data)
 * @_datalen: Amount of data remaining in buffer (decreased)
 * @_type: Where the subpacket type will be returned
 *
 * Parse a PGP V4 signature subpacket header [RFC 4880: 5.2.3.1].
 *
 * Returns packet data size on success; non-zero on error.  If successful,
 * *_data and *_datalen will have been updated and *_headerlen will be set to
 * hold the length of the packet header.
 */
static ssize_t pgp_parse_sig_subpkt_header(const u8 **_data, size_t *_datalen,
					   enum pgp_sig_subpkt_type *_type)
{
	enum pgp_sig_subpkt_type type;
	const u8 *data = *_data;
	size_t size, datalen = *_datalen;

	pr_devel("-->%s(,%zu,,)\n", __func__, datalen);

	if (datalen < 2)
		goto short_subpacket;

	pr_devel("subpkt hdr %02x, %02x\n", data[0], data[1]);

	switch (data[0]) {
	case 0x00 ... 0xbf:
		/* One-byte length */
		size = data[0];
		data++;
		datalen--;
		break;
	case 0xc0 ... 0xfe:
		/* Two-byte length */
		if (datalen < 3)
			goto short_subpacket;
		size = (data[0] - 192) * 256;
		size += data[1] + 192;
		data += 2;
		datalen -= 2;
		break;
	case 0xff:
		if (datalen < 6)
			goto short_subpacket;
		size  = data[1] << 24;
		size |= data[2] << 16;
		size |= data[3] << 8;
		size |= data[4];
		data += 5;
		datalen -= 5;
		break;
	}

	/* The type octet is included in the size */
	pr_devel("datalen=%zu size=%zu\n", datalen, size);
	if (datalen < size)
		goto short_subpacket;
	if (size == 0)
		goto very_short_subpacket;
	if ((int)size < 0)
		goto too_big;

	type = *data++ & ~PGP_SIG_SUBPKT_TYPE_CRITICAL_MASK;
	datalen--;
	size--;

	*_data = data;
	*_datalen = datalen;
	*_type = type;
	pr_devel("Found subpkt type=%u size=%zd\n", type, size);
	return size;

very_short_subpacket:
	pr_debug("Signature subpacket size can't be zero\n");
	return -EBADMSG;
short_subpacket:
	pr_debug("Attempt to parse short signature subpacket\n");
	return -EBADMSG;
too_big:
	pr_debug("Signature subpacket size >2G\n");
	return -EMSGSIZE;
}

/**
 * pgp_parse_sig_subpkts - Parse a set of PGP V4 signatute subpackets
 * @_data: Data to be parsed (updated)
 * @_datalen: Amount of data (updated)
 * @ctx: Parsing context
 *
 * Parse a set of PGP signature subpackets [RFC 4880: 5.2.3].
 */
static int pgp_parse_sig_subpkts(const u8 *data, size_t datalen,
				 struct pgp_parse_sig_context *ctx)
{
	enum pgp_sig_subpkt_type type;
	ssize_t pktlen;
	int ret;

	pr_devel("-->%s(,%zu,,)\n", __func__, datalen);

	while (datalen > 2) {
		pktlen = pgp_parse_sig_subpkt_header(&data, &datalen, &type);
		if (pktlen < 0)
			return pktlen;
		if (test_bit(type, ctx->types_of_interest)) {
			ret = ctx->process_packet(ctx, type, data, pktlen);
			if (ret < 0)
				return ret;
		}
		data += pktlen;
		datalen -= pktlen;
	}

	if (datalen != 0) {
		pr_debug("Excess octets in signature subpacket stream\n");
		return -EBADMSG;
	}

	return 0;
}

/*
 * Process a V4 signature subpacket.
 */
static int pgp_process_sig_params_subpkt(struct pgp_parse_sig_context *context,
					 enum pgp_sig_subpkt_type type,
					 const u8 *data,
					 size_t datalen)
{
	struct pgp_parse_sig_params_ctx *ctx =
		container_of(context, struct pgp_parse_sig_params_ctx, base);

	if (ctx->got_the_issuer) {
		pr_debug("V4 signature packet has multiple issuers\n");
		return -EBADMSG;
	}

	if (datalen != 8) {
		pr_debug("V4 signature issuer subpkt not 8 long (%zu)\n",
			   datalen);
		return -EBADMSG;
	}

	memcpy(&ctx->params->issuer, data, 8);
	ctx->got_the_issuer = true;
	return 0;
}

/**
 * pgp_parse_sig_params - Parse basic parameters from a PGP signature packet
 * @_data: Content of packet (updated)
 * @_datalen: Length of packet remaining (updated)
 * @p: The basic parameters
 *
 * Parse the basic parameters from a PGP signature packet [RFC 4880: 5.2] that
 * are needed to start off a signature verification operation.  The only ones
 * actually necessary are the signature type (which affects how the data is
 * transformed) and the hash algorithm.
 *
 * We also extract the public key algorithm and the issuer's key ID as we'll
 * need those to determine if we actually have the public key available.  If
 * not, then we can't verify the signature anyway.
 *
 * Returns 0 if successful or a negative error code.  *_data and *_datalen are
 * updated to point to the 16-bit subset of the hash value and the set of MPIs.
 */
int pgp_parse_sig_params(const u8 **_data, size_t *_datalen,
			 struct pgp_sig_parameters *p,
			 const u8 **hashed, size_t *hashedlen)
{
	const u8 *data = *_data;
	size_t datalen = *_datalen;
	int ret;

	pr_devel("-->%s(,%zu,,)\n", __func__, datalen);

	if (datalen < 1)
		return -EBADMSG;
	p->version = *data;

	if (p->version == PGP_SIG_VERSION_3) {
		const struct pgp_signature_v3_packet *v3 = (const void *)data;

		if (datalen < sizeof(*v3)) {
			pr_debug("Short V3 signature packet\n");
			return -EBADMSG;
		}

		*hashedlen = v3->length_of_hashed;
		*hashed = (u8 *)&v3->hashed;

		datalen -= sizeof(*v3);
		data += sizeof(*v3);

		/* V3 has everything we need in the header */
		p->signature_type = v3->hashed.signature_type;
		memcpy(&p->issuer, &v3->issuer, 8);
		p->pubkey_algo = v3->pubkey_algo;
		p->hash_algo = v3->hash_algo;

	} else if (p->version == PGP_SIG_VERSION_4) {
		const struct pgp_signature_v4_packet *v4 = (const void *)data;
		struct pgp_parse_sig_params_ctx ctx = {
			.base.process_packet = pgp_process_sig_params_subpkt,
			.params = p,
			.got_the_issuer = false,
		};
		size_t subdatalen;

		if (datalen < sizeof(*v4) + 2 + 2 + 2) {
			pr_debug("Short V4 signature packet\n");
			return -EBADMSG;
		}
		datalen -= sizeof(*v4);
		data += sizeof(*v4);

		/* V4 has most things in the header... */
		p->signature_type = v4->signature_type;
		p->pubkey_algo = v4->pubkey_algo;
		p->hash_algo = v4->hash_algo;

		/* ... but we have to get the key ID from the subpackets, of
		 * which there are two sets.
		 */
		__set_bit(PGP_SIG_ISSUER, ctx.base.types_of_interest);

		subdatalen  = *data++ << 8;
		subdatalen |= *data++;
		datalen -= 2;

		*hashedlen = 4 + 2 + subdatalen;
		*hashed = *_data;

		if (subdatalen) {
			/* Hashed subpackets */
			pr_devel("hashed data: %zu (after %zu)\n",
				 subdatalen, sizeof(*v4));
			if (subdatalen > datalen + 2 + 2) {
				pr_debug("Short V4 signature packet [hdata]\n");
				return -EBADMSG;
			}
			ret = pgp_parse_sig_subpkts(data, subdatalen,
						    &ctx.base);
			if (ret < 0)
				return ret;
			data += subdatalen;
			datalen -= subdatalen;
		}

		subdatalen  = *data++ << 8;
		subdatalen |= *data++;
		datalen -= 2;
		if (subdatalen) {
			/* Unhashed subpackets */
			pr_devel("unhashed data: %zu\n", subdatalen);
			if (subdatalen > datalen + 2) {
				pr_debug("Short V4 signature packet [udata]\n");
				return -EBADMSG;
			}
			ret = pgp_parse_sig_subpkts(data, subdatalen,
						    &ctx.base);
			if (ret < 0)
				return ret;
			data += subdatalen;
			datalen -= subdatalen;
		}

		if (!ctx.got_the_issuer) {
			pr_debug("V4 signature packet lacks issuer\n");
			return -EBADMSG;
		}
	} else {
		pr_debug("Signature packet with unhandled version %d\n",
			 p->version);
		return -EBADMSG;
	}

	*_data = data;
	*_datalen = datalen;
	return 0;
}

int pgp_get_signature_data(const u8 *signature, size_t signature_len,
			   u8 **data, size_t *data_len, u8 **sig,
			   size_t *sig_len, u8 **issuer, u16 *algo)
{
	unsigned int nbytes, nbytes_alloc;
	enum pgp_packet_tag type;
	ssize_t pktlen;
	u8 headerlen;
	struct pgp_sig_parameters p;
	const u8 *hashed;
	size_t hashedlen;
	u8 trailer[6];
	int ret;

	*data = NULL;

	pktlen = pgp_parse_packet_header((const u8 **)&signature,
					 &signature_len, &type, &headerlen);
	if (pktlen < 0)
		return pktlen;

	ret = pgp_parse_sig_params(&signature, &signature_len, &p,
				   &hashed, &hashedlen);
	if (ret < 0)
		return ret;

	if (p.version == 3) {
		*data_len = hashedlen;
		*data = malloc(hashedlen);
		if (*data == NULL)
			return -ENOMEM;

		memcpy(*data, hashed, hashedlen);
	} else if (p.version == 4) {
		trailer[0] = p.version;
		trailer[1] = 0xffU;
		trailer[2] = hashedlen >> 24;
		trailer[3] = hashedlen >> 16;
		trailer[4] = hashedlen >> 8;
		trailer[5] = hashedlen;

		*data_len = hashedlen + sizeof(trailer);
		*data = malloc(hashedlen + 6);
		if (*data == NULL)
			return -ENOMEM;

		memcpy(*data, hashed, hashedlen);
		memcpy(*data + hashedlen, trailer, 6);
	}

	*algo = p.hash_algo;

	*issuer = malloc(4);
	if (!*issuer) {
		ret = -ENOMEM;
		goto out;
	}

	memcpy(*issuer, p.issuer.id + sizeof(uint32_t), sizeof(uint32_t));

	signature += 2;
	signature_len -= 2;

	nbytes = signature_len - 2;
	nbytes_alloc = __KERNEL_DIV_ROUND_UP(nbytes, 8) * 8;

	*sig = calloc(nbytes_alloc, sizeof(u8));
	if (!*sig) {
		ret = -ENOMEM;
		goto out;
	}

	memcpy(*sig + nbytes_alloc - nbytes, signature + 2, nbytes);
	*sig_len = nbytes_alloc;

	ret = 0;
out:
	if (ret < 0) {
		free(*data);
		free(*issuer);
	}

	return ret;
}
