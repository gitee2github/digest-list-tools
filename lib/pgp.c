/*
 * Copyright (C) 1998, 1999 Free Software Foundation, Inc.
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
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "pgp.h"

#define BIT_WORD(nr)               ((nr) / __BITS_PER_LONG)
#define BIT_MASK(nr)            (1UL << ((nr) % __BITS_PER_LONG))
#define MAX_MPI 5
#define MAX_EXTERN_MPI_BITS 16384
#define __KERNEL_DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

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

struct pgp_parse_pubkey {
	enum pgp_key_version version : 8;
	enum pgp_pubkey_algo pubkey_algo : 8;
	unsigned int creation_time;
	unsigned int expires_at;
};

/**
 * pgp_parse_public_key - Parse the common part of a PGP pubkey packet
 * @_data: Content of packet (updated)
 * @_datalen: Length of packet remaining (updated)
 * @pk: Public key data
 *
 * Parse the common data struct for a PGP pubkey packet [RFC 4880: 5.5.2].
 */
int pgp_parse_public_key(const u8 **_data, size_t *_datalen,
			 struct pgp_parse_pubkey *pk)
{
	const u8 *data = *_data;
	size_t datalen = *_datalen;
	unsigned int tmp;

	if (datalen < 12) {
		pr_debug("Public key packet too short\n");
		return -EBADMSG;
	}

	pk->version = *data++;
	switch (pk->version) {
	case PGP_KEY_VERSION_2:
	case PGP_KEY_VERSION_3:
	case PGP_KEY_VERSION_4:
		break;
	default:
		pr_debug("Public key packet with unhandled version %d\n",
			   pk->version);
		return -EBADMSG;
	}

	tmp  = *data++ << 24;
	tmp |= *data++ << 16;
	tmp |= *data++ << 8;
	tmp |= *data++;
	pk->creation_time = tmp;
	if (pk->version == PGP_KEY_VERSION_4) {
		pk->expires_at = 0; /* Have to get it from the selfsignature */
	} else {
		unsigned short ndays;

		ndays  = *data++ << 8;
		ndays |= *data++;
		if (ndays)
			pk->expires_at = pk->creation_time + ndays * 86400UL;
		else
			pk->expires_at = 0;
		datalen -= 2;
	}

	pk->pubkey_algo = *data++;
	datalen -= 6;

	*_data = data;
	*_datalen = datalen;
	return 0;
}

const char *pgp_to_public_key_algo[PGP_PUBKEY__LAST] = {
	[PGP_PUBKEY_RSA_ENC_OR_SIG]     = "rsa",
	[PGP_PUBKEY_RSA_ENC_ONLY]       = "rsa",
	[PGP_PUBKEY_RSA_SIG_ONLY]       = "rsa",
	[PGP_PUBKEY_ELGAMAL]            = NULL,
	[PGP_PUBKEY_DSA]                = NULL,
};

/*
 * PGP library packet parser
 */
struct pgp_parse_context {
	u64 types_of_interest;
	int (*process_packet)(struct pgp_parse_context *context,
			      enum pgp_packet_tag type,
			      u8 headerlen,
			      const u8 *data,
			      size_t datalen);
};

/**
 * pgp_parse_packets - Parse a set of PGP packets
 * @_data: Data to be parsed (updated)
 * @_datalen: Amount of data (updated)
 * @ctx: Parsing context
 *
 * Parse a set of PGP packets [RFC 4880: 4].
 */
int pgp_parse_packets(const u8 *data, size_t datalen,
		      struct pgp_parse_context *ctx)
{
	enum pgp_packet_tag type;
	ssize_t pktlen;
	u8 headerlen;
	int ret;

	while (datalen > 2) {
		pktlen = pgp_parse_packet_header(&data, &datalen, &type,
						 &headerlen);
		if (pktlen < 0)
			return pktlen;

		if ((ctx->types_of_interest >> type) & 1) {
			ret = ctx->process_packet(ctx, type, headerlen,
						  data, pktlen);
			if (ret < 0)
				return ret;
		}
		data += pktlen;
		datalen -= pktlen;
	}

	if (datalen != 0) {
		pr_debug("Excess octets in packet stream\n");
		return -EBADMSG;
	}

	return 0;
}

static inline void digest_putc(EVP_MD_CTX *mdctx, uint8_t ch)
{
	EVP_DigestUpdate(mdctx, &ch, 1);
}

struct pgp_key_data_parse_context {
	struct pgp_parse_context pgp;
	unsigned char *raw_fingerprint;
	char *fingerprint;
	const char *user_id;
	size_t user_id_len;
	size_t fingerprint_len;
	u8 *key;
	size_t key_len;
};

int mpi_key_length(const void *xbuffer, unsigned int ret_nread,
		   unsigned int *nbits_arg, unsigned int *nbytes_arg)
{
	const uint8_t *buffer = xbuffer;
	unsigned int nbits;

	if (ret_nread < 2)
		return -EINVAL;
	nbits = buffer[0] << 8 | buffer[1];

	if (nbits > MAX_EXTERN_MPI_BITS) {
		pr_info("MPI: mpi too large (%u bits)\n", nbits);
		return -EINVAL;
	}

	if (nbits_arg)
		*nbits_arg = nbits;
	if (nbytes_arg)
		*nbytes_arg = __KERNEL_DIV_ROUND_UP(nbits, 8);

	return 0;
}

/*
 * Calculate the public key ID (RFC4880 12.2)
 */
static int pgp_calc_pkey_keyid(EVP_MD_CTX *digest,
			       struct pgp_parse_pubkey *pgp,
			       u8 *key_ptr, size_t keylen)
{
	unsigned int nb[MAX_MPI];
	unsigned int nn[MAX_MPI];
	unsigned int n;
	u8 *pp[MAX_MPI];
	u32 a32;
	int npkey;
	int i, ret;

	n = (pgp->version < PGP_KEY_VERSION_4) ? 8 : 6;
	for (i = 0; i < MAX_MPI && keylen > 0; i++) {
		ret = mpi_key_length(key_ptr, keylen, nb + i, nn + i);
		if (ret < 0)
			return ret;

		pp[i] = key_ptr + 2;
		key_ptr += 2 + nn[i];
		keylen -= 2 + nn[i];
		n += 2 + nn[i];
	}

	if (keylen != 0) {
		pr_debug("excess %zu\n", keylen);
		return -EBADMSG;
	}

	npkey = i;

	digest_putc(digest, 0x99);     /* ctb */
	digest_putc(digest, n >> 8);   /* 16-bit header length */
	digest_putc(digest, n);
	digest_putc(digest, pgp->version);

	a32 = pgp->creation_time;
	digest_putc(digest, a32 >> 24);
	digest_putc(digest, a32 >> 16);
	digest_putc(digest, a32 >>  8);
	digest_putc(digest, a32 >>  0);

	if (pgp->version < PGP_KEY_VERSION_4) {
		u16 a16;

		if (pgp->expires_at)
			a16 = (pgp->expires_at - pgp->creation_time) / 86400UL;
		else
			a16 = 0;
		digest_putc(digest, a16 >> 8);
		digest_putc(digest, a16 >> 0);
	}

	digest_putc(digest, pgp->pubkey_algo);

	for (i = 0; i < npkey; i++) {
		digest_putc(digest, nb[i] >> 8);
		digest_putc(digest, nb[i]);
		EVP_DigestUpdate(digest, pp[i], nn[i]);
	}
	ret = 0;

	return ret;
}

/*
 * Calculate the public key ID fingerprint
 */
static int pgp_generate_fingerprint(struct pgp_key_data_parse_context *ctx,
				    struct pgp_parse_pubkey *pgp,
				    u8 *key_ptr, size_t key_len)
{
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	char *fingerprint;
	u8 *raw_fingerprint;
	int digest_size, offset;
	int ret, i;

	ret = -ENOMEM;
	OpenSSL_add_all_algorithms();

	md = EVP_get_digestbyname(pgp->version < PGP_KEY_VERSION_4 ?
				  "md5" : "sha1");
	if (!md) {
		ret = -ENOENT;
		goto cleanup;
	}

	mdctx = EVP_MD_CTX_create();
	if (!mdctx) {
		ret = -ENOENT;
		goto cleanup;
	}

	if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
		ret = -EINVAL;
		goto cleanup_tfm;
	}

	ret = pgp_calc_pkey_keyid(mdctx, pgp, key_ptr, key_len);
	if (ret < 0)
		goto cleanup_tfm;

	digest_size = EVP_MD_size(md);
	raw_fingerprint = malloc(digest_size);
	if (!raw_fingerprint)
		goto cleanup_tfm;

	if (EVP_DigestFinal_ex(mdctx, raw_fingerprint, NULL) != 1) {
		ret = -EINVAL;
		goto cleanup_raw_fingerprint;
	}

	ctx->fingerprint_len = digest_size * 2;
	fingerprint = malloc(digest_size * 2 + 1);
	if (!fingerprint)
		goto cleanup_raw_fingerprint;

	offset = digest_size - 8;
	pr_debug("offset %u/%u\n", offset, digest_size);

	for (i = 0; i < digest_size; i++)
		sprintf(fingerprint + i * 2, "%02x", raw_fingerprint[i]);
	pr_debug("fingerprint %s\n", fingerprint);

	ctx->raw_fingerprint = raw_fingerprint;
	ctx->fingerprint = fingerprint;
	ret = 0;
cleanup_raw_fingerprint:
	if (ret < 0)
		free(raw_fingerprint);
cleanup_tfm:
	EVP_MD_CTX_destroy(mdctx);
cleanup:
	EVP_cleanup();
	return ret;
}

/*
 * Extract a public key or public subkey from the PGP stream.
 */
static int pgp_process_public_key(struct pgp_parse_context *context,
				  enum pgp_packet_tag type,
				  u8 headerlen,
				  const u8 *data,
				  size_t datalen)
{
	struct pgp_key_data_parse_context *ctx =
		container_of(context, struct pgp_key_data_parse_context, pgp);
	struct pgp_parse_pubkey pgp;
	int ret;

	if (type == PGP_PKT_USER_ID) {
		ctx->user_id = (const char *)data;
		ctx->user_id_len = datalen;
		return 0;
	}

	if (ctx->fingerprint) {
		return -EBADMSG;
	}

	ret = pgp_parse_public_key(&data, &datalen, &pgp);
	if (ret < 0)
		goto cleanup;

	if (pgp.pubkey_algo >= PGP_PUBKEY__LAST)
		goto cleanup_unsupported_pkey_algo;

	ctx->key = malloc(datalen);
	if (!ctx->key)
		goto cleanup_nomem;

	memcpy(ctx->key, data, datalen);
	ctx->key_len = datalen;

	ret = pgp_generate_fingerprint(ctx, &pgp, ctx->key, ctx->key_len);
	if (ret < 0)
		goto cleanup;

	return 0;

cleanup_unsupported_pkey_algo:
	pr_debug("Unsupported public key algorithm %u\n",
		 pgp.pubkey_algo);
	ret = -ENOPKG;
	goto cleanup;
cleanup_nomem:
	ret = -ENOMEM;
	goto cleanup;
cleanup:
	pr_devel("cleanup");
	free(ctx->key);
	return ret;
}

static RSA *raw_to_openssl_public_rsa(u8 *key_ptr, size_t key_len)
{
	RSA *rsa = RSA_new();
	unsigned int mpi_bytes;
	BIGNUM *n, *e;
	int ret;

	if (!rsa)
		return NULL;

	e = BN_new();
	if (!e)
		goto err_free_rsa;
	n = BN_new();
	if (!n)
		goto err_free_e;

	ret = mpi_key_length(key_ptr, 2, NULL, &mpi_bytes);
	if (ret < 0)
		goto err_free;

	key_ptr += 2;

	if (!BN_bin2bn(key_ptr, mpi_bytes, n))
                goto err_free;

	key_ptr += mpi_bytes;

	ret = mpi_key_length(key_ptr, 2, NULL, &mpi_bytes);
	if (ret < 0)
		goto err_free;

	key_ptr += 2;
	if (!BN_bin2bn(key_ptr, mpi_bytes, e))
                goto err_free;

#if OPENSSL_VERSION_NUMBER < 0x10100000
	rsa->n = n;
	rsa->e = e;
#else
	RSA_set0_key(rsa, n, e, NULL);
#endif

	return rsa;

err_free:
	BN_free(n);
err_free_e:
	BN_free(e);
err_free_rsa:
	RSA_free(rsa);

        return NULL;
}

RSA *pgp_key_parse(const u8 *data, size_t datalen, u8 *keyid)
{
	struct pgp_key_data_parse_context ctx;
	RSA *rsa;
	int ret;

	memset(&ctx, 0, sizeof(ctx));
	ctx.pgp.types_of_interest = (1 << PGP_PKT_PUBLIC_KEY) |
				    (1 << PGP_PKT_USER_ID);
	ctx.pgp.process_packet = pgp_process_public_key;

	ret = pgp_parse_packets(data, datalen, &ctx.pgp);
	if (ret < 0)
		return NULL;

	memcpy(keyid, ctx.raw_fingerprint + (ctx.fingerprint_len / 2) - 4, 4);

	rsa = raw_to_openssl_public_rsa(ctx.key, ctx.key_len);
	free(ctx.raw_fingerprint);
	free(ctx.fingerprint);
	free(ctx.key);

	return rsa;
}
