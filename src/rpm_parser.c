/*
 * Copyright (C) 2020 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: rpm_parser.c
 *      Parse RPM header and upload digest list to the kernel.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <fts.h>
#include <rpm/rpmtag.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/xattr.h>

#include "kernel_lib.h"
#include "lib.h"

#ifdef __BIG_ENDIAN__
#include <linux/byteorder/big_endian.h>
#else
#include <linux/byteorder/little_endian.h>
#endif

#define DIGEST_LIST_DATA "/sys/kernel/security/ima/digest_list_data"
#define DIGEST_LIST_DATA_DEL DIGEST_LIST_DATA "_del"
#define DIGEST_LIST_DIR "/etc/ima/digest_lists/"

enum hash_algo pgp_algo_mapping[PGP_HASH__LAST] = {
	[PGP_HASH_MD5] = HASH_ALGO_MD5,
	[PGP_HASH_SHA1] = HASH_ALGO_SHA1,
	[PGP_HASH_SHA224] = HASH_ALGO_SHA224,
	[PGP_HASH_SHA256] = HASH_ALGO_SHA256,
	[PGP_HASH_SHA384] = HASH_ALGO_SHA384,
	[PGP_HASH_SHA512] = HASH_ALGO_SHA512,
};

struct rpm_hdr {
	int32_t magic;
	int32_t reserved;
	int32_t tags;
	int32_t datasize;
} __attribute__((packed));

struct rpm_entryinfo {
	int32_t tag;
	int32_t type;
	int32_t offset;
	int32_t count;
} __attribute__((packed));

struct digest_list {
	struct compact_list_hdr hdr;
	u8 digest[SHA512_DIGEST_SIZE];
} __attribute__((packed));

static int parse_rpm(int fd_ima, int add, char *path, struct stat *st)
{
	void *bufp, *bufendp, *datap;
	struct rpm_hdr *hdr;
	int32_t tags;
	struct rpm_entryinfo *entry;
	void *digests = NULL, *algo_buf = NULL;
	void *dirnames = NULL, *basenames = NULL, *dirindexes = NULL;
	void *digests_ptr;
	char **dirnames_ptr = NULL, *basename, *dir_ptr;
	u32 digests_count = 0, dirnames_count = 0;
	u16 algo = HASH_ALGO_MD5;
	char file_path[PATH_MAX];
	u8 digest[SHA512_DIGEST_SIZE];
	struct digest_list list;
	size_t len;
	int ret = 0, fd_rpm, i, prefix_len = 0;

	const unsigned char rpm_header_magic[8] = {
		0x8e, 0xad, 0xe8, 0x01, 0x00, 0x00, 0x00, 0x00
	};

	if (st->st_size < sizeof(*hdr)) {
		printf("Missing RPM header\n");
		return -EINVAL;
	}

	fd_rpm = open(path, O_RDONLY);
	if (fd_rpm < 0)
		return -EACCES;

	bufp = mmap(NULL, st->st_size, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE, fd_rpm, 0);

	close(fd_rpm);

	if (bufp == MAP_FAILED)
		return -ENOMEM;

	if (memcmp(bufp, rpm_header_magic, sizeof(rpm_header_magic))) {
		pr_err("Invalid RPM header\n");
		return -EINVAL;
	}

	hdr = (struct rpm_hdr *)bufp;
	tags = __be32_to_cpu(hdr->tags);
	datap = bufp + sizeof(*hdr) + tags * sizeof(struct rpm_entryinfo);
	bufendp = bufp + st->st_size;
	bufp += sizeof(*hdr);

	for (i = 0; i < tags && (bufp + sizeof(*entry)) <= bufendp;
	     i++, bufp += sizeof(*entry)) {
		entry = bufp;

		switch (be32_to_cpu(entry->tag)) {
		case RPMTAG_FILEDIGESTS:
			digests = datap + be32_to_cpu(entry->offset);
			digests_count = be32_to_cpu(entry->count);
			break;
		case RPMTAG_FILEDIGESTALGO:
			algo_buf = datap + be32_to_cpu(entry->offset);
			break;
		case RPMTAG_DIRNAMES:
			dirnames = datap + be32_to_cpu(entry->offset);
			dirnames_count = be32_to_cpu(entry->count);
			break;
		case RPMTAG_BASENAMES:
			basenames = datap + be32_to_cpu(entry->offset);
			break;
		case RPMTAG_DIRINDEXES:
			dirindexes = datap + be32_to_cpu(entry->offset);
			break;

		if (digests && algo_buf && dirnames && basenames && dirindexes)
			break;
		}
	}

	if (!digests || !dirnames || !basenames || !dirindexes)
		return 0;

	dirnames_ptr = malloc(sizeof(*dirnames_ptr) * dirnames_count);
	if (!dirnames_ptr)
		return -ENOMEM;

	for (i = 0; i < dirnames_count && dirnames < bufendp; i++) {
		dirnames_ptr[i] = dirnames;
		dirnames += strlen(dirnames) + 1;
	}

	if (i < dirnames_count) {
		ret = -EINVAL;
		goto out;
	}

	if (algo_buf && algo_buf + sizeof(u32) <= bufendp)
		algo = pgp_algo_mapping[be32_to_cpu(*(u32 *)algo_buf)];

	for (i = 0; i < digests_count && digests < bufendp; i++) {
		int digest_str_len = strlen(digests);
		int basename_str_len = strlen(basenames);
		u32 dirindex = 0;

		if ((basenames &&
		    basenames + basename_str_len + 1 > bufendp) ||
		    (dirindexes &&
		    dirindexes + (i + 1) * sizeof(dirindex) > bufendp) ||
		    (digests + digest_str_len * 2 + 1 > bufendp)) {
			pr_err("RPM header read at invalid offset\n");
			ret = -EINVAL;
			goto out;
		}

		if (!digest_str_len) {
			digests += digest_str_len + 1;
			basenames += basename_str_len + 1;
			continue;
		}

		digests_ptr = digests;
		digests += digest_str_len + 1;
		dirindex = be32_to_cpu(*(u32 *)
				       (dirindexes + i * sizeof(dirindex)));

		basename = basenames;
		basenames += basename_str_len + 1;

		if (strncmp(dirnames_ptr[dirindex], DIGEST_LIST_DIR,
			    sizeof(DIGEST_LIST_DIR) - 1))
			continue;

		dir_ptr = strstr(path, DIGEST_LIST_DIR);

		if (dir_ptr)
			prefix_len = dir_ptr - path;

		snprintf(file_path, sizeof(file_path), "%.*s%s%s", prefix_len,
			 path, dirnames_ptr[dirindex], basename);

		ret = hex2bin(digest, digests_ptr, digest_str_len / 2);
		if (ret < 0)
			goto out;

		list.hdr.version = 1;
		list.hdr.type = COMPACT_FILE;
		list.hdr.modifiers = (1 << COMPACT_MOD_IMMUTABLE);
		list.hdr.algo = algo;
		list.hdr.count = 1;
		list.hdr.datalen = digest_str_len / 2;

		if (ima_canonical_fmt) {
			list.hdr.type = cpu_to_le16(list.hdr.type);
			list.hdr.modifiers = cpu_to_le16(list.hdr.modifiers);
			list.hdr.algo = cpu_to_le16(list.hdr.algo);
			list.hdr.count = cpu_to_le32(list.hdr.count);
			list.hdr.datalen = cpu_to_le32(list.hdr.datalen);
		}

		memcpy(list.digest, digest, digest_str_len / 2);

		if (!add) {
			len = write(fd_ima, file_path, strlen(file_path));
			if (len != strlen(file_path)) {
				ret = -EIO;
				goto out;
			}
		}

		len = write(fd_ima, (u8 *)&list,
			    sizeof(list.hdr) + digest_str_len / 2);
		if (len != sizeof(list.hdr) + digest_str_len / 2) {
			ret = -EIO;
			goto out;
		}

		if (add) {
			lremovexattr(file_path, XATTR_NAME_IMA);

			len = write(fd_ima, file_path, strlen(file_path));
			if (len != strlen(file_path))
				ret = -EIO;
		}
	}
out:
	free(dirnames_ptr);

	return ret;
}

int parse_digest_list(char *name)
{
	char *type_start, *format_start, *format_end;

	type_start = strchr(name, '-');
	if (!type_start)
		return 0;

	format_start = strchr(type_start + 1, '-');
	if (!format_start)
		return 0;

	format_end = strchr(format_start + 1, '-');
	if (!format_end)
		return 0;

	if (format_end - format_start - 1 != 3 ||
	    strncmp(format_start + 1, "rpm", 3))
		return 0;

	return 1;
}

int main(int argc, char *argv[])
{
	FTS *fts = NULL;
	FTSENT *ftsent;
	char *ima_path = DIGEST_LIST_DATA;
	int fts_flags = (FTS_PHYSICAL | FTS_COMFOLLOW | FTS_NOCHDIR | FTS_XDEV);
	char *paths[2] = { NULL, NULL };
	int ret, fd_ima, add = 1;

	if (argc != 3) {
		printf("Usage: %s add|del <digest list path>\n", argv[0]);
		return -EINVAL;
	}

	if (!strcmp(argv[1], "del")) {
		ima_path = DIGEST_LIST_DATA_DEL;
		add = 0;
	}

	fd_ima = open(ima_path, O_WRONLY | O_CREAT, 0600);
	if (fd_ima < 0)
		return -EACCES;

	paths[0] = argv[2];

	fts = fts_open(paths, fts_flags, NULL);
	if (!fts)
		return -EACCES;

	while ((ftsent = fts_read(fts)) != NULL) {
		switch (ftsent->fts_info) {
		case FTS_F:
			if (!parse_digest_list(ftsent->fts_name))
				break;

			ret = parse_rpm(fd_ima, add, ftsent->fts_path,
					ftsent->fts_statp);
			if (ret < 0)
				printf("Cannot parse %s\n", ftsent->fts_path);
			break;
		default:
			break;
		}
	}

	fts_close(fts);
	close(fd_ima);
	return 0;
}
