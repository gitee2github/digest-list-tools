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
 * File: upload_digest_lists.c
 *      Run parsers of digest list formats not recognizable by the kernel.
 */

#include <stdio.h>
#include <errno.h>
#include <fts.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <linux/limits.h>
#include <sys/mount.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <linux/magic.h>

#include "list.h"

#define MOUNT_FLAGS MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME

#define SYSFS_PATH "/sys"
#define SECURITYFS_PATH SYSFS_PATH "/kernel/security"
#define DIGEST_LIST_DATA SECURITYFS_PATH "/ima/digest_list_data"

struct format_entry {
	struct list_head list;
	char *format;
};

LIST_HEAD(formats);

int add_format_parser(char *path)
{
	char *format = NULL, *name;
	char *type_start, *format_start, *format_end;
	struct format_entry *cur, *new;
	int ret = 0;

	name = strrchr(path, '/');
	if (!name)
		return -EINVAL;

	name++;

	type_start = strchr(name, '-');
	if (!type_start)
		return 0;

	format_start = strchr(type_start + 1, '-');
	if (!format_start)
		return 0;

	format_end = strchr(format_start + 1, '-');
	if (!format_end)
		return 0;

	format = strndup(format_start + 1, format_end - format_start - 1);
	if (!format)
		return -ENOMEM;

	list_for_each_entry(cur, &formats, list)
		if (!strcmp(format, cur->format))
			goto out;

	if (!strcmp(format, "compact"))
		goto out;

	new = malloc(sizeof(*new));
	if (!new) {
		ret = -ENOMEM;
		goto out;
	}

	new->format = format;
	list_add(&new->list, &formats);
out:
	if (ret < 0)
		free(format);

	return ret;
}

static int init_digest_list_upload(int *mount_sysfs, int *mount_securityfs)
{
	struct stat st;
	int ret;

	if (!stat(SECURITYFS_PATH, &st))
		goto mount_securityfs;

	ret = mount(SYSFS_PATH, SYSFS_PATH, "sysfs", MOUNT_FLAGS, NULL);
	if (ret < 0) {
		printf("Cannot mount %s (%s)\n", SYSFS_PATH,
		       strerror(errno));
		return ret;
	}

	*mount_sysfs = 1;
mount_securityfs:
	if (!stat(DIGEST_LIST_DATA, &st))
		return 0;

	ret = mount(SECURITYFS_PATH, SECURITYFS_PATH, "securityfs", MOUNT_FLAGS,
		    NULL);
	if (ret < 0) {
		printf("Cannot mount %s (%s)\n", SECURITYFS_PATH,
		       strerror(errno));
		return ret;
	}

	*mount_securityfs = 1;
	return 0;
}

static void end_digest_list_upload(int umount_sysfs, int umount_securityfs)
{
	if (umount_securityfs)
		umount(SECURITYFS_PATH);
	if (umount_sysfs)
		umount(SYSFS_PATH);
}

int main(int argc, char *argv[])
{
	int mount_sysfs = 0, mount_securityfs = 0;
	char *paths[2] = { NULL, NULL };
	struct format_entry *cur, *tmp;
	char parser_path[PATH_MAX];
	FTS *fts = NULL;
	FTSENT *ftsent;
	int fts_flags = (FTS_PHYSICAL | FTS_COMFOLLOW | FTS_NOCHDIR | FTS_XDEV);
	int ret;

	if (argc != 3) {
		printf("Usage: %s add|del <digest list path>\n", argv[0]);
		return -EINVAL;
	}

	paths[0] = argv[2];

	fts = fts_open(paths, fts_flags, NULL);
	if (!fts)
		return -EACCES;

	while ((ftsent = fts_read(fts)) != NULL) {
		switch (ftsent->fts_info) {
		case FTS_F:
			ret = add_format_parser(ftsent->fts_path);
			if (ret < 0)
				printf("Cannot upload %s\n", ftsent->fts_path);

			break;
		default:
			break;
		}
	}

	fts_close(fts);
	fts = NULL;

	ret = init_digest_list_upload(&mount_sysfs, &mount_securityfs);
	if (ret < 0)
		return -EACCES;

	list_for_each_entry_safe(cur, tmp, &formats, list) {
		if (fork() == 0) {
			snprintf(parser_path, sizeof(parser_path),
				 "/usr/libexec/%s_parser", cur->format);
			return execlp(parser_path, parser_path, argv[1],
				      argv[2], NULL);
		}

		wait(NULL);

		list_del(&cur->list);
		free(cur->format);
		free(cur);
	}

	end_digest_list_upload(mount_sysfs, mount_securityfs);
	return 0;
}
