/*
 * Copyright (C) 2019-2020 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: unknown.c
 *      Create a digest list not included in the supplied compact list.
 */

#include <errno.h>
#include <fts.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <linux/magic.h>
#include <linux/stat.h>
#include <linux/fs.h>
#include <sys/mman.h>
#include <sys/xattr.h>
#include <sys/capability.h>

#include "compact_list.h"
#include "selinux.h"
#include "crypto.h"
#include "xattr.h"
#include "evm.h"
#include "cap.h"

#define FORMAT "compact"
#define FORMAT_TLV "compact_tlv"

static int add_file(int dirfd, int fd, char *path, u16 type, u16 modifiers,
		    struct list_head *list_head, struct stat *st,
		    enum hash_algo algo, enum hash_algo ima_algo, bool tlv,
		    bool gen_list, bool include_lsm_label,
		    bool include_ima_digests, bool root_cred,
		    bool set_ima_xattr, bool set_evm_xattr, char *alt_root,
		    char *caps, char *file_digest, char *label)
{
	cap_t c;
	struct ima_digest *found_digest;
	struct vfs_cap_data rawvfscap;
	u8 ima_xattr[2 + SHA512_DIGEST_SIZE];
	u8 ima_digest[SHA512_DIGEST_SIZE];
	u8 evm_digest[SHA512_DIGEST_SIZE];
	u8 *digest = ima_digest;
	char *obj_label = NULL;
	u8 *caps_bin = NULL;
	struct stat s;
	LIST_HEAD(items);
	int gen_ima_xattr = 1;
	struct list_struct *list = NULL, *list_file = NULL;
	int ret, ima_xattr_len, obj_label_len = 0, caps_bin_len = 0;

	if (!S_ISREG(st->st_mode))
		return -ENOENT;

	if (root_cred) {
		memcpy(&s, st, sizeof(s));
		s.st_uid = 0;
		s.st_gid = 0;
		st = &s;
	}

	if (((st->st_mode & S_IXUGO) || !(st->st_mode & S_IWUGO)) &&
	    st->st_size)
		modifiers |= (1 << COMPACT_MOD_IMMUTABLE);

	list = compact_list_init(list_head, type, modifiers, algo, tlv);
	if (!list)
		return -ENOMEM;

	if (type == COMPACT_METADATA && include_ima_digests) {
		list_file = compact_list_init(list_head, COMPACT_FILE,
					      modifiers, algo, tlv);
		if (!list_file)
			return -ENOMEM;
	}

	if (!file_digest) {
		ret = calc_file_digest(digest, -1, path, algo);
		if (ret < 0) {
			printf("Cannot calculate digest of %s\n", path);
			goto out;
		}
	} else {
		hex2bin(digest, file_digest, hash_digest_size[algo]);
	}

	if (type == COMPACT_METADATA || tlv) {
		ima_xattr_len = getxattr(path, XATTR_NAME_IMA, NULL, 0);
		if (!gen_ima_xattr &&
		    ima_xattr_len > 0 && ima_xattr_len < sizeof(ima_xattr)) {
			ima_xattr_len = getxattr(path, XATTR_NAME_IMA,
						 ima_xattr, ima_xattr_len);
			if (ima_xattr_len)
				gen_ima_xattr = 0;
		}

		if (gen_ima_xattr) {
			ret = gen_write_ima_xattr(ima_xattr, &ima_xattr_len,
				path, algo, ima_digest,
				(modifiers & (1 << COMPACT_MOD_IMMUTABLE)),
				set_ima_xattr);
			if (ret < 0)
				return ret;
		}

		if (set_evm_xattr) {
			ret = write_evm_xattr(path, algo);
			if (ret < 0)
				return ret;
		}

		if (label) {
			obj_label = strdup(label);
			if (!obj_label)
				return -ENOMEM;

			obj_label_len = strlen(obj_label) + 1;
		}

		if (!obj_label && include_lsm_label == 1) {
			obj_label_len = getxattr(path, XATTR_NAME_SELINUX,
						 NULL, 0);
			if (obj_label_len > 0) {
				obj_label = malloc(obj_label_len);
				if (!obj_label)
					return -ENOMEM;

				obj_label_len = getxattr(path,
							 XATTR_NAME_SELINUX,
							 obj_label,
							 obj_label_len);
				if (obj_label_len <= 0) {
					ret = -EACCES;
					goto out;
				}
			} else {
				obj_label_len = 0;
			}
		}

		if (!obj_label && include_lsm_label == 2) {
			ret = get_selinux_label(path, alt_root, &obj_label,
						st->st_mode);
			if (!ret && obj_label)
				obj_label_len = strlen(obj_label) + 1;
		}

		if (caps && strlen(caps)) {
			c = cap_from_text(caps);
			if (!c) {
				ret = -ENOMEM;
				goto out;
			}

			ret = _fcaps_save(&rawvfscap, c, &caps_bin_len);
			if (!ret) {
				caps_bin = malloc(caps_bin_len);
				if (!caps_bin) {
					ret = -ENOMEM;
					goto out;
				}

				memcpy(caps_bin, (u8 *)&rawvfscap,
				       caps_bin_len);
			}

			cap_free(c);
		} else {
			caps_bin_len = getxattr(path, XATTR_NAME_CAPS, NULL, 0);
			if (caps_bin_len > 0) {
				caps_bin = malloc(caps_bin_len);
				if (!caps_bin) {
					ret = -ENOMEM;
					goto out;
				}

				caps_bin_len = getxattr(path, XATTR_NAME_CAPS,
							caps_bin, caps_bin_len);
				if (caps_bin_len <= 0) {
					ret = -EACCES;
					goto out;
				}
			} else {
				caps_bin_len = 0;
			}
		}

		ret = evm_calc_hmac_or_hash(algo, evm_digest,
					    obj_label_len, obj_label,
					    ima_xattr_len, ima_xattr,
					    caps_bin_len, caps_bin,
					    st->st_uid, st->st_gid,
					    st->st_mode);
		if (ret < 0)
			goto out;

		if (type == COMPACT_METADATA)
			digest = evm_digest;
	}

	found_digest = ima_lookup_digest(digest, algo);
	if (found_digest) {
		ret = -EEXIST;
		goto out;
	}

	if (gen_list) {
		ret = write_check(fd, path, strlen(path));
		if (!ret)
			ret = write_check(fd, "\n", 1);

		return ret;
	}

	if (!tlv) {
		if (type == COMPACT_METADATA && include_ima_digests) {
			ret = compact_list_add_digest(fd, list_file,
						      ima_digest);
			if (ret < 0)
				goto out;
		}

		ret = compact_list_add_digest(fd, list, digest);
		goto out;
	}

	if (type == COMPACT_METADATA) {
		ret = compact_list_tlv_add_digest(fd, list, &items, evm_digest,
						  ID_EVM_DIGEST);
		if (ret < 0)
			goto out_free_items;
	}

	ret = compact_list_tlv_add_digest(fd, list, &items, ima_digest,
					  ID_DIGEST);
	if (ret < 0)
		goto out_free_items;

	ret = compact_list_tlv_add_metadata(fd, list, &items, path, alt_root,
					    st, obj_label, obj_label_len,
					    caps_bin, caps_bin_len);
	if (ret < 0)
		goto out_free_items;

	ret = compact_list_tlv_add_items(fd, list, &items);
out_free_items:
	compact_list_tlv_free_items(&items);
out:
	free(obj_label);
	free(caps_bin);
	return ret;
}

int generator(int dirfd, int pos, struct list_head *head_in,
	      struct list_head *head_out, enum compact_types type,
	      u16 modifiers, enum hash_algo algo, enum hash_algo ima_algo,
	      bool tlv, char *alt_root)
{
	struct path_struct *cur, *cur_i, *cur_e;
	FTS *fts = NULL;
	FTSENT *ftsent;
	char *paths[2] = { "/", NULL };
	char filename[NAME_MAX + 1];
	char path[PATH_MAX];
	char *digest_lists_dir = NULL, *path_list = NULL, *gen_list_path = NULL;
	char *data_ptr, *line_ptr, *real_path;
	void *data;
	loff_t size;
	time_t t = time(NULL);
	bool unlink = true;
	struct tm tm;
	struct stat st, *statp;
	LIST_HEAD(list_head);
	char *attrs[ATTR__LAST];
	struct passwd *pwd;
	struct group *grp;
	enum hash_algo list_algo;
	int include_ima_digests = 0, only_executables = 0, root_cred = 0;
	int include_path = 0, include_file = 0, set_ima_xattr = 0;
	int path_list_ext = 0, set_evm_xattr = 0, alt_root_len;
	int fts_flags = (FTS_PHYSICAL | FTS_COMFOLLOW | FTS_NOCHDIR | FTS_XDEV);
	int ret, i, digest_lists_dirfd, fd, prefix_len, include_lsm_label = 0;

	if (pos == -1)
		pos = 0;

	list_for_each_entry(cur, head_in, list) {
		if (cur->path[1] != ':') {
			pr_err("Options must be in the format <opt>:<path>\n");
			return -EINVAL;
		}

		if (cur->path[0] == 'i')
			include_ima_digests = 1;
		if (cur->path[0] == 'D')
			digest_lists_dir = &cur->path[2];
		if (cur->path[0] == 'L')
			path_list = &cur->path[2];
		if (cur->path[0] == 'M')
			path_list_ext = 1;
		if (cur->path[0] == 'G')
			gen_list_path = &cur->path[2];
		if (cur->path[0] == 'l') {
			if (!strcmp(&cur->path[2], "policy"))
				include_lsm_label = 2;
			else
				include_lsm_label = 1;
		}
		if (cur->path[0] == 'e')
			only_executables = 1;
		if (cur->path[0] == 'r')
			root_cred = 1;
		if (cur->path[0] == 'F')
			include_path = 1;
		if (cur->path[0] == 'x') {
			if (!strcmp(&cur->path[2], "evm"))
				set_evm_xattr = 1;
			else
				set_ima_xattr = 1;
		}
	}

	if (!digest_lists_dir) {
		pr_err("Digest lists directory not specified\n");
		return -EINVAL;
	}

	if (path_list) {
		ret = read_file_from_path(-1, path_list, &data, &size);
		if (ret < 0)
			return ret;

		data_ptr = (char *)data;

		while ((line_ptr = strsep(&data_ptr, "\n"))) {
			if (!strlen(line_ptr))
				continue;

			if (path_list_ext) {
				parse_file_attrs(line_ptr, attrs);
				line_ptr = attrs[ATTR_PATH];
			}

			if (!line_ptr || stat(line_ptr, &st) == -1 ||
			    !S_ISREG(st.st_mode))
				continue;

			snprintf(path, sizeof(path), "I:%s", line_ptr);
			ret = add_path_struct(path, attrs, head_in);
			if (ret < 0)
				return ret;
		}
	}

	digest_lists_dirfd = open(digest_lists_dir, O_RDONLY | O_DIRECTORY);
	if (digest_lists_dirfd < 0) {
		pr_err("Unable to open %s, ret: %d\n", digest_lists_dir,
		       digest_lists_dirfd);
		return digest_lists_dirfd;
	}

	if (type == COMPACT_METADATA && include_lsm_label) {
		ret = selinux_init_setup();
		if (ret)
			goto out;
	}

	for (i = 0; i < COMPACT__LAST; i++) {
		ret = process_lists(digest_lists_dirfd, -1, 0, 0, &list_head, i,
				    (type == COMPACT_METADATA) ?
				    PARSER_OP_ADD_META_DIGEST_TO_HTABLE :
				    PARSER_OP_ADD_DIGEST_TO_HTABLE,
				    digest_lists_dir, filename);
		if (ret < 0)
			goto out_selinux;
	}

	compact_list_flush_all(-1, &list_head);

	if (!gen_list_path) {
		tm = *localtime(&t);

		prefix_len = gen_filename_prefix(filename, sizeof(filename),
					pos, tlv ? FORMAT_TLV : FORMAT, type);
		snprintf(filename + prefix_len, sizeof(filename) - prefix_len,
			"%04d%02d%02d_%02d%02d%02d", tm.tm_year + 1900,
			tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min,
			tm.tm_sec);

		fd = openat(dirfd, filename, O_WRONLY | O_CREAT | O_TRUNC,
			    DIGEST_LIST_MODE);
	} else {
		fd = openat(-1, gen_list_path, O_WRONLY | O_CREAT | O_TRUNC,
			    DIGEST_LIST_MODE);
	}

	if (fd < 0) {
		pr_err("Cannot open %s\n", filename);
		ret = -EACCES;
		goto out_selinux;
	}

	list_for_each_entry(cur, head_in, list) {
		if (cur->path[0] != 'I')
			continue;

		if (path_list_ext) {
			pwd = NULL;
			grp = NULL;
			list_algo = algo;

			if (cur->attrs[ATTR_MODE])
				st.st_mode = strtol(cur->attrs[ATTR_MODE],
						    NULL, 10);
			st.st_uid = 0;
			if (cur->attrs[ATTR_UNAME])
				pwd = getpwnam(cur->attrs[ATTR_UNAME]);
			if (pwd)
				st.st_uid = pwd->pw_uid;
			st.st_gid = 0;
			if (cur->attrs[ATTR_GNAME])
				grp = getgrnam(cur->attrs[ATTR_GNAME]);
			if (grp)
				st.st_gid = grp->gr_gid;
			if (cur->attrs[ATTR_DIGESTALGO])
				list_algo = strtol(cur->attrs[ATTR_DIGESTALGO],
						   NULL, 10);
			if (cur->attrs[ATTR_DIGESTALGOPGP]) {
				list_algo = pgp_algo_mapping[strtol(
						cur->attrs[ATTR_DIGESTALGOPGP],
						NULL, 10)];
			}
			if (list_algo != algo)
				continue;
		}

		paths[0] = &cur->path[2];

		fts = fts_open(paths, fts_flags, NULL);
		if (!fts)
			goto out_close;

		while ((ftsent = fts_read(fts)) != NULL) {
			switch (ftsent->fts_info) {
			case FTS_F:
				real_path = ftsent->fts_path;
				alt_root_len = alt_root ? strlen(alt_root) : 0;

				if (alt_root &&
				    alt_root_len < strlen(real_path))
					real_path += alt_root_len;

				include_file = 0;
				statp = ftsent->fts_statp;
				if (path_list_ext) {
					st.st_size = statp->st_size;
					statp = &st;
				}

				if (include_path && only_executables) {
					list_for_each_entry(cur_i, head_in,
							    list) {
						if (cur_i->path[0] != 'F')
							continue;

						if (!strncmp(real_path,
						    &cur_i->path[2],
						    strlen(&cur_i->path[2]))) {
							include_file = 1;
							break;
						}
					}
				} else {
					if (!only_executables)
						include_file = 1;
				}

				if (only_executables &&
				    (statp->st_mode & S_IXUGO))
					include_file = 1;

				if (!include_file)
					continue;

				include_file = 1;

				list_for_each_entry(cur_e, head_in, list) {
					if (cur_e->path[0] == 'E' &&
					    !strncmp(&cur_e->path[2],
						     real_path,
						     strlen(&cur_e->path[2]))) {
						include_file = 0;
						break;
					}
				}

				if (!include_file)
					continue;

				ret = add_file(dirfd, fd, ftsent->fts_path,
					type, modifiers, &list_head, statp,
					algo, ima_algo, tlv,
					gen_list_path != NULL,
					include_lsm_label, include_ima_digests,
					root_cred, set_ima_xattr, set_evm_xattr,
					alt_root,
					cur->attrs[ATTR_CAPS],
					cur->attrs[ATTR_DIGEST],
					cur->attrs[ATTR_OBJ_LABEL]);
				if (!ret)
					unlink = false;
				else if (ret < 0 && ret != -EEXIST &&
					 ret != -ENOENT && ret != -ENODATA)
					goto out_fts_close;

				break;
			default:
				break;
			}
		}

		fts_close(fts);
		fts = NULL;
	}

	ret = compact_list_flush_all(fd, &list_head);
	if (ret < 0) {
		pr_err("Cannot write digest list to %s\n", filename);
		goto out_fts_close;
	}

	if (!unlink && !gen_list_path)
		ret = add_path_struct(filename, NULL, head_out);
out_fts_close:
	if (fts)
		fts_close(fts);
out_close:
	close(fd);

	if (ret < 0 || unlink)
		unlinkat(dirfd, filename, 0);
out_selinux:
	if (type == COMPACT_METADATA && include_lsm_label)
		selinux_end_setup();
out:
	close(digest_lists_dirfd);
	return ret;
}
