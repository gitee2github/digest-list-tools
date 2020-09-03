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
 * File: write_rpm_pgp_sig.c
 *      Add security.ima to a file with the RPM header.
 */

#include <sys/mman.h>
#include <unistd.h>

#include "pgp.h"
#include "xattr.h"

int main(int argc, char *argv[])
{
	void *pgp_sig;
	loff_t pgp_sig_len;
	u8 *sig = NULL, *data = NULL, *issuer = NULL;
	size_t sig_len, data_len;
	u16 algo;
	int ret, fd;

	if (argc < 3) {
		printf("Missing argument\n");
		return -EINVAL;
	}

	ret = read_file_from_path(-1, argv[2], &pgp_sig, &pgp_sig_len);
	if (ret < 0)
		return ret;

	ret = pgp_get_signature_data(pgp_sig, pgp_sig_len, &data, &data_len,
				     &sig, &sig_len, &issuer, &algo);
	if (ret < 0)
		goto out;

	if (argc == 4) {
		free(sig);

		ret = read_file_from_path(-1, argv[3], (void **)&sig,
					  (loff_t *)&sig_len);
		if (ret < 0)
			goto out;
	}

	write_ima_xattr(-1, argv[1], issuer, sizeof(uint32_t), sig, sig_len,
			pgp_algo_mapping[algo]);

	fd = openat(-1, argv[1], O_WRONLY | O_APPEND, DIGEST_LIST_MODE);
	if (fd < 0) {
		ret = -EACCES;
		goto out;
	}

	ret = write_check(fd, data, data_len);
	close(fd);
out:
	munmap(pgp_sig, pgp_sig_len);
	free(data);
	if (argc == 4)
		munmap(sig, sig_len);
	else
		free(sig);
	return ret;
}
