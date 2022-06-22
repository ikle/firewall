/*
 * Run the program quietly
 *
 * Copyright (c) 2016-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>

#include <fcntl.h>
#include <unistd.h>

int main (int argc, char *argv[])
{
	int fd;

	if (argc < 2) {
		fprintf (stderr, "usage:\n\tsilent <program> <args...>\n");
		return 0;
	}

	if ((fd = open ("/dev/zero", O_WRONLY)) != -1) {
		if (fd != 1)
			dup2 (fd, 1);

		if (fd != 2)
			dup2 (fd, 2);

		if (fd != 1 && fd != 2)
			close (fd);
	}

	execvp (argv[1], argv + 1);
	return 1;
}
