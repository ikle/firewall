/*
 * Vyatta Chain Hash Test
 *
 * Copyright (c) 2018-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <err.h>
#include <stdio.h>

#include "chain-hash.h"

int main (int argc, char *argv[])
{
	const char *scope = NULL, *name = NULL, *type = NULL;
	char hash[27];

	if (argc > 1 && argv[1][0] != '\0')
		scope = argv[1];

	if (argc > 2 && argv[2][0] != '\0')
		name = argv[2];

	if (argc > 3 && argv[3][0] != '\0')
		type = argv[3];

	chain_hash_init ();

	if (!get_chain_hash (scope, name, type, hash))
		errx (1, "could not format hash");

	printf ("hash = %.27s\n", hash);
	return 0;
}
