/*
 * Vyatta Chain Hash
 *
 * Copyright (c) 2018-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef NET_CHAIN_HASH_H
#define NET_CHAIN_HASH_H  1

void chain_hash_init (void);

int get_chain_hash (const char *scope, const char *name, const char *type,
		    char *hash);

#endif  /* NET_CHAIN_HASH_H */
