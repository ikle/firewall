/*
 * EAPoL Firewall Compiler
 *
 * Copyright (c) 2020-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>

#include "chain-hash.h"
#include "xtc-eapol.h"

static int policy_compile (const char *type, int domain)
{
	struct xtc *o;

	if ((o = xtc_alloc (domain, "filter")) == NULL)
		goto no_xtc;

	if (!xtc_eapol_compile (o, "auth-eapol") || !xtc_commit (o))
		goto no_make;

	xtc_free (o);
	return 1;
no_make:
	xtc_free (o);
no_xtc:
	fprintf (stderr, "E: %s: %s\n", type, xtc_error (domain));
	return 0;
}

int main (int argc, char *argv[])
{
	int ok;

	chain_hash_init ();

	ok = policy_compile ("IPv4", XTC_INET) &&
	     policy_compile ("IPv6", XTC_INET6);
	return ok ? 0 : 1;
}
