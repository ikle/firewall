/*
 * IP Tables Test
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "ipt.h"

static int test (struct xtc_handle *o, const char *chain)
{
	const char *policy = "policy-0";
	struct ipt_rule *r;
	int ok;

	if (!iptc_is_chain (policy, o) && !iptc_create_chain (policy, o))
		return 0;

	if (!iptc_is_chain (chain, o) && !iptc_create_chain (chain, o))
		return 0;

	if (!iptc_flush_entries (chain, o))
		return 0;

	if ((r = ipt_rule_alloc ()) == NULL)
		return 0;

	ipt_rule_set_in   (r, "eth2");
	ipt_rule_set_goto (r, policy);

	ok = iptc_append_rule (chain, r, o);
	ipt_rule_free (r);

	return ok && iptc_commit (o);
}

int main (int argc, char *argv[])
{
	struct xtc_handle *o;
	const char *chain;
	const struct ipt_entry *e;
	const char *target;

	if ((o = iptc_init ("filter")) == NULL) {
		fprintf (stderr, "E: %s\n", iptc_strerror (errno));
		return 1;
	}

	for (
		chain = iptc_first_chain (o);
		chain != NULL;
		chain = iptc_next_chain (o)
	) {
		printf ("-N %s\n", chain);

		for (
			e = iptc_first_rule (chain, o);
			e != NULL;
			e = iptc_next_rule (e, o)
		) {
			printf ("-A %s", chain);

			if (e->ip.iniface[0] != '\0')
				printf (" -i %.16s", e->ip.iniface);

			if (e->ip.outiface[0] != '\0')
				printf (" -o %.16s", e->ip.outiface);

			if ((target = iptc_get_target (e, o)) != NULL)
				printf (" -%c %s",
					e->ip.flags & IPT_F_GOTO ? 'g' : 'j',
					target);

			printf ("\n");
		}
	}

	if (!test (o, "test"))
		fprintf (stderr, "E: %s\n", iptc_strerror (errno));

//	dump_entries (o);
	iptc_free (o);
	return 0;
}
