/*
 * IP Tables Test
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <libiptc/libiptc.h>

#include "xt-rule.h"

static int test (struct xtc *o, const char *chain)
{
	const char *policy = "policy-0";
	struct xt_rule *r;
	void *e;
	int ok;

	if (!xtc_is_chain (o, policy) && !xtc_create_chain (o, policy))
		return 0;

	if (!xtc_is_chain (o, chain)  && !xtc_create_chain (o, chain))
		return 0;

	if (!xtc_flush_entries (o, chain))
		return 0;

	if ((r = xt_rule_alloc (o)) == NULL)
		return 0;

	xt_rule_set_in   (r, "eth2");
	xt_rule_set_goto (r, policy);

	e = xt_rule_make_entry (r);
	xt_rule_free (r);

	if (e == NULL)
		return 0;

	ok = xtc_append_entry (o, chain, e);
	free (e);

	return ok && xtc_commit (o);
}

int main (int argc, char *argv[])
{
	struct xtc *o;
	const char *chain;
	const struct ipt_entry *e;
	const char *target;

	if ((o = xtc_alloc (XTC_INET, "filter")) == NULL) {
		fprintf (stderr, "E: %s\n", xtc_error (XTC_INET));
		return 1;
	}

	for (
		chain = xtc_first_chain (o);
		chain != NULL;
		chain = xtc_next_chain (o)
	) {
		printf ("-N %s\n", chain);

		for (
			e = xtc_first_rule (o, chain);
			e != NULL;
			e = xtc_next_rule (o, e)
		) {
			printf ("-A %s", chain);

			if (e->ip.iniface[0] != '\0')
				printf (" -i %.16s", e->ip.iniface);

			if (e->ip.outiface[0] != '\0')
				printf (" -o %.16s", e->ip.outiface);

			if ((target = xtc_get_target (o, e)) != NULL)
				printf (" -%c %s",
					e->ip.flags & IPT_F_GOTO ? 'g' : 'j',
					target);

			printf ("\n");
		}
	}

	if (!test (o, "test"))
		fprintf (stderr, "E: %s\n", xtc_error (XTC_INET));

//	dump_entries (o);
	xtc_free (o);
	return 0;
}
