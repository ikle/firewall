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

#include <libiptc/libiptc.h>

static int test (struct xtc_handle *o, const char *chain)
{
	const char *policy = "policy-0";
	struct rule {
		struct ipt_entry e;
		struct xt_standard_target t;
	} r;

	if (!iptc_is_chain (policy, o) && !iptc_create_chain (policy, o))
		return 0;

	if (!iptc_is_chain (chain, o) && !iptc_create_chain (chain, o))
		return 0;

	if (!iptc_flush_entries (chain, o))
		return 0;

	memset (&r, 0, sizeof (r));

	strncpy (r.e.ip.iniface, "eth2", sizeof (r.e.ip.iniface));
	memset (r.e.ip.iniface_mask, '.', sizeof (r.e.ip.iniface_mask));

	r.e.ip.flags = IPT_F_GOTO;

	r.e.target_offset = offsetof (struct rule, t);
	r.e.next_offset = sizeof (r);

//	r.t.target.u.user.target_size = XT_ALIGN (sizeof (r.t));
	r.t.target.u.user.target_size = sizeof (r.t);
	strcpy (r.t.target.u.user.name, policy);

	if (!iptc_append_entry (chain, &r.e, o))
		return 0;

	return iptc_commit (o);
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
