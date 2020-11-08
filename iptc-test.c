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

struct ipt_rule {
	struct ipt_entry e;
	struct xt_standard_target t;
};

static int ipt_rule_init (struct ipt_rule *o)
{
	memset (o, 0, sizeof (*o));

	o->e.target_offset = offsetof (struct ipt_rule, t);
	o->e.next_offset = sizeof (*o);

	o->t.target.u.user.target_size = sizeof (o->t);  // XT_ALIGN?
	return 1;
}

static int ipt_rule_jump (struct ipt_rule *o, const char *target)
{
	if (strlen (target) >= sizeof (o->t.target.u.user.name)) {
		errno = EINVAL;
		return 0;
	}

	strcpy (o->t.target.u.user.name, target);
	return 1;
}

static int ipt_rule_goto (struct ipt_rule *o, const char *target)
{
	o->e.ip.flags |= IPT_F_GOTO;

	return ipt_rule_jump (o, target);
}

static int ipt_rule_in (struct ipt_rule *o, const char *iface)
{
	size_t i;
	int plus = 0;

	for (i = 0; *iface != '\0'; ++i, ++iface) {
		o->e.ip.iniface[i] = *iface;
		o->e.ip.iniface_mask[i] = 1;
		plus = *iface == '+';
	}

	if (plus)
		o->e.ip.iniface_mask[i - 1] = '\0';

	return 1;
}

static int test (struct xtc_handle *o, const char *chain)
{
	const char *policy = "policy-0";
	struct ipt_rule r;

	if (!iptc_is_chain (policy, o) && !iptc_create_chain (policy, o))
		return 0;

	if (!iptc_is_chain (chain, o) && !iptc_create_chain (chain, o))
		return 0;

	if (!iptc_flush_entries (chain, o))
		return 0;

	ipt_rule_init (&r);
	ipt_rule_in   (&r, "eth2");
	ipt_rule_goto (&r, policy);

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
