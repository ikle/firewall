/*
 * IP Tables Helpers
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "ipt.h"

struct ipt_rule {
	struct ipt_entry e;
	struct xt_standard_target t;
};

struct ipt_rule *ipt_rule_alloc (void)
{
	struct ipt_rule *o;
	size_t size = sizeof (o->e) + XT_ALIGN (sizeof (o->t));

	if ((o = calloc (1, size)) == NULL)
		return NULL;

	o->e.target_offset = offsetof (struct ipt_rule, t);
	o->e.next_offset   = size;

	o->t.target.u.user.target_size = XT_ALIGN (sizeof (o->t));
	return o;
}

void ipt_rule_free (struct ipt_rule *o)
{
	free (o);
}

int
iptc_append_rule (const char *chain, struct ipt_rule *r, struct xtc_handle *o)
{
	return iptc_append_entry (chain, &r->e, o);
}

int ipt_rule_set_jump (struct ipt_rule *o, const char *target)
{
	if (strlen (target) >= sizeof (o->t.target.u.user.name)) {
		errno = EINVAL;
		return 0;
	}

	strcpy (o->t.target.u.user.name, target);
	return 1;
}

int ipt_rule_set_goto (struct ipt_rule *o, const char *target)
{
	o->e.ip.flags |= IPT_F_GOTO;

	return ipt_rule_set_jump (o, target);
}

static int set_iface (const char *iface, char *name, unsigned char *mask)
{
	const size_t size = IFNAMSIZ;
	size_t i;
	int plus = 0;

	memset (name, 0, size);
	memset (mask, 0, size);

	for (i = 0; *iface != '\0'; ++i, ++iface) {
		if (i == size) {
			errno = EINVAL;
			return 0;
		}

		name[i] = *iface;
		mask[i] = 1;
		plus = *iface == '+';
	}

	if (!plus)
		mask[i] = 1;

	return 1;
}

int ipt_rule_set_in (struct ipt_rule *o, const char *iface)
{
	return set_iface (iface, o->e.ip.iniface, o->e.ip.iniface_mask);
}

int ipt_rule_set_out (struct ipt_rule *o, const char *iface)
{
	return set_iface (iface, o->e.ip.outiface, o->e.ip.outiface_mask);
}
