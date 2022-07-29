/*
 * Netfilter IpSet Match helper
 *
 * Copyright (c) 2020-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <linux/netfilter/xt_set.h>

#include "ipset-raw.h"
#include "xt-rule.h"

int xt_rule_match_set (struct xt_rule *o, const char *name, int dim, int flags)
{
	int index;
	struct xt_set_info *m;

	if ((index = ipset_get_index (name)) < 0)
		return 0;

	if ((m = xt_rule_match (o, "set", 1, sizeof (*m))) == NULL)
		return 0;

	m->index = index;
	m->dim   = dim;
	m->flags = flags;
	return 1;
}
