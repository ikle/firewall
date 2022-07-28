/*
 * Netfilter Comment Match helper
 *
 * Copyright (c) 2020-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <linux/netfilter/xt_comment.h>

#include "xt-rule.h"

int xt_rule_comment (struct xt_rule *o, const char *comment)
{
	struct xt_comment_info *m;

	if (strlen (comment) >= sizeof (m->comment)) {
		errno = EINVAL;
		return 0;
	}

	if ((m = xt_rule_match (o, "comment", 0, sizeof (*m))) == NULL)
		return 0;

	strcpy (m->comment, comment);
	return 1;
}
