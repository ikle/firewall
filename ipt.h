/*
 * IP Tables Helpers
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef NET_IPT_H
#define NET_IPT_H  1

struct xtc_handle;

struct xt_rule *xt_rule_alloc (int domain);
void xt_rule_free (struct xt_rule *o);

int xtc_append_rule (const char *chain, struct xt_rule *r,
		     struct xtc_handle *o);

int xt_rule_set_jump (struct xt_rule *o, const char *target);
int xt_rule_set_goto (struct xt_rule *o, const char *target);

int xt_rule_set_in  (struct xt_rule *o, const char *iface);
int xt_rule_set_out (struct xt_rule *o, const char *iface);

int xt_rule_comment (struct xt_rule *o, const char *comment);

#endif  /* NET_IPT_H */
