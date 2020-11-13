/*
 * IP Tables Rule Helpers
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef NET_XT_RULE_H
#define NET_XT_RULE_H  1

#include "xtc.h"

struct xt_rule *xt_rule_alloc (struct xtc *xtc);
void xt_rule_free (struct xt_rule *o);

void *xt_rule_make_entry (struct xt_rule *o);

int xtc_append_rule (struct xtc *o, const char *chain, struct xt_rule *r);

int xt_rule_set_jump (struct xt_rule *o, const char *target);
int xt_rule_set_goto (struct xt_rule *o, const char *target);

int xt_rule_set_in  (struct xt_rule *o, const char *iface);
int xt_rule_set_out (struct xt_rule *o, const char *iface);

int xt_rule_comment (struct xt_rule *o, const char *comment);

#endif  /* NET_XT_RULE_H */
