/*
 * IP Tables Helpers
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef NET_IPT_H
#define NET_IPT_H  1

#include <libiptc/libiptc.h>

struct ipt_rule *ipt_rule_alloc (void);
void ipt_rule_free (struct ipt_rule *o);

int iptc_append_rule (const char *chain, struct ipt_rule *r,
		      struct xtc_handle *o);

int ipt_rule_set_jump (struct ipt_rule *o, const char *target);
int ipt_rule_set_goto (struct ipt_rule *o, const char *target);

int ipt_rule_set_in  (struct ipt_rule *o, const char *iface);
int ipt_rule_set_out (struct ipt_rule *o, const char *iface);

#endif  /* NET_IPT_H */
