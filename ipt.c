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

#include <libiptc/libiptc.h>
#include <libiptc/libip6tc.h>

struct match {
	struct match *prev;
	struct xt_entry_match m;
};

static struct match *match_alloc (const char *name, size_t size)
{
	struct match *o;
	size_t total = XT_ALIGN (sizeof (o->m) + size);

	if (strlen (name) >= sizeof (o->m.u.user.name)) {
		errno = EINVAL;
		return NULL;
	}

	if ((o = calloc (1, offsetof (struct match, m) + total)) == NULL)
		return NULL;

	o->m.u.user.match_size = total;
	strcpy (o->m.u.user.name, name);
	return o;
}

static void match_free (struct match *o)
{
	free (o);
}

struct xt_rule {
	int domain;
	struct xt_standard_target t;
	struct match *m;

	union {
		struct ipt_entry  ipv4;
		struct ip6t_entry ipv6;
	};
};

struct xt_rule *xt_rule_alloc (int domain)
{
	struct xt_rule *o;

	if ((o = calloc (1, sizeof (*o))) == NULL)
		return NULL;

	o->domain = domain;

	o->t.target.u.user.target_size = XT_ALIGN (sizeof (o->t));

	switch (domain) {
	case PF_INET:
		o->ipv4.target_offset = sizeof (o->ipv4);
		o->ipv4.next_offset = o->ipv4.target_offset +
				      o->t.target.u.user.target_size;
		break;
	case PF_INET6:
		o->ipv6.target_offset = sizeof (o->ipv6);
		o->ipv6.next_offset = o->ipv6.target_offset +
				      o->t.target.u.user.target_size;
		break;
	default:
		goto no_domain;
	}

	return o;
no_domain:
	free (o);
	return NULL;
}

void xt_rule_free (struct xt_rule *o)
{
	struct match *p, *prev;

	if (o == NULL)
		return;

	for (p = o->m; p != NULL; p = prev) {
		prev = p->prev;
		match_free (p);
	}

	free (o);
}

static int xt_rule_match (struct xt_rule *o, struct match *m)
{
	switch (o->domain) {
	case PF_INET:
		o->ipv4.target_offset += m->m.u.user.match_size;
		o->ipv4.next_offset   += m->m.u.user.match_size;
		break;
	case PF_INET6:
		o->ipv6.target_offset += m->m.u.user.match_size;
		o->ipv6.next_offset   += m->m.u.user.match_size;
		break;
	}

	m->prev = o->m;
	o->m = m;
	return 1;
}

static size_t match_push (char *to, struct match *m)
{
	size_t offset;

	if (m == NULL)
		return 0;

	offset = match_push (to, m->prev);
	memcpy (to + offset, &m->m, m->m.u.user.match_size);
	return offset + m->m.u.user.match_size;
}

static int
ipv4_append_rule (const char *chain, struct xt_rule *r, struct xtc_handle *o)
{
	char *e;
	size_t offset;
	int ok;

	if ((e = calloc (1, r->ipv4.next_offset)) == NULL)
		return 0;

	memcpy (e, &r->ipv4, sizeof (r->ipv4));
	offset = sizeof (r->ipv4);

	offset += match_push (e + offset, r->m);

	memcpy (e + offset, &r->t, r->t.target.u.user.target_size);

	ok = iptc_append_entry (chain, (void *) e, o);
	free (e);
	return ok;
}

static int
ipv6_append_rule (const char *chain, struct xt_rule *r, struct xtc_handle *o)
{
	char *e;
	size_t offset;
	int ok;

	if ((e = calloc (1, r->ipv6.next_offset)) == NULL)
		return 0;

	memcpy (e, &r->ipv6, sizeof (r->ipv6));
	offset = sizeof (r->ipv6);

	offset += match_push (e + offset, r->m);

	memcpy (e + offset, &r->t, r->t.target.u.user.target_size);

	ok = ip6tc_append_entry (chain, (void *) e, o);
	free (e);
	return ok;
}

int xtc_append_rule (const char *chain, struct xt_rule *r, struct xtc_handle *o)
{
	switch (r->domain) {
	case PF_INET:	return ipv4_append_rule (chain, r, o);
	case PF_INET6:	return ipv6_append_rule (chain, r, o);
	default:	return 0;
	}
}

int xt_rule_set_jump (struct xt_rule *o, const char *target)
{
	if (strlen (target) >= sizeof (o->t.target.u.user.name)) {
		errno = EINVAL;
		return 0;
	}

	strcpy (o->t.target.u.user.name, target);
	return 1;
}

int xt_rule_set_goto (struct xt_rule *o, const char *target)
{
	switch (o->domain) {
	case PF_INET:	o->ipv4.ip.flags   |= IPT_F_GOTO;
	case PF_INET6:	o->ipv6.ipv6.flags |= IP6T_F_GOTO;
	}

	return xt_rule_set_jump (o, target);
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

	if (!plus && i < size)
		mask[i] = 1;

	return 1;
}

int xt_rule_set_in (struct xt_rule *o, const char *iface)
{
	switch (o->domain) {
	case PF_INET:
		return set_iface (iface, o->ipv4.ip.iniface,
					 o->ipv4.ip.iniface_mask);
	case PF_INET6:
		return set_iface (iface, o->ipv6.ipv6.iniface,
					 o->ipv6.ipv6.iniface_mask);
	}

	return 0;
}

int xt_rule_set_out (struct xt_rule *o, const char *iface)
{
	switch (o->domain) {
	case PF_INET:
		return set_iface (iface, o->ipv4.ip.outiface,
					 o->ipv4.ip.outiface_mask);
	case PF_INET6:
		return set_iface (iface, o->ipv6.ipv6.outiface,
					 o->ipv6.ipv6.outiface_mask);
	}

	return 0;
}

#include <linux/netfilter/xt_comment.h>

int xt_rule_comment (struct xt_rule *o, const char *comment)
{
	size_t size = sizeof (struct xt_comment_info);
	struct match *m;

	if (strlen (comment) >= size) {
		errno = EINVAL;
		return 0;
	}

	if ((m = match_alloc ("comment", size)) == NULL)
		return 0;

	strcpy ((void *) m->m.data, comment);
	return xt_rule_match (o, m);
}
