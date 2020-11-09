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

struct ipt_rule {
	struct ipt_entry e;
	struct xt_standard_target t;
	struct match *m;
};

struct ipt_rule *ipt_rule_alloc (void)
{
	struct ipt_rule *o;

	if ((o = calloc (1, sizeof (*o))) == NULL)
		return NULL;

	o->t.target.u.user.target_size = XT_ALIGN (sizeof (o->t));

	o->e.target_offset = sizeof (o->e);
	o->e.next_offset = o->e.target_offset + o->t.target.u.user.target_size;

	return o;
}

void ipt_rule_free (struct ipt_rule *o)
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

static int ipt_rule_match (struct ipt_rule *o, struct match *m)
{
	o->e.target_offset += m->m.u.user.match_size;
	o->e.next_offset   += m->m.u.user.match_size;

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

int
iptc_append_rule (const char *chain, struct ipt_rule *r, struct xtc_handle *o)
{
	char *e;
	size_t offset;
	int ok;

	if ((e = calloc (1, r->e.next_offset)) == NULL)
		return 0;

	memcpy (e, &r->e, sizeof (r->e));
	offset = sizeof (r->e);

	offset += match_push (e + offset, r->m);

	memcpy (e + offset, &r->t, r->t.target.u.user.target_size);

	ok = iptc_append_entry (chain, (void *) e, o);
	free (e);
	return ok;
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

	if (!plus && i < size)
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

#include <linux/netfilter/xt_comment.h>

int ipt_rule_comment (struct ipt_rule *o, const char *comment)
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
	return ipt_rule_match (o, m);
}
