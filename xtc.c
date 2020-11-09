/*
 * IP Tables Helpers
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <libiptc/libiptc.h>
#include <libiptc/libip6tc.h>

#include "xtc.h"

struct xtc {
	int domain;
	struct xtc_handle *h;
};

struct xtc *xtc_alloc (int domain, const char *table)
{
	struct xtc *o;

	if ((o = malloc (sizeof (*o))) == NULL)
		return NULL;

	switch (o->domain = domain) {
	case PF_INET:	o->h = iptc_init  (table); break;
	case PF_INET6:	o->h = ip6tc_init (table); break;
	default:
		errno = ENOSYS;
		break;
	}

	if (o->h != NULL)
		return o;

	free (o);
	return NULL;
}

void xtc_free (struct xtc *o)
{
	switch (o->domain) {
	case PF_INET:	iptc_free  (o->h); break;
	case PF_INET6:	ip6tc_free (o->h); break;
	}

	free (o);
}

const char *xtc_error (int domain)
{
	switch (domain) {
	case PF_INET:	return iptc_strerror  (errno);
	case PF_INET6:	return ip6tc_strerror (errno);
	default:	return strerror (errno);
	}
}

int xtc_is_chain (struct xtc *o, const char *chain)
{
	switch (o->domain) {
	case PF_INET:	return iptc_is_chain  (chain, o->h);
	case PF_INET6:	return ip6tc_is_chain (chain, o->h);
	default:	return 0;
	}
}

const char *xtc_first_chain (struct xtc *o)
{
	switch (o->domain) {
	case PF_INET:	return iptc_first_chain  (o->h);
	case PF_INET6:	return ip6tc_first_chain (o->h);
	default:	return NULL;
	}
}

const char *xtc_next_chain (struct xtc *o)
{
	switch (o->domain) {
	case PF_INET:	return iptc_next_chain  (o->h);
	case PF_INET6:	return ip6tc_next_chain (o->h);
	default:	return NULL;
	}
}

const void *xtc_first_rule (struct xtc *o, const char *chain)
{
	switch (o->domain) {
	case PF_INET:	return iptc_first_rule  (chain, o->h);
	case PF_INET6:	return ip6tc_first_rule (chain, o->h);
	default:	return NULL;
	}
}

const void *xtc_next_rule (struct xtc *o, const void *prev)
{
	switch (o->domain) {
	case PF_INET:	return iptc_next_rule  (prev, o->h);
	case PF_INET6:	return ip6tc_next_rule (prev, o->h);
	default:	return NULL;
	}
}

const char *xtc_get_target (struct xtc *o, const void *e)
{
	switch (o->domain) {
	case PF_INET:	return iptc_get_target  (e, o->h);
	case PF_INET6:	return ip6tc_get_target (e, o->h);
	default:	return NULL;
	}
}

int xtc_create_chain (struct xtc *o, const char *chain)
{
	switch (o->domain) {
	case PF_INET:	return iptc_create_chain  (chain, o->h);
	case PF_INET6:	return ip6tc_create_chain (chain, o->h);
	default:	return 0;
	}
}

int xtc_flush_entries (struct xtc *o, const char *chain)
{
	switch (o->domain) {
	case PF_INET:	return iptc_flush_entries  (chain, o->h);
	case PF_INET6:	return ip6tc_flush_entries (chain, o->h);
	default:	return 0;
	}
}

int xtc_delete_chain (struct xtc *o, const char *chain)
{
	switch (o->domain) {
	case PF_INET:	return iptc_delete_chain  (chain, o->h);
	case PF_INET6:	return ip6tc_delete_chain (chain, o->h);
	default:	return 0;
	}
}

int xtc_append_entry (struct xtc *o, const char *chain, const void *e)
{
	switch (o->domain) {
	case PF_INET:	return iptc_append_entry  (chain, e, o->h);
	case PF_INET6:	return ip6tc_append_entry (chain, e, o->h);
	default:	return 0;
	}
}

int xtc_commit (struct xtc *o)
{
	switch (o->domain) {
	case PF_INET:	return iptc_commit  (o->h);
	case PF_INET6:	return ip6tc_commit (o->h);
	default:	return 0;
	}
}
