/*
 * IP Tables Control Helpers
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef NET_XTC_H
#define NET_XTC_H  1

enum xtc_domain {
	XTC_INET,
	XTC_INET6,
	XTC_ARP,
	XTC_ETHERNET,
};

struct xtc *xtc_alloc (int domain, const char *table);
void xtc_free (struct xtc *o);

int xtc_domain (struct xtc *o);

const char *xtc_error (int domain);

int xtc_is_chain (struct xtc *o, const char *chain);

const char *xtc_first_chain (struct xtc *o);
const char *xtc_next_chain  (struct xtc *o);

const void *xtc_first_rule (struct xtc *o, const char *chain);
const void *xtc_next_rule  (struct xtc *o, const void *prev);
const char *xtc_get_target (struct xtc *o, const void *e);

int xtc_create_chain  (struct xtc *o, const char *chain);
int xtc_flush_entries (struct xtc *o, const char *chain);
int xtc_delete_chain  (struct xtc *o, const char *chain);

int xtc_append_entry (struct xtc *o, const char *chain, const void *e);

int xtc_commit (struct xtc *o);

#endif  /* NET_XTC_H */
