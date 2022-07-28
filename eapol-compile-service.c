/*
 * EAPoL Firewall Compiler
 *
 * Copyright (c) 2020-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdarg.h>
#include <stdio.h>

#include "chain-hash.h"
#include "conf.h"
#include "xt-rule.h"

static const char *chain = "eapol-auth";

static void emit (const char *fmt, ...)
{
	va_list ap;

	va_start (ap, fmt);
	vfprintf (stderr, fmt, ap);
	va_end (ap);
}

/*
 * Make EAPoL policy chain
 */
static int iface_cb (struct conf *root, char *iface, void *cookie)
{
	struct xtc *o = cookie;
	char policy[128], name[28];
	struct xt_rule *rule;
	int ok = 1;

	if (!conf_fetch (root, policy, sizeof (policy),
			 iface, "authenticator", NULL))
		return 1;

	if (!get_chain_hash ("eapol", policy, NULL, name))
		return 0;

	if ((rule = xt_rule_alloc (o)) == NULL)
		return 0;

	ok &= xt_rule_set_in    (rule, iface);
	ok &= xt_rule_match_set (rule, name, 1, 0x3);  /* !src */
	ok &= xt_rule_set_jump  (rule, "DROP");

	if (ok)
		ok = xtc_append_rule (o, chain, rule);

	xt_rule_free (rule);
	return ok;
}

static int policy_close (struct xtc *o)
{
	struct xt_rule *rule;
	int ok;

	if ((rule = xt_rule_alloc (o)) == NULL)
		return 0;

	xt_rule_set_jump (rule, "RETURN");

	ok = xtc_append_rule (o, chain, rule);

	xt_rule_free (rule);
	return ok;
}

static int policy_make (struct xtc *o, const char *type)
{
	struct conf *root;
	int ok;

	ok = xtc_is_chain (o, chain) ?	xtc_flush_entries (o, chain) :
					xtc_create_chain  (o, chain);
	if (!ok)
		return 0;

	if ((root = conf_clone (NULL, "interfaces", "ethernet", NULL)) != NULL) {
		ok = conf_iterate (root, iface_cb, o, NULL);
		conf_free (root);

		if (!ok) {
			emit ("E: %s: %s\n", type, xtc_error (xtc_domain (o)));
			return 0;
		}
	}

	return policy_close (o);
}

/*
 * Top-Level Logic State
 */
struct policy_state {
	struct xtc *filter_ipv4;
	struct xtc *filter_ipv6;
};

static int policy_enter (struct policy_state *o)
{
	if ((o->filter_ipv4 = xtc_alloc (XTC_INET,  "filter")) == NULL) {
		emit ("E: IPv4 filter: %s\n", xtc_error (XTC_INET));
		goto no_filter_ipv4;
	}

	if ((o->filter_ipv6 = xtc_alloc (XTC_INET6, "filter")) == NULL) {
		emit ("E: IPv6 filter: %s\n", xtc_error (XTC_INET6));
		goto no_filter_ipv6;
	}

	return 1;
no_filter_ipv6:
	xtc_free (o->filter_ipv4);
no_filter_ipv4:
	return 0;
}

static int policy_compile (struct policy_state *o)
{
	return	policy_make (o->filter_ipv4, "IPv4") &&
		policy_make (o->filter_ipv6, "IPv6");
}

static int xtc_final (struct xtc *o, const char *type)
{
	int ok = xtc_commit (o);

	if (!ok)
		emit ("E: %s: %s\n", type, xtc_error (xtc_domain (o)));

	xtc_free (o);
	return ok;
}

static int policy_leave (struct policy_state *o)
{
	int ok = 1;

	ok &= xtc_final (o->filter_ipv4, "IPv4");
	ok &= xtc_final (o->filter_ipv6, "IPv6");

	return ok;
}

int main (int argc, char *argv[])
{
	struct policy_state s;
	int ok;

	chain_hash_init ();

	ok = policy_enter (&s) && policy_compile (&s) && policy_leave (&s);
	return ok ? 0 : 1;
}
