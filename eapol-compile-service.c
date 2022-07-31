/*
 * EAPoL Firewall Compiler
 *
 * Copyright (c) 2020-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>

#include "chain-hash.h"
#include "conf.h"
#include "xt-rule.h"

/*
 * Make EAPoL policy chain
 */
struct eapol_ctx {
	struct xtc *h;
	const char *chain;
};

static int iface_cb (struct conf *root, char *iface, void *cookie)
{
	struct eapol_ctx *o = cookie;
	char name[28];
	struct xt_rule *rule;
	int ok;

	if (!conf_exists (root, iface, "authenticator", NULL))
		return 1;

	if (!get_chain_hash ("eapol", iface, NULL, name))
		return 0;

	if ((rule = xt_rule_alloc (o->h)) == NULL)
		return 0;

	ok  = xt_rule_set_in    (rule, iface);
	ok &= xt_rule_match_set (rule, name, 1, 0x3);  /* !src */
	ok &= xt_rule_set_jump  (rule, "DROP");
	ok &= xtc_append_rule (o->h, o->chain, rule);

	xt_rule_free (rule);
	return ok;
}

static int policy_make (struct xtc *o, const char *chain)
{
	struct eapol_ctx c = {o, chain};
	struct conf *root;
	struct xt_rule *rule;
	int ok;

	ok = xtc_is_chain (o, chain) ?	xtc_flush_entries (o, chain) :
					xtc_create_chain  (o, chain);
	if (!ok)
		return 0;

	if ((root = conf_clone (NULL, "interfaces", "ethernet", NULL)) != NULL) {
		ok = conf_iterate (root, iface_cb, &c, NULL);
		conf_free (root);

		if (!ok)
			return 0;
	}

	if ((rule = xt_rule_alloc (o)) == NULL)
		return 0;

	ok  = xt_rule_set_jump (rule, "RETURN");
	ok &= xtc_append_rule (o, chain, rule);

	xt_rule_free (rule);
	return ok;
}

/*
 * Top-Level Logic
 */
static int policy_compile (const char *type, int domain)
{
	struct xtc *o;

	if ((o = xtc_alloc (domain, "filter")) == NULL)
		goto no_xtc;

	if (!policy_make (o, "eapol-auth") || !xtc_commit (o))
		goto no_make;

	xtc_free (o);
	return 1;
no_make:
	xtc_free (o);
no_xtc:
	fprintf (stderr, "E: %s: %s\n", type, xtc_error (domain));
	return 0;
}

int main (int argc, char *argv[])
{
	int ok;

	chain_hash_init ();

	ok = policy_compile ("IPv4", XTC_INET) &&
	     policy_compile ("IPv6", XTC_INET6);
	return ok ? 0 : 1;
}
