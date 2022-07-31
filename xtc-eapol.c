/*
 * EAPoL Firewall Compiler
 *
 * Copyright (c) 2020-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "chain-hash.h"
#include "conf.h"
#include "xt-rule.h"
#include "xtc-eapol.h"

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

int xtc_eapol_compile (struct xtc *o, const char *chain)
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

	if ((root = conf_clone (NULL, "interfaces", "bonding", NULL)) != NULL) {
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
