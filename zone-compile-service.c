/*
 * Zone-based Firewall
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "chain-hash.h"
#include "conf.h"
#include "ipt.h"

static const char *local_in  = "ZONE_LOCAL_IN";
static const char *forward   = "ZONE_FORWARD";
static const char *local_out = "ZONE_LOCAL_OUT";

static const char *type = "firewall";

static int verbose;

static void emit (const char *fmt, ...)
{
	va_list ap;

	switch (fmt[0]) {
	case 'I':	if (verbose < 1) return;
	case 'D':	if (verbose < 2) return;
	}

	va_start (ap, fmt);
	vfprintf (stderr, fmt, ap);
	va_end (ap);
}

#define CHAIN_SIZE  (XT_EXTENSION_MAXNAMELEN)

static int get_zone_chain (const char *zone, char *chain)
{
	return snprintf (chain, CHAIN_SIZE, "ZONE-%s-IN", zone) < CHAIN_SIZE;
}

static int get_policy_chain (const char *policy, char *chain)
{
	return get_chain_hash (type, policy, NULL, chain);
}

static const char *trans_action (const char *action)
{
	return	strcmp (action, "drop")   == 0 ? "DROP"   :
		strcmp (action, "reject") == 0 ? "REJECT" :
		action;
}

static int
append_default (struct conf *root, const char *chain, const char *zone,
		struct xtc_handle *o)
{
	char action[CHAIN_SIZE + 1];
	struct ipt_rule *r;
	int ok;

	emit ("D: append_default (%s, %s)\n", chain, zone);

	if (!conf_fetch (root, action, sizeof (action),
			 zone, "default-action", NULL))
		return 1;  /* default: return to main automata */

	if ((r = ipt_rule_alloc ()) == NULL)
		return 0;

	if (!(ok = ipt_rule_set_jump (r, trans_action (action))))
		emit ("E: Invalid default-action for zone %s\n", zone);
	else
		ok = iptc_append_rule (chain, r, o);

	ipt_rule_free (r);
	return ok;
}

struct policy_ctx {
	struct xtc_handle *h;
	const char *zone;
	const char *chain;
	struct ipt_rule *rule;
};

static int in_rule_cb (struct conf *root, char *iface, void *cookie)
{
	struct policy_ctx *o = cookie;

	ipt_rule_set_in (o->rule, iface);
	iptc_append_rule (o->chain, o->rule, o->h);
	return 1;
}

static int out_rule_cb (struct conf *root, char *iface, void *cookie)
{
	struct policy_ctx *o = cookie;

	ipt_rule_set_out (o->rule, iface);
	iptc_append_rule (o->chain, o->rule, o->h);
	return 1;
}

static int in_policy_cb (struct conf *root, char *peer, void *cookie)
{
	struct policy_ctx *o = cookie;
	char policy[CHAIN_SIZE], target[CHAIN_SIZE];

	if (!conf_fetch (root, policy, sizeof (policy),
			 o->zone, "from", peer, "policy", type, NULL))
		return 1;

	emit ("D: %s from %s policy %s %s\n", o->zone, peer, type, policy);

	if (!get_policy_chain (policy, target))
		return 0;

	if (!iptc_is_chain (target, o->h)) {
		emit ("E: Policy %s %s does not exists\n", type, policy);
		errno = ENOENT;
		return 0;
	}

	if ((o->rule = ipt_rule_alloc ()) == NULL)
		return 0;

	ipt_rule_comment (o->rule, policy);
	ipt_rule_set_goto (o->rule, target);
	conf_iterate (root, in_rule_cb, o, peer, "interface", NULL);

	ipt_rule_free (o->rule);
	return 1;
}

static int out_policy_cb (struct conf *root, char *peer, void *cookie)
{
	struct policy_ctx *o = cookie;
	char policy[CHAIN_SIZE], target[CHAIN_SIZE];

	if (!conf_fetch (root, policy, sizeof (policy),
			 peer, "from", o->zone, "policy", type, NULL))
		return 1;

	emit ("D: %s from %s policy %s %s\n", o->zone, peer, type, policy);

	if (!get_policy_chain (policy, target))
		return 0;

	if (!iptc_is_chain (target, o->h)) {
		emit ("E: Policy %s %s does not exists\n", type, policy);
		errno = ENOENT;
		return 0;
	}

	if ((o->rule = ipt_rule_alloc ()) == NULL)
		return 0;

	ipt_rule_comment (o->rule, policy);
	ipt_rule_set_goto (o->rule, target);
	conf_iterate (root, out_rule_cb, o, peer, "interface", NULL);

	ipt_rule_free (o->rule);
	return 1;
}

static int
create_zone_chain (struct conf *root, const char *zone, struct xtc_handle *o)
{
	char chain[CHAIN_SIZE];
	struct policy_ctx p = {o, zone, chain};

	emit ("D: create_zone_chain (%s)\n", zone);

	if (!get_zone_chain (zone, chain) || !iptc_create_chain (chain, o))
		return 0;

	return	conf_iterate (root, in_policy_cb, &p, zone, "from", NULL) &&
		append_default (root, chain, zone, o);
}

static int
connect_transit (struct conf *root, const char *zone, struct xtc_handle *o)
{
	char target[CHAIN_SIZE];
	struct policy_ctx p = {o, zone, forward};

	emit ("D: connect_transit (%s)\n", zone);

	if (!get_zone_chain (zone, target))
		return 0;

	if ((p.rule = ipt_rule_alloc ()) == NULL)
		return 0;

	ipt_rule_set_goto (p.rule, target);
	conf_iterate (root, out_rule_cb, &p, zone, "interface", NULL);

	ipt_rule_free (p.rule);
	return 1;
}

static int
connect_local_in (struct conf *root, const char *zone, struct xtc_handle *o)
{
	char target[CHAIN_SIZE];
	struct ipt_rule *r;
	int ok;

	emit ("D: connect_local_in (%s)\n", zone);

	if (!get_zone_chain (zone, target) || (r = ipt_rule_alloc ()) == NULL)
		return 0;

	ipt_rule_set_goto (r, target);
	ok = iptc_append_rule (local_in, r, o);

	ipt_rule_free (r);
	return ok;
}

static int
connect_local_out (struct conf *root, const char *zone, struct xtc_handle *o)
{
	struct policy_ctx p = {o, zone, local_out};

	emit ("D: connect_local_out (%s)\n", zone);

	return	conf_iterate (root, out_policy_cb, &p, zone, "from", NULL) &&
		append_default (root, local_out, zone, o);
}

void zone_fini (struct xtc_handle *o)
{
	const char *chain;

	iptc_flush_entries (local_in,  o);
	iptc_flush_entries (forward,   o);
	iptc_flush_entries (local_out, o);

	emit ("D: zone_fini ()\n");

	for (
		chain = iptc_first_chain (o);
		chain != NULL;
		chain = iptc_next_chain (o)
	)
		if (strncmp (chain, "ZONE-", 5) == 0) {
			iptc_flush_entries (chain, o);
			iptc_delete_chain  (chain, o);
		}
}

static int zone_chain_cb (struct conf *root, char *zone, void *cookie)
{
	struct xtc_handle *o = cookie;

	return create_zone_chain (root, zone, o);
}

static int zone_policy_cb (struct conf *root, char *zone, void *cookie)
{
	struct xtc_handle *o = cookie;

	return conf_exists (root, zone, "local-zone", NULL) ? (
		connect_local_in  (root, zone, o) &&
		connect_local_out (root, zone, o)
	) :
		connect_transit (root, zone, o);
}

int zone_init (struct xtc_handle *o)
{
	struct conf *root;
	int ok;

	emit ("D: zone_init ()\n");

	if ((root = conf_clone (NULL, "zone-policy", "zone", NULL)) == NULL)
		return 0;

	ok = conf_iterate (root, zone_chain_cb,  o, NULL) &&
	     conf_iterate (root, zone_policy_cb, o, NULL) &&
	     iptc_commit (o);

	conf_free (root);
	return ok;
}

int main (int argc, char *argv[])
{
	size_t i;
	struct xtc_handle *o;

	for (; argc > 1 && argv[1][0] == '-'; --argc, ++argv)
		for (i = 1; argv[1][i] != '\0'; ++i)
			switch (argv[1][i]) {
			case 'v':	++verbose; break;
			}

	if ((o = iptc_init ("filter")) == NULL) {
		emit ("E: %s\n", iptc_strerror (errno));
		return 1;
	}

	zone_fini (o);

	if (!zone_init (o)) {
		emit ("E: %s\n", iptc_strerror (errno));
		iptc_free (o);
		return 1;
	}

	iptc_free (o);
	return 0;
}
