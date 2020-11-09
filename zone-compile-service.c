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


static int
append_default (struct conf *root, const char *chain, const char *zone,
		struct xtc_handle *o)
{
	struct conf *c;
	char action[CHAIN_SIZE + 1];
	struct ipt_rule *r;
	int ok;

	emit ("D: append_default (%s, %s)\n", chain, zone);

	if ((c = conf_clone (root, zone, "default-action", NULL)) == NULL)
		return 1;  /* default: return to main automata */

	if (conf_get (c, action, sizeof (action)))
		goto no_action;

	if ((r = ipt_rule_alloc ()) == NULL)
		goto no_rule;

	if (!(ok = ipt_rule_set_jump (r, action)))
		emit ("E: Invalid default-action for zone %s\n", zone);
	else
		ok = iptc_append_rule (chain, r, o);

	ipt_rule_free (r);
	conf_free (c);
	return ok;
no_rule:
	conf_free (c);
	return 0;
no_action:
	conf_free (c);
	return 1;  /* default: return to main automata */
}

static int
get_peer_policy (struct conf *root, const char *zone, const char *peer,
		 char *policy)
{
	struct conf *c;
	int ok;

	c = conf_clone (root, zone, "from", peer, "policy", type, NULL);
	if (c == NULL)
		return 0;

	ok = conf_get (c, policy, CHAIN_SIZE);
	conf_free (c);
	return ok;
}

struct rule_ctx {
	struct xtc_handle *h;
	const char *chain;
	struct ipt_rule *rule;
};

static int in_rule_cb (struct conf *root, char *iface, void *cookie)
{
	struct rule_ctx *o = cookie;

	ipt_rule_set_in (o->rule, iface);
	iptc_append_rule (o->chain, o->rule, o->h);
	return 1;
}

static int out_rule_cb (struct conf *root, char *iface, void *cookie)
{
	struct rule_ctx *o = cookie;

	ipt_rule_set_out (o->rule, iface);
	iptc_append_rule (o->chain, o->rule, o->h);
	return 1;
}

static int
create_zone_chain (struct conf *root, const char *zone, struct xtc_handle *o)
{
	char chain[CHAIN_SIZE], target[CHAIN_SIZE];
	char peer[CHAIN_SIZE], policy[CHAIN_SIZE];
	struct conf *c;
	struct rule_ctx r = {o, chain};

	emit ("D: create_zone_chain (%s)\n", zone);

	if (!get_zone_chain (zone, chain) || !iptc_create_chain (chain, o))
		return 0;

	if ((c = conf_clone (root, zone, "from", NULL)) == NULL)
		goto empty;

	if ((r.rule = ipt_rule_alloc ()) == NULL)
		goto no_rule;

	while (conf_get (c, peer, sizeof (peer))) {
		if (!get_peer_policy (root, zone, peer, policy))
			continue;

		if (!get_policy_chain (policy, target))
			goto no_policy;

		emit ("D: %s from %s policy %s %s\n", zone, peer, type, policy);

		if (!iptc_is_chain (target, o)) {
			emit ("E: Policy %s %s does not exists\n", type, policy);
			errno = ENOENT;
			goto no_policy;
		}

		ipt_rule_set_goto (r.rule, target);
		conf_iterate (root, in_rule_cb, &r, peer, "interface", NULL);
	}

	ipt_rule_free (r.rule);
	conf_free (c);
empty:
	return append_default (root, chain, zone, o);
no_policy:
	ipt_rule_free (r.rule);
no_rule:
	conf_free (c);
	return 0;
}

static int
connect_transit (struct conf *root, const char *zone, struct xtc_handle *o)
{
	char target[CHAIN_SIZE], iface[CHAIN_SIZE];
	struct conf *c;
	struct ipt_rule *r;

	emit ("D: connect_transit (%s)\n", zone);

	if (!get_zone_chain (zone, target))
		return 0;

	if ((c = conf_clone (root, zone, "interface", NULL)) == NULL)
		return 1;

	if ((r = ipt_rule_alloc ()) == NULL)
		goto no_rule;

	ipt_rule_set_goto (r, target);

	while (conf_get (c, iface, sizeof (iface))) {
		ipt_rule_set_out (r, iface);
		iptc_append_rule (forward, r, o);
	}

	ipt_rule_free (r);
	conf_free (c);
	return 1;
no_rule:
	conf_free (c);
	return 0;
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
	char target[CHAIN_SIZE];
	char peer[CHAIN_SIZE], policy[CHAIN_SIZE];
	struct conf *c;
	struct rule_ctx r = {o, local_out};

	emit ("D: connect_local_out (%s)\n", zone);

	if ((c = conf_clone (root, zone, "from", NULL)) == NULL)
		goto empty;

	if ((r.rule = ipt_rule_alloc ()) == NULL)
		goto no_rule;

	while (conf_get (c, peer, sizeof (peer))) {
		if (!get_peer_policy (root, peer, zone, policy))
			continue;

		if (!get_policy_chain (policy, target))
			goto no_policy;

		emit ("D: %s from %s policy %s %s\n", zone, peer, type, policy);

		if (!iptc_is_chain (target, o)) {
			emit ("E: Policy %s %s does not exists\n", type, policy);
			errno = ENOENT;
			goto no_policy;
		}

		ipt_rule_set_goto (r.rule, target);
		conf_iterate (root, out_rule_cb, &r, peer, "interface", NULL);
	}

	ipt_rule_free (r.rule);
	conf_free (c);
empty:
	return append_default (root, local_out, zone, o);
no_policy:
	ipt_rule_free (r.rule);
no_rule:
	conf_free (c);
	return 0;
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

int zone_init (struct xtc_handle *o)
{
	char zone[CHAIN_SIZE];
	struct conf *root;
	int ok;

	emit ("D: zone_init ()\n");

	if ((root = conf_clone (NULL, "zone-policy", "zone", NULL)) == NULL)
		return 0;

	while (conf_get (root, zone, sizeof (zone)))
		if (!create_zone_chain (root, zone, o))
			goto error;

	if (!conf_rewind (root))
		goto error;

	while (conf_get (root, zone, sizeof (zone))) {
		ok = conf_exists (root, zone, "local-zone", NULL) ? (
			connect_local_in  (root, zone, o) &&
			connect_local_out (root, zone, o)
		) :
			connect_transit (root, zone, o);

		if (!ok)
			goto error;
	}

	conf_free (root);
	return iptc_commit (o);
error:
	conf_free (root);
	return 0;
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
