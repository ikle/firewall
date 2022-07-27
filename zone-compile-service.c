/*
 * Zone-based Firewall
 *
 * Copyright (c) 2020-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>

#include "chain-hash.h"
#include "conf.h"
#include "xt-rule.h"

static const char *local_in  = "ZONE_LOCAL_IN";
static const char *forward   = "ZONE_FORWARD";
static const char *local_out = "ZONE_LOCAL_OUT";

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

#define CHAIN_SIZE  29  /* XT_EXTENSION_MAXNAMELEN */

static int get_zone_chain (const char *zone, char *chain)
{
	return snprintf (chain, CHAIN_SIZE, "ZONE-%s-IN", zone) < CHAIN_SIZE;
}

static int get_policy_chain (const char *type, const char *policy, char *chain)
{
	return get_chain_hash (type, policy, NULL, chain);
}

static const char *trans_action (const char *action)
{
	return	strcmp (action, "drop")   == 0 ? "DROP"   :
		strcmp (action, "reject") == 0 ? "REJECT" :
		strcmp (action, "accept") == 0 ? "RETURN" :
		action;
}

struct policy_ctx {
	struct xtc *h;
	const char *type;
	const char *zone;
	const char *chain;
	struct xt_rule *rule;
	int linked;		/* untyped links exists */
};

static int accept_local (struct policy_ctx *o, int in)
{
	struct xt_rule *r;
	int ok;

	emit ("D: accept_local (%s, %s)\n", o->zone, in ? "in" : "out");

	if ((r = xt_rule_alloc (o->h)) == NULL)
		return 0;

	if (in)
		xt_rule_set_in (r, "lo");
	else
		xt_rule_set_out (r, "lo");

	xt_rule_set_jump (r, "RETURN");
	ok = xtc_append_rule (o->h, o->chain, r);

	xt_rule_free (r);
	return ok;
}

static int accept_local_in (struct policy_ctx *o)
{
	return accept_local (o, 1);
}

static int accept_local_out (struct policy_ctx *o)
{
	return accept_local (o, 0);
}

static int append_default (struct conf *root, struct  policy_ctx *o)
{
	char action[CHAIN_SIZE + 1];
	struct xt_rule *r;
	int ok;

	emit ("D: append_default (%s, %s)\n", o->chain, o->zone);

	if (strncmp (o->type, "firewall", 8) != 0)
		return 1;  /* not a firewall table */

	if (!conf_fetch (root, action, sizeof (action),
			 o->zone, "default-action", NULL)) {
		if (o->chain == local_out ||
		    conf_exists (root, o->zone, "local-zone", NULL))
			return 1;  /* local default: return to main automata */

		/* non-local zone default */
		strncpy (action, "drop", sizeof (action));
	}

	if ((r = xt_rule_alloc (o->h)) == NULL)
		return 0;

	if (!(ok = xt_rule_set_jump (r, trans_action (action))))
		emit ("E: Invalid default-action for zone %s\n", o->zone);
	else
		ok = xtc_append_rule (o->h, o->chain, r);

	xt_rule_free (r);
	return ok;
}

static int in_rule_cb (struct conf *root, char *iface, void *cookie)
{
	struct policy_ctx *o = cookie;

	xt_rule_set_in (o->rule, iface);
	xtc_append_rule (o->h, o->chain, o->rule);
	return 1;
}

static int out_rule_cb (struct conf *root, char *iface, void *cookie)
{
	struct policy_ctx *o = cookie;

	xt_rule_set_out (o->rule, iface);
	xtc_append_rule (o->h, o->chain, o->rule);
	return 1;
}

static int in_policy_cb (struct conf *root, char *peer, void *cookie)
{
	struct policy_ctx *o = cookie;
	char policy[CHAIN_SIZE], target[CHAIN_SIZE];

	if (!conf_fetch (root, policy, sizeof (policy),
			 o->zone, "from", peer, "policy", o->type, NULL))
		return 1;

	emit ("D: %s from %s policy %s %s\n", o->zone, peer, o->type, policy);

	if (!get_policy_chain (o->type, policy, target))
		return 0;

	if (!xtc_is_chain (o->h, target)) {
		emit ("E: Policy %s %s does not exists\n", o->type, policy);
		errno = ENOENT;
		return 0;
	}

	if ((o->rule = xt_rule_alloc (o->h)) == NULL)
		return 0;

	xt_rule_comment (o->rule, policy);
	xt_rule_set_goto (o->rule, target);
	conf_iterate (root, in_rule_cb, o, peer, "interface", NULL);

	xt_rule_free (o->rule);
	return 1;
}

static int out_policy_cb (struct conf *root, char *peer, void *cookie)
{
	struct policy_ctx *o = cookie;
	char policy[CHAIN_SIZE], target[CHAIN_SIZE];

	if (!conf_fetch (root, policy, sizeof (policy),
			 peer, "from", o->zone, "policy", o->type, NULL))
		return 1;

	emit ("D: %s from %s policy %s %s\n", o->zone, peer, o->type, policy);

	if (!get_policy_chain (o->type, policy, target))
		return 0;

	if (!xtc_is_chain (o->h, target)) {
		emit ("E: Policy %s %s does not exists\n", o->type, policy);
		errno = ENOENT;
		return 0;
	}

	if ((o->rule = xt_rule_alloc (o->h)) == NULL)
		return 0;

	xt_rule_comment (o->rule, policy);
	xt_rule_set_goto (o->rule, target);
	conf_iterate (root, out_rule_cb, o, peer, "interface", NULL);

	xt_rule_free (o->rule);
	return 1;
}

static int create_zone_chain (struct conf *root, struct policy_ctx *o)
{
	char chain[CHAIN_SIZE];

	o->chain = chain;

	emit ("D: create_zone_chain (%s)\n", o->zone);

	if (!get_zone_chain (o->zone, chain))
		return 0;

	if ((o->linked = xtc_is_chain (o->h, chain)))
		return 1;  /* untyped links exists already */

	if (!xtc_create_chain (o->h, chain))
		return 0;

	/*
	 * Accept zone internal traffic
	 */
	if ((o->rule = xt_rule_alloc (o->h)) == NULL)
		return 0;

	xt_rule_set_jump (o->rule, "RETURN");
	conf_iterate (root, in_rule_cb, o, o->zone, "interface", NULL);
	xt_rule_free (o->rule);

	/*
	 * Process policies from other zones
	 */
	return	conf_iterate (root, in_policy_cb, o, o->zone, "from", NULL) &&
		append_default (root, o);
}

static int connect_transit (struct conf *root, struct policy_ctx *o)
{
	char target[CHAIN_SIZE];

	o->chain = forward;

	emit ("D: connect_transit (%s)\n", o->zone);

	if (o->linked)
		return 1;  /* untyped links exists already */

	if (!get_zone_chain (o->zone, target))
		return 0;

	if ((o->rule = xt_rule_alloc (o->h)) == NULL)
		return 0;

	xt_rule_set_goto (o->rule, target);
	conf_iterate (root, out_rule_cb, o, o->zone, "interface", NULL);

	xt_rule_free (o->rule);
	return 1;
}

static int connect_local_in (struct conf *root, struct policy_ctx *o)
{
	char target[CHAIN_SIZE];
	struct xt_rule *r;
	int ok;

	o->chain = local_in;

	emit ("D: connect_local_in (%s)\n", o->zone);

	if (o->linked)
		return 1;  /* untyped links exists already */

	if (!accept_local_in (o) ||
	    !get_zone_chain (o->zone, target) ||
	    (r = xt_rule_alloc (o->h)) == NULL)
		return 0;

	xt_rule_set_goto (r, target);
	ok = xtc_append_rule (o->h, o->chain, r);

	xt_rule_free (r);
	return ok;
}

static int connect_local_out (struct conf *root, struct policy_ctx *o)
{
	o->chain = local_out;

	emit ("D: connect_local_out (%s)\n", o->zone);

	return	conf_iterate (root, out_policy_cb, o, o->zone, "from", NULL) &&
		accept_local_out (o) &&
		append_default (root, o);
}

/*
 * Clean up zones
 */
static void zone_fini (struct xtc *o)
{
	const char *chain;

	xtc_flush_entries (o, local_in);
	xtc_flush_entries (o, forward);
	xtc_flush_entries (o, local_out);

	emit ("D: zone_fini ()\n");

	for (
		chain = xtc_first_chain (o);
		chain != NULL;
		chain = xtc_next_chain (o)
	)
		if (strncmp (chain, "ZONE-", 5) == 0) {
			xtc_flush_entries (o, chain);
			xtc_delete_chain  (o, chain);
		}
}

static int zone_chain_cb (struct conf *root, char *zone, void *cookie)
{
	struct policy_ctx *o = cookie;

	o->zone = zone;
	return create_zone_chain (root, o);
}

static int zone_policy_cb (struct conf *root, char *zone, void *cookie)
{
	struct policy_ctx *o = cookie;

	o->zone = zone;

	return conf_exists (root, zone, "local-zone", NULL) ? (
		connect_local_in  (root, o) &&
		connect_local_out (root, o)
	) :
		connect_transit (root, o);
}

/*
 * Initialize zones
 */
static int zone_init (struct xtc *o, const char *type)
{
	struct conf *root;
	struct policy_ctx p = {o, type};
	int ok;

	emit ("D: zone_init (%s)\n", type);

	if ((root = conf_clone (NULL, "zone-policy", "zone", NULL)) == NULL)
		return 1;

	ok = conf_iterate (root, zone_chain_cb,  &p, NULL) &&
	     conf_iterate (root, zone_policy_cb, &p, NULL);

	if (!ok)
		emit ("E: %s: %s\n", type, xtc_error (xtc_domain (o)));

	conf_free (root);
	return ok;
}

/*
 * Top-Level Logic State
 */
struct zone_state {
	struct xtc *filter_ipv4;
	struct xtc *filter_ipv6;

	struct xtc *mangle_ipv4;
	struct xtc *mangle_ipv6;
};

/*
 * Open connection for all protocols and tables
 */
int zone_enter (struct zone_state *o)
{
	if ((o->filter_ipv4 = xtc_alloc (XTC_INET,  "filter")) == NULL) {
		emit ("E: IPv4 filter: %s\n", xtc_error (XTC_INET));
		goto no_filter_ipv4;
	}

	if ((o->filter_ipv6 = xtc_alloc (XTC_INET6, "filter")) == NULL) {
		emit ("E: IPv6 filter: %s\n", xtc_error (XTC_INET6));
		goto no_filter_ipv6;
	}

	if ((o->mangle_ipv4 = xtc_alloc (XTC_INET,  "mangle")) == NULL) {
		emit ("E: IPv4 mangle: %s\n", xtc_error (XTC_INET));
		goto no_mangle_ipv4;
	}

	if ((o->mangle_ipv6 = xtc_alloc (XTC_INET6, "mangle")) == NULL) {
		emit ("E: IPv4 mangle: %s\n", xtc_error (XTC_INET6));
		goto no_mangle_ipv6;
	}

	zone_fini (o->filter_ipv4);
	zone_fini (o->filter_ipv6);
	zone_fini (o->mangle_ipv4);
	zone_fini (o->mangle_ipv6);

	return 1;
no_mangle_ipv6:
	xtc_free (o->mangle_ipv4);
no_mangle_ipv4:
	xtc_free (o->filter_ipv6);
no_filter_ipv6:
	xtc_free (o->filter_ipv4);
no_filter_ipv4:
	return 0;
}

/*
 * Compile zone rules
 */
int zone_compile (struct zone_state *o)
{
	return	zone_init (o->filter_ipv4, "firewall")		&&
		zone_init (o->filter_ipv6, "firewall-ipv6")	&&
		zone_init (o->mangle_ipv4, "clone")		&&
		zone_init (o->mangle_ipv6, "clone-ipv6")	&&
		zone_init (o->mangle_ipv4, "modify")		&&
		zone_init (o->mangle_ipv6, "modify-ipv6");
}

static int xtc_final (struct xtc *o, const char *type)
{
	int ok = xtc_commit (o);

	if (!ok)
		emit ("E: %s: %s\n", type, xtc_error (xtc_domain (o)));

	xtc_free (o);
	return ok;
}

/*
 * Commit all changes and return cumulative status
 */
int zone_leave (struct zone_state *o)
{
	int ok = 0;

	ok |= xtc_final (o->filter_ipv4, "firewall");
	ok |= xtc_final (o->filter_ipv6, "firewall-ipv6");
	ok |= xtc_final (o->mangle_ipv4, "clone/modify");
	ok |= xtc_final (o->mangle_ipv6, "clone/modify-ipv6");

	return ok;
}

int main (int argc, char *argv[])
{
	size_t i;
	struct zone_state s;
	int ok;

	for (; argc > 1 && argv[1][0] == '-'; --argc, ++argv)
		for (i = 1; argv[1][i] != '\0'; ++i)
			switch (argv[1][i]) {
			case 'v':	++verbose; break;
			}

	if (argc != 1) {
		emit ("usage:\n\tzone-compile [-v]\n");
		return 1;
	}

	ok = zone_enter (&s) && zone_compile (&s) && zone_leave (&s);
	return ok ? 0: 1;
}
