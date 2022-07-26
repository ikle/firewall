/*
 * EAPoL Agent
 *
 * Copyright (c) 2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <syslog.h>
#include <unistd.h>

#include "chain-hash.h"
#include "conf.h"
#include "ipset.h"
#include "wpac.h"

static int get_reauth (const char *policy, int def)
{
	char v[32];

	if (!conf_fetch (NULL, v, sizeof (v),
			 "service", "eapol", policy, "reauth", NULL))
		return def;

	return atoi (v);
}

static int get_policy (const char *iface, char *data, size_t len)
{
	return conf_fetch (NULL, data, len,
			   "interfaces", "ethernet", iface, "authenticator",
			   NULL);
}

struct eapol_set {
	struct ipset_session *s;
	char policy[64];
	char name[28];
	const char *type;
	int timeout;
};

static int eapol_set_init (struct eapol_set *o, const char *iface)
{
	if (!get_policy (iface, o->policy, sizeof (o->policy)) ||
	    !get_chain_hash ("eapol", o->policy, NULL, o->name))
		return 0;

	o->name[27] = '\0';
	o->type = "hash:mac";
	o->timeout = 120 + 5;

	if ((o->s = ipset_session_init_silent (1)) == NULL)
		return 0;

	if (!ipset_create (o->s, o->name, o->type, 120) ||
	    ipset_commit (o->s) != 0)
		goto no_create;

	syslog (LOG_INFO, "Created %s policy set", o->policy);
	return 1;
no_create:
	ipset_session_fini (o->s);
	syslog (LOG_ERR, "Cannot create %s policy set", o->policy);
	return 0;
}

static void eapol_set_fini (struct eapol_set *o)
{
	ipset_session_fini (o->s);
}

static int parse_mac (const char *data, void *mac)
{
	unsigned char *p = mac;

	if (sscanf (data, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		    p, p + 1, p + 2, p + 3, p + 4, p + 5) == 6)
		return 1;

	return 0;
}

static int eapol_cb (int level, char *data, size_t len, void *cookie)
{
	struct eapol_set *o = cookie;
	const char *ev = data;
	char *p;
	unsigned char mac[6];

	if (level != WPAC_INFO || (p = memchr (data, ' ', len)) == NULL)
		return 1;

	*p++ = '\0';

	if (strcmp (ev, "AP-STA-CONNECTED")        == 0 ||
	    strcmp (ev, "CTRL-EVENT-EAP-SUCCESS")  == 0 ||
	    strcmp (ev, "CTRL-EVENT-EAP-SUCCESS2") == 0) {
		if (parse_mac (p, mac) &&
		    ipset_add_mac (o->s, o->name, o->type, mac, o->timeout) &&
		    ipset_commit (o->s) == 0)
			syslog (LOG_NOTICE,
				"Authorized %02x:%02x:%02x:%02x:%02x:%02x "
				"for %s policy",
				mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
				o->policy);
		return 1;
	}

	return 1;
}

int main (int argc, char *argv[])
{
	struct eapol_set c;
	char path[128];
	struct wpac *o;

	if (argc != 2) {
		fprintf (stderr, "usage:\n\teapol-agent iface\n");
		return 1;
	}

	chain_hash_init ();
	ipset_load_types ();
	openlog ("eapol-agent", 0, LOG_AUTH);

	snprintf (path, sizeof (path), "/var/run/hostapd/%s", argv[1]);

	for (;; sleep (1)) {
		if (!eapol_set_init (&c, argv[1]))
			continue;

		if ((o = wpac_alloc (path, eapol_cb, &c)) != NULL) {
			c.timeout = get_reauth (c.policy, 120) + 5;

			syslog (LOG_INFO, "Monitor events for %s policy",
				c.policy);
			wpac_monitor (o);
			wpac_free (o);
		}

		eapol_set_fini (&c);
	}

	return 0;
}
