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
#include "ipset.h"
#include "wpac.h"

#ifndef IPSET_V7
static void
ipset_envopt_set(struct ipset_session *s, enum ipset_envopt opt)
{
	ipset_envopt_parse (s, opt, NULL);
}

#define IPSET_OUT_ARG
static int ipset_out (const char *fmt, ...)
#else
#define IPSET_OUT_ARG  , NULL
static
int ipset_out (struct ipset_session *session, void *p, const char *fmt, ...)
#endif
{
	return 0;
}

struct eapol_set {
	struct ipset_session *s;
	const char *policy;
	char name[28];
	const char *type;
	int timeout;
};

static int
eapol_set_init (struct eapol_set *o, const char *policy, const char *timeout)
{
	if (!get_chain_hash ("eapol", policy, NULL, o->name))
		return 0;

	o->policy = policy;
	o->name[27] = '\0';
	o->type = "hash:mac";
	o->timeout = atoi (timeout);

	if ((o->s = ipset_session_init (ipset_out IPSET_OUT_ARG)) == NULL)
		return 0;

	ipset_envopt_set (o->s, IPSET_ENV_EXIST);

	if (!ipset_create (o->s, o->name, o->type, 120) ||
	    ipset_commit (o->s) != 0)
		goto no_create;

	syslog (LOG_INFO, "Created %s policy set", policy);
	return 1;
no_create:
	ipset_session_fini (o->s);
	syslog (LOG_ERR, "Cannot create %s policy set", policy);
	return 0;
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

	if (argc != 4) {
		fprintf (stderr,
			 "usage:\n"
			 "\teapol-agent iface policy timeout\n");
		return 1;
	}

	chain_hash_init ();
	ipset_load_types ();
	openlog ("eapol-agent", 0, LOG_AUTH);

	if (!eapol_set_init (&c, argv[2], argv[3])) {
		fprintf (stderr, "E: Cannot init EAPoL set\n");
		return 1;
	}

	snprintf (path, sizeof (path), "/var/run/hostapd/%s", argv[1]);

	for (;;) {
		if ((o = wpac_alloc (path, eapol_cb, &c)) != NULL) {
			syslog (LOG_INFO, "Monitor events for %s policy",
				c.policy);
			wpac_monitor (o);
			wpac_free (o);
		}

		sleep (1);
	}

	return 0;
}
