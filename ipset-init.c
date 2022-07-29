/*
 * IpSet Helpers
 *
 * Copyright (c) 2017-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <libipset/session.h>

#include "ipset.h"

#ifndef IPSET_V7
static void ipset_envopt_set(struct ipset_session *s, enum ipset_envopt opt)
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

struct ipset_session *ipset_session_init_silent (int exists)
{
	struct ipset_session *s;

	if ((s = ipset_session_init (ipset_out IPSET_OUT_ARG)) == NULL)
		return s;

	ipset_envopt_set (s, IPSET_ENV_EXIST);
	return s;
}
