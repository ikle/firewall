/*
 * Netfilter IpSet helper
 *
 * Copyright (c) 2020-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>

#include <sys/socket.h>

#include <netinet/in.h>
#include <unistd.h>

#include <linux/netfilter/ipset/ip_set.h>

#include "ipset-raw.h"

int ipset_get_index (const char *name)
{
	struct ip_set_req_get_set req;
	socklen_t size = sizeof (req);
	int s, ret;

	if ((s = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
		return -1;

	req.version = IPSET_PROTOCOL;
	req.op      = IP_SET_OP_GET_BYNAME;

	snprintf (req.set.name, sizeof (req.set.name), "%s", name);

	ret = getsockopt (s, SOL_IP, SO_IP_SET, &req, &size);
	close (s);

	if (ret != 0 || req.set.index == IPSET_INVALID_ID)
		return -1;

	return req.set.index;
}
