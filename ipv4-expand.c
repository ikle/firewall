/*
 * Internet address range to network list expander
 *
 * Copyright (c) 2017 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <stdint.h>

#include <arpa/inet.h>

#include "ipv4-expand.h"

typedef uint32_t u32;
typedef unsigned long long ull;

/* floor to power of two */
static ull flp2 (ull x)
{
	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	x |= x >> 8;
	x |= x >> 16;
	x |= x >> 32;

	return x - (x >> 1);
}

static unsigned cidr_from_range (ull x)
{
	if (x == (1ULL << 32))
		return 1;

	return __builtin_clz (x) + 1;
}

static int net_up (u32 m, ull range, ipv4_net_cb *cb, void *cookie)
{
	ull step;
	struct ipv4_masked o;

	for (step = flp2 (range); step > 0; step = flp2 (range)) {
		o.addr.s_addr = htonl (m);
		o.mask = cidr_from_range (step);

		if (!cb (&o, cookie))
			return 0;

		m += step, range -= step;
	}

	return 1;
}

static int net_down (u32 m, ull range, ipv4_net_cb *cb, void *cookie)
{
	ull step;
	struct ipv4_masked o;

	for (step = flp2 (range); step > 0; step = flp2 (range)) {
		m -= step, range -= step;

		o.addr.s_addr = htonl (m);
		o.mask = cidr_from_range (step);

		if (!cb (&o, cookie))
			return 0;
	}

	return 1;
}

static u32 floor_to2 (u32 x, u32 to)
{
	return x & ~(to - 1);
}

int ipv4_range_expand (struct ipv4_range *o, ipv4_net_cb *cb, void *cookie)
{
	u32 start = ntohl (o->start.s_addr);
	u32 stop  = ntohl (o->stop.s_addr);

	u32 m = floor_to2 (stop, flp2 (stop + 1ULL - start));

	return net_up (m, stop + 1ULL - m, cb, cookie) &&
	       net_down (m, m - start, cb, cookie);
}
