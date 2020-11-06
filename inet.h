/*
 * Internet address helpers
 *
 * Copyright (c) 2017-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef JANUS_INET_H
#define JANUS_INET_H  1

#include <netinet/in.h>

struct ipv4_masked {
	struct in_addr addr;
	unsigned mask;
};

struct ipv6_masked {
	struct in6_addr addr;
	unsigned mask;
};

struct ipv4_range {
	struct in_addr start;
	struct in_addr stop;
};

struct ipv6_range {
	struct in6_addr start;
	struct in6_addr stop;
};

struct ip_port_range {
	unsigned short start, stop;
};

int get_ipv4 (const char *from, struct in_addr *to);
int get_ipv6 (const char *from, struct in6_addr *to);
int get_ipv4_masked (const char *from, struct ipv4_masked *to);
int get_ipv6_masked (const char *from, struct ipv6_masked *to);
int get_ipv4_range (const char *from, struct ipv4_range *to);
int get_ipv6_range (const char *from, struct ipv6_range *to);

int get_service (const char *from, unsigned *to);
int get_port_range (const char *from, struct ip_port_range *to);

#endif  /* JANUS_INET_H */
