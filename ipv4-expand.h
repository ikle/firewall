/*
 * Internet address range to network list expander
 *
 * Copyright (c) 2017 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef JANUS_IPV4_EXPAND_H
#define JANUS_IPV4_EXPAND_H

#include "inet.h"

typedef int (ipv4_net_cb) (struct ipv4_masked *o, void *cookie);

int ipv4_range_expand (struct ipv4_range *o, ipv4_net_cb *cb, void *cookie);

#endif  /* JANUS_IPV4_EXPAND_H */
