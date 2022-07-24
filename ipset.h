/*
 * IpSet Helpers
 *
 * Copyright (c) 2017-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef JANUS_IPSET_H
#define JANUS_IPSET_H  1

#include <netinet/in.h>

#include <libipset/types.h>
#include <libipset/data.h>
#include <libipset/session.h>
#include <libipset/parse.h>

static inline int
ipset_set_target (struct ipset_session *s, const char *name, const char *type)
{
	struct ipset_data *d = ipset_session_data (s);

	return	ipset_data_set (d, IPSET_SETNAME, name) == 0 &&
		ipset_parse_typename (s, IPSET_OPT_TYPENAME, type) == 0;
}

static inline int
ipset_set_u8 (struct ipset_session *s, enum ipset_opt type, uint8_t value)
{
	return ipset_session_data_set (s, type, &value) == 0;
}

static inline int
ipset_set_u32 (struct ipset_session *s, enum ipset_opt type, uint32_t value)
{
	return ipset_session_data_set (s, type, &value) == 0;
}

static inline int ipset_set_mac (struct ipset_session *s, const char *mac)
{
	return ipset_session_data_set (s, IPSET_OPT_ETHER, mac) == 0;
}

static inline int ipset_set_ip (struct ipset_session *s, struct in_addr *addr)
{
	return ipset_session_data_set (s, IPSET_OPT_IP, addr) == 0;
}

static inline int
ipset_create (struct ipset_session *s, const char *name, const char *type)
{
	return	ipset_set_target (s, name, type) &&
		ipset_set_u32 (s, IPSET_OPT_HASHSIZE, 1) &&
		ipset_set_u32 (s, IPSET_OPT_MAXELEM, UINT32_MAX) &&
		ipset_cmd (s, IPSET_CMD_CREATE, 0) == 0;
}

static inline int
ipset_destroy (struct ipset_session *s, const char *name, const char *type)
{
	return	ipset_set_target (s, name, type) &&
		ipset_cmd (s, IPSET_CMD_DESTROY, 0) == 0;
}

static inline int
ipset_add_mac (struct ipset_session *s, const char *name, const char *type,
	       const char *mac)
{
	return	ipset_set_target (s, name, type) &&
		ipset_set_mac (s, mac) &&
		ipset_cmd (s, IPSET_CMD_ADD, 0) == 0;
}

static inline int
ipset_add_node (struct ipset_session *s, const char *name, const char *type,
		struct in_addr *addr)
{
	return	ipset_set_target (s, name, type) &&
		ipset_set_ip (s, addr) &&
		ipset_cmd (s, IPSET_CMD_ADD, 0) == 0;
}

static inline int
ipset_add_net (struct ipset_session *s, const char *name, const char *type,
	       struct in_addr *addr, unsigned mask)
{
	return	ipset_set_target (s, name, type) &&
		ipset_set_ip (s, addr) &&
		ipset_set_u8 (s, IPSET_OPT_CIDR, mask) &&
		ipset_cmd (s, IPSET_CMD_ADD, 0) == 0;
}

static inline int
ipset_swap (struct ipset_session *s, const char *from, const char *to,
	    const char *type)
{
	return	ipset_set_target (s, from, type) &&
		ipset_session_data_set (s, IPSET_OPT_SETNAME2, to) == 0 &&
		ipset_cmd (s, IPSET_CMD_SWAP, 0) == 0;
}

#endif  /* JANUS_IPSET_H */
