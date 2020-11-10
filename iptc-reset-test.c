/*
 * IP Tables Raw Reset Test
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#include <libiptc/libiptc.h>

static int ipt_replace (const char *table, struct ipt_replace *o, size_t size)
{
	int s;
	struct ipt_getinfo info;
	socklen_t len = sizeof (info);
	struct xt_counters *c;

	if ((s = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror ("socket");
		return 0;
	}

	strcpy (info.name, table);

	if (getsockopt (s, IPPROTO_IP, IPT_SO_GET_INFO, &info, &len) < 0)
		goto no_info;

	if ((c = malloc (sizeof (c[0]) * info.num_entries)) == NULL)
		goto no_counters;

	strcpy (o->name, table);

	o->num_counters = info.num_entries;
	o->counters	= c;

	if (setsockopt (s, IPPROTO_IP, IPT_SO_SET_REPLACE, o, size) < 0) {
		perror ("ipt replace");
		goto no_replace;
	}

	free (c);
	close (s);
	return 1;
no_replace:
	free (c);
no_counters:
no_info:
	close (s);
	return 0;
}

struct hook_entry {
	struct ipt_entry e;
	struct xt_standard_target t;
};

#define HE_OFFSET	(sizeof (struct ipt_entry))
#define HE_SIZE		(sizeof (struct hook_entry))
#define HT_SIZE		(XT_ALIGN (sizeof (struct xt_standard_target)))

struct chain_entry {
	struct ipt_entry e;
	struct xt_error_target t;
};

#define CE_OFFSET	(sizeof (struct ipt_entry))
#define CE_SIZE		(sizeof (struct chain_entry))
#define CT_SIZE		(XT_ALIGN (sizeof (struct xt_error_target)))

struct null_filter {
	struct ipt_replace head;
	struct hook_entry hooks[3];
	struct chain_entry end;
};

static struct null_filter null_filter = {
	.head	= {
		.valid_hooks	= 0x0e,
		.num_entries	= 4,
		.size		= 3 * HE_SIZE + CE_SIZE,
		.hook_entry	= {
			[NF_IP_LOCAL_IN]	= 0 * HE_SIZE,
			[NF_IP_FORWARD]		= 1 * HE_SIZE,
			[NF_IP_LOCAL_OUT]	= 2 * HE_SIZE,
		},
		.underflow	= {
			[NF_IP_LOCAL_IN]	= 0 * HE_SIZE,
			[NF_IP_FORWARD]		= 1 * HE_SIZE,
			[NF_IP_LOCAL_OUT]	= 2 * HE_SIZE,
		},
	},
	.hooks	= {
		{
			.e.target_offset	= HE_OFFSET,
			.e.next_offset		= HE_SIZE,
			.e.comefrom		= 1 << NF_IP_LOCAL_IN,
			.t.target.u.target_size	= HT_SIZE,
			.t.verdict		= -NF_ACCEPT - 1,
		},
		{
			.e.target_offset	= HE_OFFSET,
			.e.next_offset		= HE_SIZE,
			.e.comefrom		= 1 << NF_IP_FORWARD,
			.t.target.u.target_size	= HT_SIZE,
			.t.verdict		= -NF_ACCEPT - 1,
		},
		{
			.e.target_offset	= HE_OFFSET,
			.e.next_offset		= HE_SIZE,
			.e.comefrom		= 1 << NF_IP_LOCAL_OUT,
			.t.target.u.target_size	= HT_SIZE,
			.t.verdict		= -NF_ACCEPT - 1,
		},
	},
	.end	= {
		.e.target_offset		= CE_OFFSET,
		.e.next_offset			= CE_SIZE,
		.t.target.u.user.target_size	= CT_SIZE,
		.t.target.u.user.name		= XT_ERROR_TARGET,
		.t.errorname			= "ERROR",
	},
};

int main (int argc, char *argv[])
{
	return ipt_replace ("filter",
			    &null_filter.head, sizeof (null_filter)) ? 0 : 1;

}
