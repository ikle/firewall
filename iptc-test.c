/*
 * IP Tables Test
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>	// raw test
#include <string.h>

#include <unistd.h>	// raw test

#include <libiptc/libiptc.h>

static struct ipt_get_entries *ipt_get_entries (const char *table)
{
	int s;
	struct ipt_getinfo info;
	socklen_t len;
	struct ipt_get_entries *entries;

	if ((s = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror ("socket");
		return NULL;
	}

	len = sizeof (info);
	strcpy (info.name, table);

	if (getsockopt (s, IPPROTO_IP, IPT_SO_GET_INFO, &info, &len) < 0) {
		perror ("get ipt info");
		goto no_info;
	}

	printf ("valid hooks = %08x, entries count = %u, size = %u\n\n",
		 info.valid_hooks, info.num_entries, info.size);

	len = sizeof (*entries) + info.size;

	if ((entries = malloc (len)) == NULL) {
		perror ("alloc entries");
		goto no_alloc;
	}

	strcpy (entries->name, table);
	entries->size = info.size;

	if (getsockopt (s, IPPROTO_IP, IPT_SO_GET_ENTRIES, entries, &len) < 0) {
		perror ("get ipt entries");
		goto no_entries;
	}

	close (s);
	return entries;
no_entries:
	free (entries);
no_alloc:
no_info:
	close (s);
	return NULL;
}

static int ipt_replace (struct ipt_replace *o, size_t size)
{
	int s;

	if ((s = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror ("socket");
		return 0;
	}

	if (setsockopt (s, IPPROTO_IP, IPT_SO_SET_REPLACE, o, size) < 0) {
		perror ("ipt replace");
		goto no_replace;
	}

	close (s);
	return 1;
no_replace:
	close (s);
	return 0;
}

#if 0
static int
find_entry_cb (struct ipt_entry *e, const char *name, struct ipt_entry **res)
{
	struct xt_entry_target *t = ipt_get_target (e);
	struct xt_error_target *et = (void *) t;

	if (strcmp (t->u.user.name, XT_ERROR_TARGET) == 0 &&
	    strcmp (et->errorname, name) == 0) {
		*res = e;
		return 1;
	}

	return 0;
}

struct ipt_entry *
ipt_find_entry (struct ipt_get_entries *entries, const char *name)
{
	struct ipt_entry *res = NULL;

	IPT_ENTRY_ITERATE (entries->entrytable, entries->size,
			   find_entry_cb, name, &res);

	return res;
}
#endif

static int
find_name_cb (struct ipt_entry *e, void *p, const char **res)
{
	struct xt_entry_target *t = ipt_get_target (e);
	struct xt_error_target *et = (void *) t;

	if (strcmp (t->u.user.name, XT_ERROR_TARGET) == 0 &&
	    (char *) e + e->next_offset == p) {
		*res = et->errorname;
		return 1;
	}

	return 0;
}

static const char *ipt_find_name (struct ipt_get_entries *entries, int offset)
{
	const char *res = NULL;
	void *p = (char *) entries->entrytable + offset;

	IPT_ENTRY_ITERATE (entries->entrytable, entries->size,
			   find_name_cb, p, &res);

	return res;
}

static void dump_from (struct ipt_entry *e)
{
	const char *name;

	switch (e->comefrom) {
	case (1 << NF_IP_PRE_ROUTING):	name = "PREROUTING";	break;
	case (1 << NF_IP_LOCAL_IN):	name = "INPUT";		break;
	case (1 << NF_IP_FORWARD):	name = "FORWARD";	break;
	case (1 << NF_IP_LOCAL_OUT):	name = "OUTPUT";	break;
	case (1 << NF_IP_POST_ROUTING):	name = "POSTROUTING";	break;

	default:
		if (e->comefrom != 0)
			printf ("from\t= %u\n", e->comefrom);

		return;
	}

	printf ("from\t= %s\n", name);
}

static void dump_counts (struct ipt_entry *e)
{
	if (e->counters.pcnt != 0)
		printf ("packets\t= %llu\n", e->counters.pcnt);

	if (e->counters.bcnt != 0)
		printf ("bytes\t= %llu\n", e->counters.bcnt);
}

static void dump_ip (struct ipt_entry *e)
{
	if (e->ip.src.s_addr != 0)
		printf ("src\t= %08x/%08x\n",
			ntohl (e->ip.src.s_addr), ntohl (e->ip.smsk.s_addr));

	if (e->ip.dst.s_addr != 0)
		printf ("dst\t= %08x/%08x\n",
			ntohl (e->ip.dst.s_addr), ntohl (e->ip.dmsk.s_addr));

	if (e->ip.iniface[0] != '\0')
		printf ("in\t= %s/%s\n",
			e->ip.iniface, e->ip.iniface_mask);

	if (e->ip.outiface[0] != '\0')
		printf ("out\t= %s/%s\n",
			e->ip.outiface, e->ip.outiface_mask);

	if (e->ip.proto != 0)
		printf ("proto\t= %u\n", e->ip.proto);

	if (e->ip.flags != 0)
		printf ("flags\t= %02x\n", e->ip.flags);

	if (e->ip.invflags != 0)
		printf ("inverse\t= %02x\n", e->ip.invflags);

	if (e->nfcache != 0)
		printf ("cache\t= %u\n", e->nfcache);
}

static int dump_match (const struct xt_entry_match *o)
{
	printf ("match\t= %s\n", o->u.user.name);

	return 0;
}

static void dump_target (struct ipt_entry *e, struct ipt_get_entries *entries)
{
	struct xt_entry_target *t = ipt_get_target (e);
	struct xt_standard_target *st;
	struct xt_error_target *et;
	const char *name, *type;

	if (strcmp (t->u.user.name, XT_STANDARD_TARGET) == 0) {
		st = (void *) t;

		switch (st->verdict) {
		case (-NF_DROP   - 1):	name = IPTC_LABEL_DROP;		break;
		case (-NF_ACCEPT - 1):	name = IPTC_LABEL_ACCEPT;	break;
		case (-NF_QUEUE  - 1):	name = IPTC_LABEL_QUEUE;	break;
		case XT_RETURN:		name = IPTC_LABEL_RETURN;	break;
		default:
			name = ipt_find_name (entries, st->verdict);

			if (name == NULL) {
				printf ("verdict\t= %d\n", st->verdict);
				return;
			}
		}

		type = "verdict";
	}
	else if (strcmp (t->u.user.name, XT_ERROR_TARGET) == 0) {
		et = (void *) t;

		name = et->errorname;
		type = "error";
	}
	else {
		name = t->u.user.name;
		type = "target";
	}

	printf ("%s\t= %s\n", type, name);
}

static int dump_entry (struct ipt_entry *e, struct ipt_get_entries *entries)
{
	printf ("offset\t= %td\n", (char *) e - (char *) entries->entrytable);
	dump_from (e);
	dump_counts (e);
	dump_ip (e);

	IPT_MATCH_ITERATE (e, dump_match);

	dump_target (e, entries);
	printf ("\n");
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

static struct xt_counters null_counters[3];

static struct null_filter null_filter = {
	.head	= {
		.name		= "filter",
		.valid_hooks	= 0x0e,
		.num_entries	= 3,
		.size		= 3 * HE_SIZE + CE_SIZE,
		.hook_entry	= {
			[NF_IP_PRE_ROUTING]	= -1,
			[NF_IP_LOCAL_IN]	= 0 * HE_SIZE,
			[NF_IP_FORWARD]		= 1 * HE_SIZE,
			[NF_IP_LOCAL_OUT]	= 2 * HE_SIZE,
			[NF_IP_POST_ROUTING]	= -1,
		},
		.underflow	= {
			[NF_IP_PRE_ROUTING]	= -1,
			[NF_IP_LOCAL_IN]	= 0 * HE_SIZE,
			[NF_IP_FORWARD]		= 1 * HE_SIZE,
			[NF_IP_LOCAL_OUT]	= 2 * HE_SIZE,
			[NF_IP_POST_ROUTING]	= -1,
		},
		.num_counters	= 3,
		.counters	= null_counters,
	},
	.hooks	= {
		{
			.e.target_offset	= HE_OFFSET,
			.e.next_offset		= HE_SIZE,
//			.e.comefrom		= NF_IP_LOCAL_IN,
			.t.target.u.target_size	= HT_SIZE,
			.t.verdict		= -NF_ACCEPT - 1,
		},
		{
			.e.target_offset	= HE_OFFSET,
			.e.next_offset		= HE_SIZE,
//			.e.comefrom		= NF_IP_FORWARD,
			.t.target.u.target_size	= HT_SIZE,
			.t.verdict		= -NF_ACCEPT - 1,
		},
		{
			.e.target_offset	= HE_OFFSET,
			.e.next_offset		= HE_SIZE,
//			.e.comefrom		= NF_IP_LOCAL_OUT,
			.t.target.u.target_size	= HT_SIZE,
			.t.verdict		= -NF_ACCEPT - 1,
		},
	},
	.end	= {
		.e.target_offset		= CE_OFFSET,
		.e.next_offset			= CE_SIZE,
		.t.target.u.target_size		= CT_SIZE,
		.t.target.u.user.name		= XT_ERROR_TARGET,
		.t.errorname			= "ERROR",
	},
};

static int raw_test (const char *table)
{
	struct ipt_get_entries *entries;

	if ((entries = ipt_get_entries (table)) == NULL)
		return 0;

	IPT_ENTRY_ITERATE (entries->entrytable, entries->size,
			   dump_entry, entries);
	free (entries);

	return ipt_replace (&null_filter.head, sizeof (null_filter));
	return 1;
}

static int test (struct xtc_handle *o, const char *chain)
{
	const char *policy = "policy-0";
	struct rule {
		struct ipt_entry e;
		struct xt_standard_target t;
	} r;

	if (!iptc_is_chain (policy, o) && !iptc_create_chain (policy, o))
		return 0;

	if (!iptc_is_chain (chain, o) && !iptc_create_chain (chain, o))
		return 0;

	if (!iptc_flush_entries (chain, o))
		return 0;

	memset (&r, 0, sizeof (r));

	strncpy (r.e.ip.iniface, "eth2", sizeof (r.e.ip.iniface));
	memset (r.e.ip.iniface_mask, '.', sizeof (r.e.ip.iniface_mask));

	r.e.ip.flags = IPT_F_GOTO;

	r.e.target_offset = offsetof (struct rule, t);
	r.e.next_offset = sizeof (r);

//	r.t.target.u.user.target_size = XT_ALIGN (sizeof (r.t));
	r.t.target.u.user.target_size = sizeof (r.t);
	strcpy (r.t.target.u.user.name, policy);

	if (!iptc_append_entry (chain, &r.e, o))
		return 0;

	return iptc_commit (o);
}

int main (int argc, char *argv[])
{
	struct xtc_handle *o;
	const char *chain;
	const struct ipt_entry *e;
	const char *target;

	raw_test ("filter");

	return 0;

	if ((o = iptc_init ("filter")) == NULL) {
		fprintf (stderr, "E: %s\n", iptc_strerror (errno));
		return 1;
	}

	for (
		chain = iptc_first_chain (o);
		chain != NULL;
		chain = iptc_next_chain (o)
	) {
		printf ("-N %s\n", chain);

		for (
			e = iptc_first_rule (chain, o);
			e != NULL;
			e = iptc_next_rule (e, o)
		) {
			printf ("-A %s", chain);

			if (e->ip.iniface[0] != '\0')
				printf (" -i %.16s", e->ip.iniface);

			if (e->ip.outiface[0] != '\0')
				printf (" -o %.16s", e->ip.outiface);

			if ((target = iptc_get_target (e, o)) != NULL)
				printf (" -%c %s",
					e->ip.flags & IPT_F_GOTO ? 'g' : 'j',
					target);

			printf ("\n");
		}
	}

	if (!test (o, "test"))
		fprintf (stderr, "E: %s\n", iptc_strerror (errno));

//	dump_entries (o);
	iptc_free (o);
	return 0;
}
