/*
 * IP Tables Raw Dumper
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

static struct ipt_getinfo *ipt_getinfo (const char *table)
{
	int s;
	struct ipt_getinfo *o;
	socklen_t len = sizeof (*o);

	if ((s = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
		return NULL;

	if ((o = malloc (len)) == NULL)
		goto no_alloc;

	strncpy (o->name, table, sizeof (o->name));

	if (getsockopt (s, IPPROTO_IP, IPT_SO_GET_INFO, o, &len) < 0)
		goto no_info;

	close (s);
	return o;
no_info:
	free (o);
no_alloc:
	close (s);
	return NULL;
}

static struct ipt_get_entries *ipt_get_entries (const char *table, size_t size)
{
	int s;
	socklen_t len;
	struct ipt_get_entries *entries;

	if ((s = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
		return NULL;

	len = sizeof (*entries) + size;

	if ((entries = malloc (len)) == NULL)
		goto no_alloc;

	strcpy (entries->name, table);
	entries->size = size;

	if (getsockopt (s, IPPROTO_IP, IPT_SO_GET_ENTRIES, entries, &len) < 0)
		goto no_entries;

	close (s);
	return entries;
no_entries:
	free (entries);
no_alloc:
	close (s);
	return NULL;
}

static void dump_info (const struct ipt_getinfo *o)
{
	printf ("valid hooks = %08x, entries count = %u, size = %u\n\n",
	        o->valid_hooks, o->num_entries, o->size);
}

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

static int dump_image (const struct ipt_get_entries *entries, const char *image)
{
	FILE *f;
	int ok;

	if ((f = fopen (image, "wb")) == NULL)
		return 0;

	ok = fwrite (entries->entrytable, entries->size, 1, f) == 1;

	return fclose (f) == 0 && ok;
}

int main (int argc, char *argv[])
{
	char *table = argc > 1 ? argv[1] : "filter";
	struct ipt_getinfo *info;
	struct ipt_get_entries *entries;
	int ok;

	if ((info = ipt_getinfo (table)) == NULL) {
		perror ("iptc-dump");
		return 1;
	}

	dump_info (info);

	if ((entries = ipt_get_entries (table, info->size)) == NULL) {
		perror ("iptc-dump");
		free (info);
		return 1;
	}

	if (argc < 3)
		ok = IPT_ENTRY_ITERATE (entries->entrytable, entries->size,
					dump_entry, entries) == 0;
	else
		ok = dump_image (entries, argv[2]);

	free (entries);
	free (info);
	return ok ? 0 : 1;
}
