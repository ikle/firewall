/*
 * Simple PCAP BPF Compiler
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap/pcap.h>

int main (int argc, char *argv[])
{
	pcap_t *pcap;
	int type;
	struct bpf_program p;
	struct bpf_insn *e;
	u_int limit = UINT_MAX, i;

	if (argc > 2 && strcmp (argv[1], "-l") == 0)
		limit = atoi (argv[2]), argv += 2, argc -= 2;

	if (argc != 3)
		goto usage;

	if ((type = pcap_datalink_name_to_val (argv[1])) == -1) {
		fprintf (stderr, "E: unupported type %s\n", argv[1]);
		return 1;
	}

	if ((pcap = pcap_open_dead (type, 65535)) == NULL) {
		fprintf (stderr, "E: cannot create PCAP context\n");
		return 1;
	}

	if (pcap_compile (pcap, &p, argv[2], 1, PCAP_NETMASK_UNKNOWN) != 0) {
		pcap_perror (pcap, "E");
		goto no_compile;
	}

	if (p.bf_len > limit) {
		fprintf (stderr, "E: generated BPF code too long\n");
		goto overflow;
	}

	printf ("%u", p.bf_len);

	for (e = p.bf_insns, i = 0; i < p.bf_len; ++e, ++i)
		printf (",%u %u %u %u", e->code, e->jt, e->jf, e->k);

	printf ("\n");
	pcap_freecode (&p);
	pcap_close (pcap);
	return 0;
usage:
	fprintf (stderr, "usage:\n\n"
			 "\tbpfc [-l limit] <link-type> <program>\n\n"
			 "link-type:\n\n"
			 "\tIPV4\tIPv4\n"
			 "\tIPV6\tIPv6\n"
			 "\tRAW\tIPv4 or IPv6\n"
			 "\tEN10MB\tEthernet\n"
			 "\t...\n");
	return 1;
overflow:
	pcap_freecode (&p);
no_compile:
	pcap_close (pcap);
	return 1;
}
