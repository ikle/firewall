/*
 * WPA Control Socket test
 *
 * Copyright (c) 2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>

#include "wpac.h"

static int cb (int level, char *data, size_t len, void *cookie)
{
	FILE *to = cookie;

	fprintf (to, "%d: %s\n", level, data);

	return 1;
}

int main (int argc, char *argv[])
{
	const char *path = argv[1];
	struct wpac *o;

	if (argc != 2) {
		fprintf (stderr, "usage:\n\twpac-test wpa-control-socket\n");
		return 1;
	}

	if ((o = wpac_alloc (path, cb, stdout)) == NULL) {
		fprintf (stderr, "E: Cannot allocate WPA Control context\n");
		return 1;
	}

	wpac_monitor (o);

	wpac_free (o);
	return 0;
}
