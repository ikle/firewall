/*
 * WPA Control Socket helpers
 *
 * Copyright (c) 2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef YONK_WPAC_H
#define YONK_WPAC_H  1

#include <sys/types.h>

enum wpac_level {
	WPAC_EXTRA	= 0,
	WPAC_DUMP	= 1,
	WPAC_DEBUG	= 2,
	WPAC_INFO	= 3,
	WPAC_WARNING	= 4,
	WPAC_ERROR	= 5,
};

typedef int wpac_cb (int level, char *data, size_t len, void *cookie);

struct wpac *wpac_alloc (const char *path, wpac_cb cb, void *cookie);
void wpac_free (struct wpac *o);

ssize_t wpac_send (struct wpac *o, const void *data, size_t len);
ssize_t wpac_recv (struct wpac *o, void *data, size_t len, int timeout);

int wpac_wait (struct wpac *o, const void *data, size_t len, int timeout);

int wpac_attach (struct wpac *o);
int wpac_ping   (struct wpac *o);
int wpac_detach (struct wpac *o);

int wpac_monitor (struct wpac *o);

#endif  /* YONK_WPAC_H */
