/*
 * WPA Control Socket helpers
 *
 * Copyright (c) 2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <poll.h>
#include <unistd.h>

#include "wpac.h"

struct wpac {
	int s;
	struct sockaddr_un cli, srv;

	int track;
	wpac_cb *cb;
	void *cookie;

	char buf[256];
};

struct wpac *wpac_alloc (const char *path, wpac_cb cb, void *cookie)
{
	size_t len = strlen (path);
	struct wpac *o;

	if (len >= sizeof (o->srv.sun_path)) {
		errno = EINVAL;
		return NULL;
	}

	if ((o = malloc (sizeof (*o))) == NULL)
		return NULL;

	if ((o->s = socket (AF_UNIX, SOCK_DGRAM, 0)) == -1)
		goto no_socket;

	o->cli.sun_family = AF_UNIX;
	o->cli.sun_path[0] = '\0';
	snprintf (o->cli.sun_path + 1, sizeof (o->cli.sun_path) - 1,
		  "wpac-%lu", (long) getpid ());

	if (bind (o->s, (void *) &o->cli, sizeof (o->cli)) == -1)
		goto no_bind;

	o->srv.sun_family = AF_UNIX;
	strncpy (o->srv.sun_path, path, sizeof (o->srv.sun_path));

	if (connect (o->s, (void *) &o->srv, sizeof (o->srv)) == -1)
		goto no_connect;

	o->track  = 0;
	o->cb     = cb;
	o->cookie = cookie;
	return o;
no_connect:
no_bind:
	close (o->s);
no_socket:
	free (o);
	return NULL;
}

void wpac_free (struct wpac *o)
{
	if (o == NULL)
		return;

	if (o->track)
		wpac_detach (o);

	close (o->s);
	free (o);
}

ssize_t wpac_send (struct wpac *o, const void *data, size_t len)
{
	return send (o->s, data, len, 0);
}

ssize_t wpac_recv (struct wpac *o, void *data, size_t len, int timeout)
{
	struct pollfd fds[1] = {{o->s, POLLIN, 0}};
	int n;

	while ((n = poll (fds, 1, timeout)) > 0)
		if ((fds[0].revents & POLLIN) != 0)
			return recv (o->s, data, len, 0);

	return n;
}

static int wpac_emit (struct wpac *o, size_t len)
{
	int level;

	if (o->cb == NULL || len < 3)
		return 1;

	if (o->buf[0] != '<' || !isdigit (o->buf[1]) || o->buf[2] != '>')
		return 1;

	level = o->buf[1] - '0';

	return o->cb (level, o->buf + 3, len - 3, o->cookie);
}

int wpac_wait (struct wpac *o, const void *data, size_t len, int timeout)
{
	ssize_t n;

	if (len > sizeof (o->buf)) {
		errno = EINVAL;
		return 0;
	}

	while ((n = wpac_recv (o, o->buf, sizeof (o->buf), timeout)) > 0) {
		if (o->buf[0] != '<')
			return n >= len && memcmp (o->buf, data, len) == 0;

		if (!wpac_emit (o, n))
			return 0;
	}

	return 0;
}

int wpac_attach (struct wpac *o)
{
	if (wpac_send (o, "ATTACH", 6) != 6 || !wpac_wait (o, "OK\n", 3, 500))
		return 0;

	o->track = 1;
	return 1;
}

int wpac_ping (struct wpac *o)
{
	if (wpac_send (o, "PING", 4) != 4)
		return 0;

	return wpac_wait (o, "PONG", 4, 500);
}

int wpac_detach (struct wpac *o)
{
	if (wpac_send (o, "DETACH", 6) != 6 || !wpac_wait (o, "OK\n", 3, 500))
		return 0;

	o->track = 0;
	return 1;
}

int wpac_monitor (struct wpac *o)
{
	ssize_t n;

	if (!o->track && !wpac_attach (o))
		return 0;

	do {
		while ((n = wpac_recv (o, o->buf, sizeof (o->buf), 3000)) > 0)
			if (!wpac_emit (o, n))
				break;

	}
	while (n == 0 && wpac_ping (o));

	return 1;
}
