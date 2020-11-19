/*
 * Configuration Interface
 *
 * Copyright (c) 2018-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <dirent.h>

#include <glib.h>

#include "conf.h"

static const char *path_root (void)
{
	const char *root = getenv ("VYATTA_TEMP_CONFIG_DIR");

	return root == NULL ? "/var/run/config/active" : root;
}

static char *path_push_one (const char *path, const char *name)
{
	char *e, *p;

	e = g_uri_escape_string (name, NULL, TRUE);
	p = g_build_filename (path, e, NULL);
	free (e);
	return p;
}

static char *path_pushv (const char *path, va_list ap)
{
	char *p = g_build_filename (path, NULL), *q;
	const char *name;

	while ((name = va_arg (ap, const char *)) != NULL) {
		q = path_push_one (p, name);
		free (p);
		p = q;
	}

	return p;
}

struct conf {
	char *root;
	DIR *dir;
	FILE *file;
};

static int conf_init (struct conf *o)
{
	char path[512];

	snprintf (path, sizeof (path), "%s/node.val", o->root);

	if ((o->file = fopen (path, "r")) != NULL) {
		o->dir = NULL;
		return 1;
	}

	if ((o->dir = opendir (o->root)) != NULL)
		return 1;

	return 0;
}

static void conf_fini (struct conf *o)
{
	if (o->dir != NULL)
		closedir (o->dir);

	if (o->file != NULL)
		fclose (o->file);

	o->dir = NULL;
	o->file = NULL;
}

struct conf *conf_alloc (const char *root)
{
	struct conf *o;

	if ((o = malloc (sizeof (*o))) == NULL)
		return NULL;

	o->root = strdup (root == NULL ? path_root () : root);

	if (o->root == NULL || !conf_init (o))
		goto error;

	return o;
error:
	free (o->root);
	free (o);
	return NULL;
}

void conf_free (struct conf *o)
{
	if (o == NULL)
		return;

	conf_fini (o);
	free (o->root);
	free (o);
}

struct conf *conf_clonev (struct conf *o, va_list ap)
{
	const char *root = o == NULL ? path_root () : o->root;
	char *path = path_pushv (root, ap);
	struct conf *c;

	if ((c = conf_alloc (path)) == NULL)
		goto error;

	free (path);
	return c;
error:
	free (path);
	return NULL;
}

struct conf *conf_clone (struct conf *o, ...)
{
	struct conf *c;
	va_list ap;

	va_start (ap, o);
	c = conf_clonev (o, ap);
	va_end (ap);
	return c;
}

int conf_exists (struct conf *o, ...)
{
	struct conf *c;
	va_list ap;
	int ret;

	va_start (ap, o);
	c = conf_clonev (o, ap);
	va_end (ap);

	ret = c != NULL;
	conf_free (c);
	return ret;
}

static void chomp (char *s)
{
	for (; *s != '\0'; ++s)
		if (s[0] == '\n' && s[1] == '\0') {
			s[0] = '\0';
			break;
		}
}

int conf_get (struct conf *o, char *buf, size_t size)
{
	struct dirent *de;
	char *name;

	if (o->dir != NULL) {
		do {
			if ((de = readdir (o->dir)) == NULL)
				return 0;
		}
		while (strcmp (de->d_name, ".")  == 0 ||
		       strcmp (de->d_name, "..") == 0);

		name = g_uri_unescape_string (de->d_name, NULL);
		snprintf (buf, size, "%s", name);
		free (name);
		return 1;
	}

	if (o->file == NULL || /* should never happen */
	    fgets (buf, size, o->file) == NULL)
		return 0;

	chomp (buf);
	return 1;
}

int conf_rewind (struct conf *o)
{
	conf_fini (o);
	return conf_init (o);
}

int conf_iteratev (struct conf *o, conf_cb *cb, void *cookie, va_list ap)
{
	struct conf *c;
	char entry[128];
	int ok = 1;

	if ((c = conf_clonev (o, ap)) == NULL)
		return ok;

	while (conf_get (c, entry, sizeof (entry))) {
		if (!(ok = cb (o, entry, cookie)))
			break;
	}

	conf_free (c);
	return ok;
}

int conf_iterate (struct conf *o, conf_cb *cb, void *cookie, ...)
{
	va_list ap;
	int ok;

	va_start (ap, cookie);
	ok = conf_iteratev (o, cb, cookie, ap);
	va_end (ap);

	return ok;
}

int conf_fetchv (struct conf *o, char *buf, size_t size, va_list ap)
{
	struct conf *c;
	int ok;

	if ((c = conf_clonev (o, ap)) == NULL)
		return 0;

	ok = (c->file != NULL && fgets (buf, size, c->file) != NULL);
	if (ok)
		chomp (buf);

	conf_free (c);
	return ok;
}

int conf_fetch (struct conf *o, char *buf, size_t size, ...)
{
	va_list ap;
	int ok;

	va_start (ap, size);
	ok = conf_fetchv (o, buf, size, ap);
	va_end (ap);

	return ok;
}
