/*
 * Configuration Interface
 *
 * Copyright (c) 2018 Alexei A. Smekalkine <ikle@ikle.ru>
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

	if (root == NULL)
		root = getenv ("VYATTA_TEMP_CONFIG_DIR");

	o->root = strdup (root == NULL ? "/var/run/config/active" : root);

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

static int conf_push_one (struct conf *o, const char *name)
{
	char *name_e;
	struct conf c;

	if ((name_e = g_uri_escape_string (name, NULL, TRUE)) == NULL)
		return 0;

	c.root = g_build_filename (o->root, name_e, NULL);
	free (name_e);

	if (!conf_init (&c))
		goto error;

	conf_fini (o);
	free (o->root);
	*o = c;
	return 1;
error:
	free (c.root);
	return 0;
}

struct conf *conf_clonev (struct conf *o, va_list ap)
{
	struct conf *c;
	const char *name;

	if ((c = conf_alloc (o == NULL ? NULL : o->root)) == NULL)
		return NULL;

	while ((name = va_arg (ap, const char *)) != NULL)
		if (!conf_push_one (c, name))
			goto error;

	return c;
error:
	conf_free (c);
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
