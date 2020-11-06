/*
 * Simple callout task scheduler
 *
 * Copyright (c) 2015-2017 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef JANUS_CALLOUT_H
#define JANUS_CALLOUT_H  1

#include <time.h>

struct callout {
	struct callout *next;
	time_t time;
	void (*fn) (void *cookie);
	void *cookie;
};

/* initialize callout object */
void callout_init (struct callout *o, void (*fn) (void *cookie), void *cookie);

/* schedule this callout to run in the specified timeout */
void callout_schedule (struct callout *o, time_t timeout);

/* initalize callout system */
void callout_sys_init (void);

/* process ready callouts and return */
void callout_process (void);

#endif  /* JANUS_CALLOUT_H */
