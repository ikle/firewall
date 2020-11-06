/*
 * Simple callout task scheduler
 *
 * Copyright (c) 2015-2017 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>

#include "callout.h"
#include "seq.h"

#define nitems(a)  (sizeof (a) / sizeof ((a)[0]))

SEQ_DECLARE (callout)

static time_t now;
static struct callout_seq wheel[2][256];
static const size_t size = nitems (wheel[0]);

static void wheel_enqueue (struct callout *o, time_t timeout)
{
	size_t level = 0, i = now + timeout;

	if (timeout >= size)
		++level, i /= size;

	callout_seq_enqueue (&wheel[level][i % size], o);
}

static void wheel_reschedule (struct callout_seq *slot)
{
	struct callout *o;

	while ((o = callout_seq_dequeue (slot)) != NULL)
		wheel_enqueue (o, o->time > now ? o->time - now : 1);
}

static struct callout *wheel_step (void)
{
	size_t i = now;
	struct callout_seq *slot = &wheel[0][i % size];
	struct callout *ready;

	/* extract waiters */
	ready = slot->head;
	callout_seq_init (slot);

	if ((now % size) == 0) {
		i /= size;
		wheel_reschedule (&wheel[1][i % size]);
	}

	return ready;
}

/* initialize callout object */
void callout_init (struct callout *o, void (*fn) (void *cookie), void *cookie)
{
	o->next = NULL;
	o->time = 0;
	o->fn = fn;
	o->cookie = cookie;
}

/* schedule this callout to run in specified timeout */
void callout_schedule (struct callout *o, time_t timeout)
{
	time_t to = time (NULL) + timeout;

	if (to < o->time)
		o->time = to;	/* reschedule it earlier */

	if (o->time != 0)
		return;		/* already scheduled */

	o->time = to;
	wheel_enqueue (o, timeout);
}

/* initalize callout system */
void callout_sys_init (void)
{
	size_t level, i;

	now = time (NULL);

	for (level = 0; level < nitems (wheel); ++level)
		for (i = 0; i < size; ++i)
			callout_seq_init (wheel[level] + i);
}

/* process ready callouts and return */
void callout_process (void)
{
	time_t current = time (NULL);
	struct callout *ready, *next;

	for (; now < current; ++now)
		while ((ready = wheel_step ()) != NULL)
			for (; ready != NULL; ready = next) {
				next = ready->next;

				ready->next = NULL;
				ready->time = 0;
				ready->fn (ready->cookie);
			}
}
