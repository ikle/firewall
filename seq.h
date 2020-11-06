/*
 * Sequence: list, queue or stack
 *
 * Copyright (c) 2014 Alexei A. Smekalkine
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef DATA_SEQ_H
#define DATA_SEQ_H  1

#include <assert.h>
#include <stddef.h>

#define SEQ_DECLARE(type)						\
struct type##_seq {							\
	struct type *head, **tail;					\
};									\
									\
static inline void type##_seq_init (struct type##_seq *s)		\
{									\
	assert (s != NULL);						\
									\
	s->head = NULL;							\
	s->tail = &s->head;						\
}									\
									\
static void inline type##_seq_fini (struct type##_seq *s,		\
				    void (*f) (struct type *))		\
{									\
	struct type *i, *next;						\
									\
	assert (s != NULL);						\
	assert (f != NULL);						\
									\
	for (i = s->head; i != NULL; i = next) {			\
		next = i->next;						\
		f (i);							\
	}								\
}									\
									\
static inline void type##_seq_move (struct type##_seq *from,		\
				    struct type##_seq *to,		\
				    void (*f) (struct type *))		\
{									\
	assert (from != NULL);						\
	assert (to != NULL);						\
									\
	type##_seq_fini (to, f);					\
	to->head = from->head;						\
	to->tail = from->tail == &from->head ? &to->head : from->tail;	\
}									\
									\
static inline void type##_seq_push (struct type##_seq *s,		\
				    struct type *i)			\
{									\
	assert (s != NULL);						\
	assert (i != NULL);						\
	assert (i->next == NULL);					\
									\
	i->next = s->head;						\
									\
	if (s->head == NULL)						\
		s->tail = &i->next;					\
									\
	s->head = i;							\
}									\
									\
static inline struct type *type##_seq_pop (struct type##_seq *s)	\
{									\
	struct type *i = s->head;					\
									\
	assert (s != NULL);						\
									\
	if (i == NULL)							\
		return NULL;						\
									\
	s->head = i->next;						\
	if (s->head == NULL)						\
		s->tail = &s->head;					\
									\
	i->next = NULL;							\
	return i;							\
}									\
									\
static inline void type##_seq_enqueue (struct type##_seq *s,		\
				       struct type *i)			\
{									\
	assert (s != NULL);						\
	assert (i != NULL);						\
									\
	*s->tail = i;							\
	s->tail = &i->next;						\
}									\
									\
static inline struct type *type##_seq_dequeue (struct type##_seq *s)	\
{									\
	assert (s != NULL);						\
									\
	return type##_seq_pop (s);					\
}									\
									\
static inline int type##_seq_is_empty (struct type##_seq *s)		\
{									\
	assert (s != NULL);						\
									\
	return s->head == NULL;						\
}

#endif  /* DATA_SEQ_H */
