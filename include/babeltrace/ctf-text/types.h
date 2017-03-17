#ifndef _BABELTRACE_CTF_TEXT_TYPES_H
#define _BABELTRACE_CTF_TEXT_TYPES_H

/*
 * Common Trace Format (Text Output)
 *
 * Type header
 *
 * Copyright 2010 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <sys/mman.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <glib.h>
#include <stdarg.h>
#include <babeltrace/babeltrace-internal.h>
#include <babeltrace/types.h>
#include <babeltrace/format.h>
#include <babeltrace/format-internal.h>

/*
 * Inherit from both struct bt_stream_pos and struct bt_trace_descriptor.
 */
struct ctf_text_stream_pos {
	struct bt_stream_pos parent;
	struct bt_trace_descriptor trace_descriptor;
	FILE *fp;		/* File pointer. NULL if unset. */
	//
	FILE *table_fp; /* File pointer for table. NULL if unset. */
	void (*print_all)(struct ctf_text_stream_pos *pos, const char * text, ...);
	GHashTable *table_whitelist;
	bool is_this_event_whitelisted; /* this is the only struct pass down the call stack */
	bool (*is_event_whitelist)(GHashTable *hashtable, const char *event);
	char * task_event_name; /* task_name and event_name concat */
	int task_event_name_size; /* current size of the task_event_name field */
	//
	int depth;
	int dummy;		/* disable output */
	int print_names;	/* print field names */
	int field_nr;
	uint64_t last_real_timestamp;	/* to print delta */
	uint64_t last_cycles_timestamp;	/* to print delta */
	GString *string;	/* Current string */
};

//
static inline void print_all(struct ctf_text_stream_pos *pos, const char * text, ...) {
	va_list argptr;
	va_start(argptr, text);
	vfprintf(pos->fp, text, argptr);
	va_end(argptr);
	if (pos->table_fp && pos->is_this_event_whitelisted) {
		va_start(argptr, text);
		vfprintf(pos->table_fp, text, argptr);
		va_end(argptr);
	}
}

static inline bool is_event_whitelist(GHashTable *hashtable, const char *task_event_name) {
	return g_hash_table_lookup_extended(hashtable, task_event_name, NULL, NULL);
}
//

static inline
struct ctf_text_stream_pos *ctf_text_pos(struct bt_stream_pos *pos)
{
	return container_of(pos, struct ctf_text_stream_pos, parent);
}

/*
 * Write only is supported for now.
 */
BT_HIDDEN
int ctf_text_integer_write(struct bt_stream_pos *pos, struct bt_definition *definition);
BT_HIDDEN
int ctf_text_float_write(struct bt_stream_pos *pos, struct bt_definition *definition);
BT_HIDDEN
int ctf_text_string_write(struct bt_stream_pos *pos, struct bt_definition *definition);
BT_HIDDEN
int ctf_text_enum_write(struct bt_stream_pos *pos, struct bt_definition *definition);
BT_HIDDEN
int ctf_text_struct_write(struct bt_stream_pos *pos, struct bt_definition *definition);
BT_HIDDEN
int ctf_text_variant_write(struct bt_stream_pos *pos, struct bt_definition *definition);
BT_HIDDEN
int ctf_text_array_write(struct bt_stream_pos *pos, struct bt_definition *definition);
BT_HIDDEN
int ctf_text_sequence_write(struct bt_stream_pos *pos, struct bt_definition *definition);

static inline
void print_pos_tabs(struct ctf_text_stream_pos *pos)
{
	int i;

	for (i = 0; i < pos->depth; i++)
		fprintf(pos->fp, "\t");
}

/*
 * Check if the field must be printed.
 */
BT_HIDDEN
int print_field(struct bt_definition *definition);

#endif /* _BABELTRACE_CTF_TEXT_TYPES_H */
