/*
 * Common Trace Format
 *
 * Strings read/write functions.
 *
 * Copyright 2010-2011 EfficiOS Inc. and Linux Foundation
 *
 * Author: Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <babeltrace/ctf-text/types.h>
#include <stdio.h>
#include <limits.h>		/* C99 limits */
#include <string.h>

void print_replace_newline(char * str, struct ctf_text_stream_pos *pos)
{
    char * saveptr = str;
    char * token;
    bool first = true;
    
    while (*saveptr != '\0' && *(saveptr + 1) != '\0')
    {
        if (saveptr[0] == '\r' && saveptr[1] == '\n')
        {
            saveptr[1] = '\t';
            saveptr += 2;
        }
        else
        {
            saveptr += 1;
        }
    }
    
    saveptr = str;
    
    while ((token = strtok_r(saveptr, "\n", &saveptr)) != NULL)
    {
        if (!first)
        {
            pos->print_all(pos, "%s", "\r\t");
            // fprintf(pos->fp, "%s", "\r\t");
        }
        first = false;
        pos->print_all(pos, "%s", token);
        // fprintf(pos->fp, "%s", token);
    }
}

int ctf_text_string_write(struct bt_stream_pos *ppos,
			  struct bt_definition *definition)
{
	struct definition_string *string_definition =
		container_of(definition, struct definition_string, p);
	struct ctf_text_stream_pos *pos = ctf_text_pos(ppos);

	assert(string_definition->value != NULL);

	if (!print_field(definition))
		return 0;

	if (pos->dummy)
		return 0;

	if (pos->field_nr++ != 0)
    {
        if (strcmp(rem_(g_quark_to_string(definition->name)), "eventNameField") == 0)
        {
            pos->print_all(pos, ".");
            // fprintf(pos->fp, ".");
        }
        else if (strcmp(rem_(g_quark_to_string(definition->name)), "idField") == 0)
        {
            if (strcmp(string_definition->value, "") != 0)
            {
                pos->print_all(pos, "@");
                // fprintf(pos->fp, "@");
            }
        }
        else
        {
            pos->print_all(pos, ",");
            // fprintf(pos->fp, ",");
        }
    }
	// fprintf(pos->fp, " ");
    
	// if (pos->print_names)
	// 	fprintf(pos->fp, "%s = ",
	// 		rem_(g_quark_to_string(definition->name)));
    // fprintf(pos->fp, "\"");
    if (strcmp(string_definition->value, "") != 0)
    {
        print_replace_newline(string_definition->value, pos);
    }
    
    // fprintf(pos->fp, "\"");
	// fprintf(pos->fp, "\"%s\"", string_definition->value);
	return 0;
}
