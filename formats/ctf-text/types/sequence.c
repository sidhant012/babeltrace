/*
 * Common Trace Format
 *
 * Sequence format access functions.
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
#include <wchar.h>
#include <iconv.h>


void sequence_find_replace_newline(char * str, struct ctf_text_stream_pos *pos)
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

int ctf_text_sequence_write(struct bt_stream_pos *ppos, struct bt_definition *definition)
{
	struct ctf_text_stream_pos *pos = ctf_text_pos(ppos);
	struct definition_sequence *sequence_definition =
		container_of(definition, struct definition_sequence, p);
	struct declaration_sequence *sequence_declaration =
		sequence_definition->declaration;
	struct bt_declaration *elem = sequence_declaration->elem;
	int field_nr_saved;
	int ret = 0;
    
	if (!print_field(definition))
		return 0;

	if (!pos->dummy) {
		if (pos->field_nr++ != 0)
        {
            if (strcmp(rem_(g_quark_to_string(definition->name)), "idField") == 0)
            {
                char * precheck = sequence_definition->string->str;
                if (*precheck != 0 || *(precheck + 1) != 0)
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
	}

	if (elem->id == CTF_TYPE_INTEGER) {
		struct declaration_integer *integer_declaration =
			container_of(elem, struct declaration_integer, p);

		if (integer_declaration->encoding == CTF_STRING_UTF8
		      || integer_declaration->encoding == CTF_STRING_ASCII) {

			if (!(integer_declaration->len == CHAR_BIT
			    && integer_declaration->p.alignment == CHAR_BIT)) {
				pos->string = sequence_definition->string;
				g_string_assign(sequence_definition->string, "");
				ret = bt_sequence_rw(ppos, definition);
				pos->string = NULL;
			}
            
			// fprintf(pos->fp, "\"%s\"", sequence_definition->string->str);
            iconv_t cd = iconv_open("UTF-8", "UTF-16");
            if (cd == (iconv_t) -1) {
                fprintf(stderr, "iconv open failure");
                return -1;
            }
            char * ptr = sequence_definition->string->str;
            char * temp = ptr;
            int length = 0;
            while (*temp != 0 || *(temp + 1) != 0)
            {
                temp += 2;
                length += 2;
            }
            
            char * converted = calloc(length * 2 + 2, sizeof(char));
            char * converted_start = converted;
            size_t srcLength = length + 2;
            size_t dstLength = length * 2 + 2;
            ret = iconv(cd, &ptr, &srcLength, &converted, &dstLength);
            if (ret) {
                return ret;
            }
            sequence_find_replace_newline(converted_start, pos);
            // fprintf(pos->fp, "%s", converted_start);
            free(converted_start);
            // fwprintf(pos->fp, L"\"%s\"", converted_start);
            // fprintf(pos->fp, "\"%s\"", sequence_definition->string->str);
            ret = iconv_close(cd);
            if (ret) {
                return ret;
            }
			return ret;
		}
	}

	if (!pos->dummy) {
		fprintf(pos->fp, "[");
		pos->depth++;
	}
	field_nr_saved = pos->field_nr;
	pos->field_nr = 0;
	ret = bt_sequence_rw(ppos, definition);
	if (!pos->dummy) {
		pos->depth--;
		fprintf(pos->fp, " ]");
	}
	pos->field_nr = field_nr_saved;
	return ret;
}
