/*
 * Copyright 2026 David Xanatos, xanasoft.com
 *
 * This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//---------------------------------------------------------------------------
// HTTP/1.1 request/response framing
//---------------------------------------------------------------------------

#include "http11.h"

#include <string.h>


static int Http11_AsciiLower(int value)
{
    if (value >= 'A' && value <= 'Z')
        return value - 'A' + 'a';
    return value;
}


static int Http11_NamesEqual(const char *left, const char *right)
{
    ULONG index;
    if (! left || ! right)
        return 0;
    for (index = 0; left[index] || right[index]; ++index) {
        if (Http11_AsciiLower((unsigned char)left[index]) !=
                Http11_AsciiLower((unsigned char)right[index])) {
            return 0;
        }
    }
    return 1;
}


static int Http11_CopyToken(
    char *dest,
    ULONG destSize,
    const UCHAR *source,
    ULONG sourceSize)
{
    if (! dest || destSize == 0 || sourceSize + 1 > destSize)
        return 0;
    memcpy(dest, source, sourceSize);
    dest[sourceSize] = 0;
    return 1;
}


static int Http11_FindLine(
    const UCHAR *data,
    ULONG size,
    ULONG start,
    ULONG *lineEnd,
    ULONG *next)
{
    ULONG index;

    if (! data || ! lineEnd || ! next || start > size)
        return HTTP11_ERROR;

    for (index = start; index < size; ++index) {
        if (index - start > HTTP11_MAX_LINE)
            return HTTP11_ERROR;
        if (data[index] == '\n')
            return HTTP11_ERROR;
        if (data[index] == '\r') {
            if (index + 1 >= size)
                return HTTP11_NEED_MORE;
            if (data[index + 1] != '\n')
                return HTTP11_ERROR;
            if (index - start > HTTP11_MAX_LINE)
                return HTTP11_ERROR;
            *lineEnd = index;
            *next = index + 2;
            return HTTP11_OK;
        }
    }

    if (size - start > HTTP11_MAX_LINE)
        return HTTP11_ERROR;
    return HTTP11_NEED_MORE;
}


static ULONG Http11_TrimOwsStart(const UCHAR *data, ULONG start, ULONG end)
{
    while (start < end && (data[start] == ' ' || data[start] == '\t'))
        ++start;
    return start;
}


static ULONG Http11_TrimOwsEnd(const UCHAR *data, ULONG start, ULONG end)
{
    while (end > start && (data[end - 1] == ' ' || data[end - 1] == '\t'))
        --end;
    return end;
}


static int Http11_ParseContentHints(
    const HTTP11_HEADER *headers,
    ULONG count,
    ULONG *contentLength,
    BOOL *chunked)
{
    ULONG index;
    *contentLength = 0;
    *chunked = FALSE;

    for (index = 0; index < count; ++index) {
        if (Http11_NamesEqual(headers[index].name, "Content-Length")) {
            const char *cursor = headers[index].value;
            ULONG value = 0;
            if (! cursor[0])
                return HTTP11_ERROR;
            while (*cursor) {
                if (*cursor < '0' || *cursor > '9')
                    return HTTP11_ERROR;
                if (value > (0xFFFFFFFFul / 10ul))
                    return HTTP11_ERROR;
                value = value * 10ul + (ULONG)(*cursor - '0');
                ++cursor;
            }
            *contentLength = value;
        }
        else if (Http11_NamesEqual(headers[index].name, "Transfer-Encoding") &&
                Http11_NamesEqual(headers[index].value, "chunked")) {
            *chunked = TRUE;
        }
    }
    return HTTP11_OK;
}


static int Http11_ParseHeaders(
    const UCHAR *data,
    ULONG size,
    ULONG *offset,
    HTTP11_HEADER *headers,
    ULONG *headerCount)
{
    *headerCount = 0;

    for (;;) {
        ULONG lineEnd = 0;
        ULONG next = 0;
        ULONG nameStart;
        ULONG nameEnd;
        ULONG valueStart;
        ULONG valueEnd;
        ULONG colon;
        int status = Http11_FindLine(data, size, *offset, &lineEnd, &next);
        if (status != HTTP11_OK)
            return status;

        if (lineEnd == *offset) {
            *offset = next;
            return HTTP11_OK;
        }

        if (data[*offset] == ' ' || data[*offset] == '\t')
            return HTTP11_ERROR;
        if (*headerCount >= HTTP11_MAX_HEADERS)
            return HTTP11_ERROR;

        colon = *offset;
        while (colon < lineEnd && data[colon] != ':')
            ++colon;
        if (colon == *offset || colon >= lineEnd)
            return HTTP11_ERROR;

        nameStart = *offset;
        nameEnd = Http11_TrimOwsEnd(data, nameStart, colon);
        valueStart = Http11_TrimOwsStart(data, colon + 1, lineEnd);
        valueEnd = Http11_TrimOwsEnd(data, valueStart, lineEnd);
        if (nameEnd == nameStart)
            return HTTP11_ERROR;
        if (! Http11_CopyToken(
                headers[*headerCount].name,
                HTTP11_MAX_NAME,
                data + nameStart,
                nameEnd - nameStart) ||
                ! Http11_CopyToken(
                    headers[*headerCount].value,
                    HTTP11_MAX_VALUE,
                    data + valueStart,
                    valueEnd - valueStart)) {
            return HTTP11_ERROR;
        }

        ++*headerCount;
        *offset = next;
    }
}


static int Http11_SplitThree(
    const UCHAR *line,
    ULONG lineSize,
    ULONG *firstEnd,
    ULONG *secondStart,
    ULONG *secondEnd,
    ULONG *thirdStart)
{
    ULONG index = 0;
    while (index < lineSize && line[index] != ' ')
        ++index;
    if (index == 0 || index >= lineSize)
        return 0;
    *firstEnd = index;
    ++index;
    *secondStart = index;
    while (index < lineSize && line[index] != ' ')
        ++index;
    if (index == *secondStart || index >= lineSize)
        return 0;
    *secondEnd = index;
    ++index;
    if (index >= lineSize)
        return 0;
    *thirdStart = index;
    return 1;
}


int Http11_ParseRequest(
    const UCHAR *data,
    ULONG size,
    HTTP11_REQUEST *out)
{
    ULONG offset = 0;
    ULONG lineEnd = 0;
    ULONG next = 0;
    ULONG firstEnd = 0;
    ULONG secondStart = 0;
    ULONG secondEnd = 0;
    ULONG thirdStart = 0;
    int status;

    if (! data || ! out)
        return HTTP11_ERROR;
    memset(out, 0, sizeof(*out));

    status = Http11_FindLine(data, size, 0, &lineEnd, &next);
    if (status != HTTP11_OK)
        return status;
    if (! Http11_SplitThree(
            data, lineEnd, &firstEnd, &secondStart, &secondEnd, &thirdStart)) {
        return HTTP11_ERROR;
    }
    if (! Http11_CopyToken(out->method, HTTP11_MAX_METHOD, data, firstEnd) ||
            ! Http11_CopyToken(
                out->target,
                HTTP11_MAX_TARGET,
                data + secondStart,
                secondEnd - secondStart) ||
            ! Http11_CopyToken(
                out->version,
                HTTP11_MAX_VERSION,
                data + thirdStart,
                lineEnd - thirdStart)) {
        return HTTP11_ERROR;
    }

    offset = next;
    status = Http11_ParseHeaders(
        data, size, &offset, out->headers, &out->header_count);
    if (status != HTTP11_OK)
        return status;

    out->header_bytes = offset;
    return Http11_ParseContentHints(
        out->headers, out->header_count, &out->content_length, &out->chunked);
}


int Http11_ParseResponse(
    const UCHAR *data,
    ULONG size,
    HTTP11_RESPONSE *out)
{
    ULONG offset = 0;
    ULONG lineEnd = 0;
    ULONG next = 0;
    ULONG firstEnd = 0;
    ULONG secondStart = 0;
    ULONG secondEnd = 0;
    ULONG thirdStart = 0;
    ULONG statusValue = 0;
    ULONG digit;
    int status;

    if (! data || ! out)
        return HTTP11_ERROR;
    memset(out, 0, sizeof(*out));

    status = Http11_FindLine(data, size, 0, &lineEnd, &next);
    if (status != HTTP11_OK)
        return status;
    if (! Http11_SplitThree(
            data, lineEnd, &firstEnd, &secondStart, &secondEnd, &thirdStart)) {
        return HTTP11_ERROR;
    }
    if (! Http11_CopyToken(
            out->version, HTTP11_MAX_VERSION, data, firstEnd)) {
        return HTTP11_ERROR;
    }
    if (secondEnd - secondStart != 3)
        return HTTP11_ERROR;
    for (digit = 0; digit < 3; ++digit) {
        UCHAR value = data[secondStart + digit];
        if (value < '0' || value > '9')
            return HTTP11_ERROR;
        statusValue = statusValue * 10 + (ULONG)(value - '0');
    }
    out->status = statusValue;
    if (! Http11_CopyToken(
            out->reason,
            HTTP11_MAX_REASON,
            data + thirdStart,
            lineEnd - thirdStart)) {
        return HTTP11_ERROR;
    }

    offset = next;
    status = Http11_ParseHeaders(
        data, size, &offset, out->headers, &out->header_count);
    if (status != HTTP11_OK)
        return status;

    out->header_bytes = offset;
    return Http11_ParseContentHints(
        out->headers, out->header_count, &out->content_length, &out->chunked);
}


const HTTP11_HEADER *Http11_FindHeader(
    const HTTP11_HEADER *headers,
    ULONG count,
    const char *name)
{
    ULONG index;
    if (! headers || ! name)
        return NULL;
    for (index = 0; index < count; ++index) {
        if (Http11_NamesEqual(headers[index].name, name))
            return &headers[index];
    }
    return NULL;
}
