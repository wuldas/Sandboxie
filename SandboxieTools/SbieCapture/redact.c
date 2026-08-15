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
// Default HTTPS header redaction
//---------------------------------------------------------------------------

#include "redact.h"

#include <string.h>


static const char *const kSensitiveHeaders[] = {
    "Authorization",
    "Proxy-Authorization",
    "Cookie",
    "Set-Cookie",
    "X-Api-Key",
    "X-Api-Token",
    "Api-Key",
    "X-Auth-Token",
    "X-Access-Token",
};


static int Redact_AsciiLower(int value)
{
    if (value >= 'A' && value <= 'Z')
        return value - 'A' + 'a';
    return value;
}


static int Redact_NamesEqual(const char *left, const char *right)
{
    ULONG index;
    if (! left || ! right)
        return 0;
    for (index = 0; left[index] || right[index]; ++index) {
        if (Redact_AsciiLower((unsigned char)left[index]) !=
                Redact_AsciiLower((unsigned char)right[index])) {
            return 0;
        }
    }
    return 1;
}


BOOL Redact_IsSensitiveHeader(const char *name)
{
    ULONG index;
    if (! name)
        return FALSE;
    for (index = 0;
            index < sizeof(kSensitiveHeaders) / sizeof(kSensitiveHeaders[0]);
            ++index) {
        if (Redact_NamesEqual(name, kSensitiveHeaders[index]))
            return TRUE;
    }
    return FALSE;
}


void Redact_ApplyToHeaders(HTTP11_HEADER *headers, ULONG count)
{
    ULONG index;
    if (! headers)
        return;
    for (index = 0; index < count; ++index) {
        if (Redact_IsSensitiveHeader(headers[index].name)) {
            strcpy_s(
                headers[index].value,
                sizeof(headers[index].value),
                REDACT_REPLACEMENT);
        }
    }
}
