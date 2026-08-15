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

#ifndef _MY_REDACT_H
#define _MY_REDACT_H

#include "http11.h"

#define REDACT_REPLACEMENT          "[REDACTED]"

#ifdef __cplusplus
extern "C" {
#endif

BOOL Redact_IsSensitiveHeader(const char *name);
void Redact_ApplyToHeaders(HTTP11_HEADER *headers, ULONG count);

#ifdef __cplusplus
}
#endif

#endif /* _MY_REDACT_H */
