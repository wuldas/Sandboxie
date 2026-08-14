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
// Capture Connection Filter
//---------------------------------------------------------------------------

#include "capture_filter.h"

#ifndef KERNEL_MODE
#include <wchar.h>
#endif


static BOOLEAN CaptureFilter_StringEquals(
    const WCHAR *left, const WCHAR *right, ULONG count)
{
    ULONG index = 0;
    while (index < count) {
        WCHAR leftChar = left[index];
        WCHAR rightChar = right[index];

        if (leftChar >= L'a' && leftChar <= L'z')
            leftChar -= L'a' - L'A';
        if (rightChar >= L'a' && rightChar <= L'z')
            rightChar -= L'a' - L'A';

        if (leftChar != rightChar)
            return FALSE;
        if (! leftChar)
            return TRUE;
        ++index;
    }

    return FALSE;
}


BOOLEAN CaptureFilter_Matches(
    const CAPTURE_FILTER_TARGET *target,
    const CAPTURE_FILTER_IDENTITY *identity)
{
    if (! target || ! identity)
        return FALSE;

    if (identity->session_id != target->session_id ||
            ! CaptureFilter_StringEquals(
                identity->box_name, target->box_name, BOXNAME_COUNT) ||
            ! CaptureFilter_StringEquals(
                identity->sid_string, target->sid_string, 96)) {
        return FALSE;
    }

    if (identity->loopback &&
            !(target->flags & CAPTURE_FILTER_FLAG_INCLUDE_LOOPBACK)) {
        return FALSE;
    }

    if (target->scope == CAPTURE_FILTER_SCOPE_PROCESS) {
        return identity->process_id == target->process_id &&
               identity->process_create_time == target->process_create_time;
    }

    if (target->scope != CAPTURE_FILTER_SCOPE_BOX)
        return FALSE;

    if (target->flags & CAPTURE_FILTER_FLAG_INCLUDE_FUTURE)
        return TRUE;

    for (ULONG index = 0; index < target->initial_process_count; ++index) {
        const CAPTURE_FILTER_PROCESS_KEY *key = &target->initial_processes[index];
        if (identity->process_id == key->process_id &&
                identity->process_create_time == key->process_create_time) {
            return TRUE;
        }
    }

    return FALSE;
}
