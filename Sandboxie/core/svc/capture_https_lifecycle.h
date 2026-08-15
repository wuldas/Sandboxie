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
// HTTPS capture session lifecycle helpers
//---------------------------------------------------------------------------

#ifndef _MY_CAPTURE_HTTPS_LIFECYCLE_H
#define _MY_CAPTURE_HTTPS_LIFECYCLE_H

#if defined(KERNEL_MODE) || defined(_NTDDK_)
#include <ntddk.h>
#else
#include <windows.h>
#endif


#define CAPTURE_HTTPS_LIFECYCLE_WAITING     1
#define CAPTURE_HTTPS_LIFECYCLE_SPAWN       2
#define CAPTURE_HTTPS_LIFECYCLE_FAILED      3
#define CAPTURE_HTTPS_LIFECYCLE_STOPPED     4

#define CAPTURE_HTTPS_BROKER_ACTION_KEEP_REDIRECT   1
#define CAPTURE_HTTPS_BROKER_ACTION_TEARDOWN        2


#ifdef __cplusplus
extern "C" {
#endif

ULONG CaptureHttpsLifecycle_OnExport(
    BOOLEAN httpsMode,
    BOOLEAN hasPcapExport,
    BOOLEAN hasHarExport);

ULONG CaptureHttpsLifecycle_OnBrokerDeath(
    BOOLEAN httpsMode,
    BOOLEAN wasRunning);

#ifdef __cplusplus
}
#endif


#endif /* _MY_CAPTURE_HTTPS_LIFECYCLE_H */
