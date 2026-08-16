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
// Session capture CA -- public API, no OpenSSL types
//---------------------------------------------------------------------------

#ifndef _MY_CAPTURE_CA_H
#define _MY_CAPTURE_CA_H

#include <windows.h>

#define CAPTURE_CA_OK               0
#define CAPTURE_CA_ERROR            (-1)

#define CAPTURE_CA_STORE_CURRENT_USER   0x1
#define CAPTURE_CA_STORE_LOCAL_MACHINE  0x2
#define CAPTURE_CA_STORE_GROUP_POLICY   0x4
#define CAPTURE_CA_STORE_DEFAULT \
    (CAPTURE_CA_STORE_CURRENT_USER | CAPTURE_CA_STORE_GROUP_POLICY)

typedef struct _CAPTURE_CA CAPTURE_CA;

#ifdef __cplusplus
extern "C" {
#endif

CAPTURE_CA *CaptureCa_Create(void);

//
// load the persistent CA from <dir>\ca.crt + <dir>\ca.key, or create and
// persist a new one on first use.  reusing one CA (instead of minting a
// fresh one per session) means the host Root trust only needs to be
// granted once; later imports are idempotent and do not re-prompt.
//

CAPTURE_CA *CaptureCa_LoadOrCreatePersistent(const WCHAR *dir);

void CaptureCa_Free(CAPTURE_CA *ca);

int CaptureCa_ExportPublicPem(
    const CAPTURE_CA *ca,
    char *buffer,
    ULONG capacity,
    ULONG *length);

int CaptureCa_WritePublicPemPath(const CAPTURE_CA *ca, const WCHAR *path);
int CaptureCa_WritePublicPemHandle(const CAPTURE_CA *ca, HANDLE file);
int CaptureCa_ImportPublicPemToStore(
    const char *pem,
    ULONG pemLength,
    const WCHAR *storeName);
int CaptureCa_ImportPublicPemToStoreEx(
    const char *pem,
    ULONG pemLength,
    const WCHAR *storeName,
    ULONG storeFlags);

int CaptureCa_RemovePublicPemFromStore(
    const char *pem,
    ULONG pemLength,
    const WCHAR *storeName);
int CaptureCa_RemovePublicPemFromStoreEx(
    const char *pem,
    ULONG pemLength,
    const WCHAR *storeName,
    ULONG storeFlags);

//
// import/remove through the SYSTEM store provider (CryptSvc-visible),
// used for the HOST user Root store; the REG-direct path above stays
// in use for the sandboxed copy
//

int CaptureCa_ImportPublicPemToUserSystemStore(
    const char *pem,
    ULONG pemLength,
    const WCHAR *storeName);
int CaptureCa_RemovePublicPemFromUserSystemStore(
    const char *pem,
    ULONG pemLength,
    const WCHAR *storeName);

#ifdef __cplusplus
}
#endif

#endif /* _MY_CAPTURE_CA_H */
