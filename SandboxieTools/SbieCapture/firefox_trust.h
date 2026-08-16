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
// Firefox/NSS trust helpers -- make a sandboxed Firefox profile trust the
// Phase 4 session CA without touching the host Firefox profile or host NSS
// databases.  Opt-in and boxed-profile-only.
//---------------------------------------------------------------------------

#ifndef _MY_FIREFOX_TRUST_H
#define _MY_FIREFOX_TRUST_H

#include <windows.h>

#define FIREFOX_TRUST_OK            0
#define FIREFOX_TRUST_ERROR         (-1)

#ifdef __cplusplus
extern "C" {
#endif

//
// Enable security.enterprise_roots.enabled in the given Firefox profile so it
// trusts the host Root store, where the Phase 4 persistent session CA already
// lives.  Idempotent: writes/updates <profile>\user.js and leaves the
// profile's own prefs.js untouched.  Firefox must be restarted to pick it up.
//
int FirefoxTrust_EnableEnterpriseRoots(const WCHAR *profileDir);

//
// Inject a CA public certificate into the profile's NSS cert9.db using the
// NSS certutil tool.  Returns OK only when certutil is present and the import
// succeeded.  certutilPath may be NULL to resolve "certutil" from PATH.
// Firefox must be closed while this runs (cert9.db is locked otherwise).
//
int FirefoxTrust_ImportCaToNss(
    const WCHAR *profileDir,
    const char *caPem,
    ULONG pemLength,
    const WCHAR *certutilPath);

#ifdef __cplusplus
}
#endif

#endif /* _MY_FIREFOX_TRUST_H */
