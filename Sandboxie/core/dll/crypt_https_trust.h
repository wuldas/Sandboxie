/*
 * Copyright 2026 David Xanatos, xanasoft.com
 *
 * This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//---------------------------------------------------------------------------
// Inject session MITM CA into Schannel chain building
//---------------------------------------------------------------------------

#ifndef _MY_CRYPT_HTTPS_TRUST_H
#define _MY_CRYPT_HTTPS_TRUST_H

#include <windows.h>
#include <wincrypt.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CRYPT_HTTPS_SESSION_CA_CN   L"SbieCapture Session CA"

HCERTSTORE CryptHttps_StoreFromEncodedCa(
    const BYTE *encoded,
    DWORD encodedLen);

HCERTSTORE CryptHttps_OpenSessionCaStore(void);

HCERTSTORE CryptHttps_OpenNamedRootsFromRegistry(
    HKEY hive,
    const WCHAR *keyPath);

HCERTSTORE CryptHttps_CombineStores(
    HCERTSTORE additional,
    HCERTSTORE session);

BOOL CryptHttps_RelaxSessionCaChain(
    PCCERT_CHAIN_CONTEXT chain,
    HCERTSTORE sessionCas);

BOOL CryptHttps_RelaxSessionCaPolicy(
    PCCERT_CHAIN_CONTEXT chain,
    CERT_CHAIN_POLICY_STATUS *status);

BOOL CryptHttps_LeafSignedByKnownCas(
    PCCERT_CONTEXT leaf,
    HCERTSTORE sessionCas);

#ifdef __cplusplus
}
#endif

#endif /* _MY_CRYPT_HTTPS_TRUST_H */
