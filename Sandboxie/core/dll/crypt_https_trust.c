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

#include "crypt_https_trust.h"

static int CryptHttps_NameEquals(const WCHAR *left, const WCHAR *right)
{
    WCHAR a;
    WCHAR b;

    if (! left || ! right)
        return 0;
    while (*left || *right) {
        a = *left;
        b = *right;
        if (a >= L'A' && a <= L'Z')
            a = (WCHAR)(a - L'A' + L'a');
        if (b >= L'A' && b <= L'Z')
            b = (WCHAR)(b - L'A' + L'a');
        if (a != b)
            return 0;
        ++left;
        ++right;
    }
    return 1;
}


static void CryptHttps_CopyNamedRoots(HCERTSTORE dest, HCERTSTORE src)
{
    PCCERT_CONTEXT cert = NULL;
    WCHAR name[128];

    if (! dest || ! src)
        return;
    while ((cert = CertEnumCertificatesInStore(src, cert)) != NULL) {
        name[0] = 0;
        CertGetNameStringW(
            cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL,
            name, ARRAYSIZE(name));
        if (! CryptHttps_NameEquals(name, CRYPT_HTTPS_SESSION_CA_CN))
            continue;
        CertAddCertificateContextToStore(
            dest, cert, CERT_STORE_ADD_REPLACE_EXISTING, NULL);
    }
}


HCERTSTORE CryptHttps_StoreFromEncodedCa(
    const BYTE *encoded,
    DWORD encodedLen)
{
    HCERTSTORE store;
    PCCERT_CONTEXT cert;

    if (! encoded || encodedLen == 0)
        return NULL;
    store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    if (! store)
        return NULL;
    cert = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, encoded, encodedLen);
    if (! cert) {
        CertCloseStore(store, 0);
        return NULL;
    }
    if (! CertAddCertificateContextToStore(
            store, cert, CERT_STORE_ADD_REPLACE_EXISTING, NULL)) {
        CertFreeCertificateContext(cert);
        CertCloseStore(store, 0);
        return NULL;
    }
    CertFreeCertificateContext(cert);
    return store;
}


typedef LONG (WINAPI *P_CryptHttpsRegOpenKeyExW)(
    HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
typedef LONG (WINAPI *P_CryptHttpsRegCloseKey)(HKEY);

static HMODULE CryptHttps_Advapi(void)
{
    HMODULE module = GetModuleHandleW(L"advapi32.dll");
    if (! module)
        module = LoadLibraryW(L"advapi32.dll");
    return module;
}


static LONG CryptHttps_RegOpenKeyExW(
    HKEY hive,
    LPCWSTR path,
    DWORD options,
    REGSAM sam,
    PHKEY key)
{
    static P_CryptHttpsRegOpenKeyExW fn = NULL;
    HMODULE module;

    if (! fn) {
        module = CryptHttps_Advapi();
        if (module)
            fn = (P_CryptHttpsRegOpenKeyExW)GetProcAddress(
                module, "RegOpenKeyExW");
    }
    if (! fn)
        return 2;
    return fn(hive, path, options, sam, key);
}


static void CryptHttps_RegCloseKey(HKEY key)
{
    static P_CryptHttpsRegCloseKey fn = NULL;
    HMODULE module;

    if (! fn) {
        module = CryptHttps_Advapi();
        if (module)
            fn = (P_CryptHttpsRegCloseKey)GetProcAddress(
                module, "RegCloseKey");
    }
    if (fn && key)
        fn(key);
}


static void CryptHttps_AddNamedRootsFromKey(
    HCERTSTORE memory,
    HKEY hive,
    const WCHAR *keyPath)
{
    HKEY key = NULL;
    HCERTSTORE src;

    if (! memory || ! keyPath)
        return;
    if (CryptHttps_RegOpenKeyExW(hive, keyPath, 0, KEY_READ, &key) != 0)
        return;
    src = CertOpenStore(CERT_STORE_PROV_REG, 0, 0, 0, key);
    if (src) {
        CryptHttps_CopyNamedRoots(memory, src);
        CertCloseStore(src, 0);
    }
    CryptHttps_RegCloseKey(key);
}


HCERTSTORE CryptHttps_OpenNamedRootsFromRegistry(
    HKEY hive,
    const WCHAR *keyPath)
{
    HCERTSTORE memory;
    DWORD count = 0;
    PCCERT_CONTEXT cert = NULL;

    memory = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    if (! memory)
        return NULL;
    CryptHttps_AddNamedRootsFromKey(memory, hive, keyPath);
    while ((cert = CertEnumCertificatesInStore(memory, cert)) != NULL)
        ++count;
    if (count == 0) {
        CertCloseStore(memory, 0);
        return NULL;
    }
    return memory;
}


HCERTSTORE CryptHttps_OpenSessionCaStore(void)
{
    HCERTSTORE memory;
    DWORD count = 0;
    PCCERT_CONTEXT cert = NULL;

    memory = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    if (! memory)
        return NULL;

    //
    // this hook runs only inside sandboxed processes, so the store it
    // reads is the box's VIRTUAL HKCU Root (which the in-box import wrote
    // into).  curl's schannel validates against the HOST Root via
    // host-side machinery instead; that path is served by the broker's
    // host-user import, not this function.
    //
    CryptHttps_AddNamedRootsFromKey(
        memory,
        HKEY_CURRENT_USER,
        L"Software\\Microsoft\\SystemCertificates\\Root");
    CryptHttps_AddNamedRootsFromKey(
        memory,
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\Root");

    while ((cert = CertEnumCertificatesInStore(memory, cert)) != NULL)
        ++count;
    if (count == 0) {
        CertCloseStore(memory, 0);
        return NULL;
    }
    return memory;
}


HCERTSTORE CryptHttps_CombineStores(
    HCERTSTORE additional,
    HCERTSTORE session)
{
    HCERTSTORE collection;

    if (! session)
        return additional;
    if (! additional)
        return session;
    collection = CertOpenStore(CERT_STORE_PROV_COLLECTION, 0, 0, 0, NULL);
    if (! collection)
        return session;
    CertAddStoreToCollection(collection, additional, 0, 0);
    CertAddStoreToCollection(collection, session, 0, 0);
    return collection;
}


static BOOL CryptHttps_LeafSignedByCa(
    PCCERT_CONTEXT leaf,
    PCCERT_CONTEXT ca)
{
    if (! leaf || ! ca)
        return FALSE;
    return CryptVerifyCertificateSignatureEx(
        0,
        X509_ASN_ENCODING,
        CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT,
        (void *)leaf,
        CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT,
        (void *)ca,
        0,
        NULL);
}


static BOOL CryptHttps_ChainLeafSignedBySessionCa(
    PCCERT_CHAIN_CONTEXT chain,
    HCERTSTORE sessionCas)
{
    if (! chain || chain->cChain == 0 ||
            ! chain->rgpChain || ! chain->rgpChain[0] ||
            chain->rgpChain[0]->cElement == 0 ||
            ! chain->rgpChain[0]->rgpElement ||
            ! chain->rgpChain[0]->rgpElement[0]) {
        return FALSE;
    }
    return CryptHttps_LeafSignedByKnownCas(
        chain->rgpChain[0]->rgpElement[0]->pCertContext, sessionCas);
}


BOOL CryptHttps_LeafSignedByKnownCas(
    PCCERT_CONTEXT leaf,
    HCERTSTORE sessionCas)
{
    PCCERT_CONTEXT ca = NULL;
    BOOL matched = FALSE;

    if (! leaf || ! sessionCas)
        return FALSE;
    while ((ca = CertEnumCertificatesInStore(sessionCas, ca)) != NULL) {
        if (CryptHttps_LeafSignedByCa(leaf, ca)) {
            matched = TRUE;
            break;
        }
    }
    if (ca)
        CertFreeCertificateContext(ca);
    return matched;
}


static void CryptHttps_ClearUntrusted(CERT_TRUST_STATUS *status)
{
    if (! status)
        return;
    status->dwErrorStatus &= ~(
        CERT_TRUST_IS_UNTRUSTED_ROOT |
        CERT_TRUST_IS_PARTIAL_CHAIN |
        CERT_TRUST_IS_NOT_SIGNATURE_VALID);
}


BOOL CryptHttps_RelaxSessionCaChain(
    PCCERT_CHAIN_CONTEXT chain,
    HCERTSTORE sessionCas)
{
    DWORD simple;
    DWORD element;

    if (! CryptHttps_ChainLeafSignedBySessionCa(chain, sessionCas))
        return FALSE;

    CryptHttps_ClearUntrusted((CERT_TRUST_STATUS *)&chain->TrustStatus);
    for (simple = 0; simple < chain->cChain; ++simple) {
        if (! chain->rgpChain[simple])
            continue;
        CryptHttps_ClearUntrusted(
            (CERT_TRUST_STATUS *)&chain->rgpChain[simple]->TrustStatus);
        for (element = 0; element < chain->rgpChain[simple]->cElement; ++element) {
            if (chain->rgpChain[simple]->rgpElement[element]) {
                CryptHttps_ClearUntrusted(
                    (CERT_TRUST_STATUS *)&chain->rgpChain[simple]->
                        rgpElement[element]->TrustStatus);
            }
        }
    }
    return TRUE;
}


BOOL CryptHttps_RelaxSessionCaPolicy(
    PCCERT_CHAIN_CONTEXT chain,
    CERT_CHAIN_POLICY_STATUS *status)
{
    HCERTSTORE sessionCas;
    BOOL relaxed = FALSE;

    if (! chain || ! status)
        return FALSE;
    sessionCas = CryptHttps_OpenSessionCaStore();
    if (! sessionCas)
        return FALSE;
    if (CryptHttps_ChainLeafSignedBySessionCa(chain, sessionCas)) {
        CryptHttps_RelaxSessionCaChain(chain, sessionCas);
        status->dwError = 0;
        status->lChainIndex = -1;
        status->lElementIndex = -1;
        relaxed = TRUE;
    } else {
    }
    CertCloseStore(sessionCas, 0);
    return relaxed;
}
