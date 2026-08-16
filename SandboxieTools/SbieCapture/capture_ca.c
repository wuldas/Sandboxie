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
// Session capture CA
//---------------------------------------------------------------------------

#include "capture_ca_priv.h"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#include <wincrypt.h>
#include <string.h>


static EVP_PKEY *CaptureCa_NewRsaKey(void)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (! ctx)
        return NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
            EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
            EVP_PKEY_keygen(ctx, &key) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}


static int CaptureCa_RandomSerial(ASN1_INTEGER *serial)
{
    unsigned char bytes[8];
    unsigned long long value;
    if (RAND_bytes(bytes, sizeof(bytes)) != 1)
        return 0;
    bytes[0] = (unsigned char)(bytes[0] & 0x7f);
    value =
        ((unsigned long long)bytes[0] << 56) |
        ((unsigned long long)bytes[1] << 48) |
        ((unsigned long long)bytes[2] << 40) |
        ((unsigned long long)bytes[3] << 32) |
        ((unsigned long long)bytes[4] << 24) |
        ((unsigned long long)bytes[5] << 16) |
        ((unsigned long long)bytes[6] << 8) |
        (unsigned long long)bytes[7];
    if (value == 0)
        value = 1;
    return ASN1_INTEGER_set_uint64(serial, value) == 1;
}


static int CaptureCa_AddCn(X509_NAME *name, const char *cn)
{
    return X509_NAME_add_entry_by_txt(
        name, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1, 0) == 1;
}


static int CaptureCa_AddExt(
    X509 *cert,
    X509 *issuer,
    int nid,
    const char *value)
{
    X509V3_CTX extCtx;
    X509_EXTENSION *ext;
    int ok;

    X509V3_set_ctx(&extCtx, issuer, cert, NULL, NULL, 0);
    ext = X509V3_EXT_conf_nid(NULL, &extCtx, nid, value);
    if (! ext)
        return 0;
    ok = X509_add_ext(cert, ext, -1) == 1;
    X509_EXTENSION_free(ext);
    return ok;
}


static X509 *CaptureCa_NewCertificateEx(
    EVP_PKEY *subjectKey,
    EVP_PKEY *issuerKey,
    X509 *issuerCert,
    const char *cn,
    int isCa,
    long notAfterSeconds)
{
    X509 *cert = X509_new();
    X509_NAME *name;

    if (! cert)
        return NULL;
    if (X509_set_version(cert, 2) != 1)
        goto fail;
    if (! CaptureCa_RandomSerial(X509_get_serialNumber(cert)))
        goto fail;
    if (! X509_gmtime_adj(X509_getm_notBefore(cert), 0) ||
            ! X509_gmtime_adj(X509_getm_notAfter(cert), notAfterSeconds)) {
        goto fail;
    }
    if (X509_set_pubkey(cert, subjectKey) != 1)
        goto fail;
    name = X509_get_subject_name(cert);
    if (! CaptureCa_AddCn(name, cn))
        goto fail;
    if (issuerCert) {
        if (X509_set_issuer_name(cert, X509_get_subject_name(issuerCert)) != 1)
            goto fail;
    }
    else if (X509_set_issuer_name(cert, name) != 1) {
        goto fail;
    }

    if (isCa) {
        if (! CaptureCa_AddExt(
                cert, cert, NID_basic_constraints, "critical,CA:TRUE") ||
                ! CaptureCa_AddExt(
                    cert, cert, NID_key_usage, "critical,keyCertSign,cRLSign")) {
            goto fail;
        }
    }
    else {
        char san[256];
        if (! CaptureCa_AddExt(cert, issuerCert, NID_basic_constraints, "CA:FALSE"))
            goto fail;
        sprintf_s(san, sizeof(san), "DNS:%s", cn);
        if (! CaptureCa_AddExt(cert, issuerCert, NID_subject_alt_name, san))
            goto fail;
        if (! CaptureCa_AddExt(
                cert, issuerCert, NID_ext_key_usage, "serverAuth")) {
            goto fail;
        }
    }

    if (X509_sign(cert, issuerKey, EVP_sha256()) <= 0)
        goto fail;
    return cert;

fail:
    X509_free(cert);
    return NULL;
}


static X509 *CaptureCa_NewCertificate(
    EVP_PKEY *subjectKey,
    EVP_PKEY *issuerKey,
    X509 *issuerCert,
    const char *cn,
    int isCa)
{
    return CaptureCa_NewCertificateEx(
        subjectKey, issuerKey, issuerCert, cn, isCa, 24 * 60 * 60);
}


CAPTURE_CA *CaptureCa_Create(void)
{
    CAPTURE_CA *ca = (CAPTURE_CA *)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*ca));
    if (! ca)
        return NULL;
    ca->key = CaptureCa_NewRsaKey();
    if (! ca->key)
        goto fail;
    ca->cert = CaptureCa_NewCertificate(
        ca->key, ca->key, NULL, "SbieCapture Session CA", 1);
    if (! ca->cert)
        goto fail;
    return ca;

fail:
    CaptureCa_Free(ca);
    return NULL;
}


//---------------------------------------------------------------------------
// Persistent CA
//---------------------------------------------------------------------------


#define CAPTURE_CA_PERSIST_CERT_NAME   L"ca.crt"
#define CAPTURE_CA_PERSIST_KEY_NAME    L"ca.key"
#define CAPTURE_CA_PERSIST_VALID_DAYS  (3650)   // ~10 years


static CAPTURE_CA *CaptureCa_CreatePersistent(void)
{
    CAPTURE_CA *ca = (CAPTURE_CA *)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*ca));
    if (! ca)
        return NULL;
    ca->key = CaptureCa_NewRsaKey();
    if (! ca->key)
        goto fail;
    ca->cert = CaptureCa_NewCertificateEx(
        ca->key, ca->key, NULL, "SbieCapture Session CA", 1,
        CAPTURE_CA_PERSIST_VALID_DAYS * 24L * 60L * 60L);
    if (! ca->cert)
        goto fail;
    return ca;

fail:
    CaptureCa_Free(ca);
    return NULL;
}


static int CaptureCa_WritePemFileFromBio(BIO *bio, const WCHAR *path)
{
    char *data = NULL;
    long length;
    HANDLE file;
    DWORD written = 0;
    int ok = 0;

    length = BIO_get_mem_data(bio, &data);
    if (length <= 0)
        return CAPTURE_CA_ERROR;
    file = CreateFileW(
        path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return CAPTURE_CA_ERROR;
    if (WriteFile(file, data, (DWORD)length, &written, NULL) &&
            written == (DWORD)length) {
        ok = 1;
    }
    CloseHandle(file);
    return ok ? CAPTURE_CA_OK : CAPTURE_CA_ERROR;
}


static int CaptureCa_WritePrivatePemPath(
    const CAPTURE_CA *ca, const WCHAR *path)
{
    BIO *bio;
    int status = CAPTURE_CA_ERROR;

    if (! ca || ! ca->key || ! path || ! path[0])
        return CAPTURE_CA_ERROR;
    bio = BIO_new(BIO_s_mem());
    if (! bio)
        return CAPTURE_CA_ERROR;
    if (PEM_write_bio_PrivateKey(bio, ca->key, NULL, NULL, 0, NULL, NULL) == 1)
        status = CaptureCa_WritePemFileFromBio(bio, path);
    BIO_free(bio);
    return status;
}


static int CaptureCa_JoinPath(
    const WCHAR *dir, const WCHAR *name, WCHAR *out, ULONG outChars)
{
    ULONG dirLen;

    if (! dir || ! name || ! out || outChars == 0)
        return 0;
    dirLen = (ULONG)wcslen(dir);
    if (dirLen == 0 || dirLen + wcslen(name) + 2 > outChars)
        return 0;
    memcpy(out, dir, dirLen * sizeof(WCHAR));
    if (out[dirLen - 1] != L'\\' && out[dirLen - 1] != L'/')
        out[dirLen++] = L'\\';
    wcscpy_s(out + dirLen, outChars - dirLen, name);
    return 1;
}


CAPTURE_CA *CaptureCa_LoadOrCreatePersistent(const WCHAR *dir)
{
    WCHAR certPath[512];
    WCHAR keyPath[512];
    CAPTURE_CA *ca;
    HANDLE file;
    DWORD fileSize;
    DWORD read = 0;
    char *buf;
    BIO *bio;
    X509 *cert = NULL;
    EVP_PKEY *key = NULL;

    if (! dir || ! dir[0])
        return NULL;
    if (! CaptureCa_JoinPath(
            dir, CAPTURE_CA_PERSIST_CERT_NAME, certPath, ARRAYSIZE(certPath)) ||
            ! CaptureCa_JoinPath(
                dir, CAPTURE_CA_PERSIST_KEY_NAME, keyPath, ARRAYSIZE(keyPath))) {
        return NULL;
    }

    //
    // try to load an existing pair; if either half is missing or malformed,
    // fall through and mint a fresh persistent CA
    //

    file = CreateFileW(
        certPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (file != INVALID_HANDLE_VALUE) {
        fileSize = GetFileSize(file, NULL);
        if (fileSize && fileSize < (1024 * 1024)) {
            buf = (char *)HeapAlloc(GetProcessHeap(), 0, fileSize + 1);
            if (buf &&
                    ReadFile(file, buf, fileSize, &read, NULL) && read) {
                bio = BIO_new_mem_buf(buf, (int)read);
                if (bio) {
                    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
                    BIO_free(bio);
                }
            }
            if (buf)
                HeapFree(GetProcessHeap(), 0, buf);
        }
        CloseHandle(file);
    }

    file = CreateFileW(
        keyPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (file != INVALID_HANDLE_VALUE) {
        fileSize = GetFileSize(file, NULL);
        if (fileSize && fileSize < (1024 * 1024)) {
            buf = (char *)HeapAlloc(GetProcessHeap(), 0, fileSize + 1);
            if (buf &&
                    ReadFile(file, buf, fileSize, &read, NULL) && read) {
                bio = BIO_new_mem_buf(buf, (int)read);
                if (bio) {
                    key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
                    BIO_free(bio);
                }
            }
            if (buf)
                HeapFree(GetProcessHeap(), 0, buf);
        }
        CloseHandle(file);
    }

    if (cert && key) {
        ca = (CAPTURE_CA *)HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*ca));
        if (ca) {
            ca->cert = cert;
            ca->key = key;
            return ca;
        }
    }
    if (cert)
        X509_free(cert);
    if (key)
        EVP_PKEY_free(key);

    //
    // mint + persist a fresh CA; require the directory to already exist
    // (the broker creates it before calling)
    //

    ca = CaptureCa_CreatePersistent();
    if (! ca)
        return NULL;
    if (CaptureCa_WritePublicPemPath(ca, certPath) != CAPTURE_CA_OK ||
            CaptureCa_WritePrivatePemPath(ca, keyPath) != CAPTURE_CA_OK) {
        //
        // could not persist: keep using the in-memory CA for this session
        //
        return ca;
    }
    return ca;
}


void CaptureCa_Free(CAPTURE_CA *ca)
{
    if (! ca)
        return;
    X509_free(ca->cert);
    EVP_PKEY_free(ca->key);
    HeapFree(GetProcessHeap(), 0, ca);
}


int CaptureCa_ExportPublicPem(
    const CAPTURE_CA *ca,
    char *buffer,
    ULONG capacity,
    ULONG *length)
{
    BIO *bio;
    char *data = NULL;
    long pemLength;

    if (! ca || ! ca->cert || ! buffer || capacity == 0 || ! length)
        return CAPTURE_CA_ERROR;
    *length = 0;
    bio = BIO_new(BIO_s_mem());
    if (! bio)
        return CAPTURE_CA_ERROR;
    if (PEM_write_bio_X509(bio, ca->cert) != 1) {
        BIO_free(bio);
        return CAPTURE_CA_ERROR;
    }
    pemLength = BIO_get_mem_data(bio, &data);
    if (pemLength <= 0 || (ULONG)pemLength + 1 > capacity) {
        BIO_free(bio);
        return CAPTURE_CA_ERROR;
    }
    memcpy(buffer, data, (size_t)pemLength);
    buffer[pemLength] = 0;
    *length = (ULONG)pemLength;
    BIO_free(bio);
    return CAPTURE_CA_OK;
}


int CaptureCa_WritePublicPemPath(const CAPTURE_CA *ca, const WCHAR *path)
{
    char pem[4096];
    ULONG length = 0;
    HANDLE file;
    DWORD written = 0;

    if (! path || ! path[0])
        return CAPTURE_CA_ERROR;
    if (CaptureCa_ExportPublicPem(ca, pem, sizeof(pem), &length) != CAPTURE_CA_OK)
        return CAPTURE_CA_ERROR;
    file = CreateFileW(
        path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return CAPTURE_CA_ERROR;
    if (! WriteFile(file, pem, length, &written, NULL) || written != length) {
        CloseHandle(file);
        return CAPTURE_CA_ERROR;
    }
    CloseHandle(file);
    return CAPTURE_CA_OK;
}


int CaptureCa_WritePublicPemHandle(const CAPTURE_CA *ca, HANDLE file)
{
    char pem[4096];
    ULONG length = 0;
    DWORD written = 0;

    if (file == NULL || file == INVALID_HANDLE_VALUE)
        return CAPTURE_CA_ERROR;
    if (CaptureCa_ExportPublicPem(ca, pem, sizeof(pem), &length) != CAPTURE_CA_OK)
        return CAPTURE_CA_ERROR;
    if (! WriteFile(file, pem, length, &written, NULL) || written != length)
        return CAPTURE_CA_ERROR;
    return CAPTURE_CA_OK;
}


int CaptureCa_MintLeaf(
    CAPTURE_CA *ca,
    const char *sni,
    X509 **cert,
    EVP_PKEY **key)
{
    EVP_PKEY *leafKey;
    X509 *leaf;

    if (! ca || ! ca->cert || ! ca->key || ! cert || ! key)
        return CAPTURE_CA_ERROR;
    if (! sni || ! sni[0])
        sni = "invalid.invalid";
    leafKey = CaptureCa_NewRsaKey();
    if (! leafKey)
        return CAPTURE_CA_ERROR;
    leaf = CaptureCa_NewCertificate(leafKey, ca->key, ca->cert, sni, 0);
    if (! leaf) {
        EVP_PKEY_free(leafKey);
        return CAPTURE_CA_ERROR;
    }
    *cert = leaf;
    *key = leafKey;
    return CAPTURE_CA_OK;
}


static const char *CaptureCa_SkipPemHeader(const char *pem, ULONG *remaining)
{
    const char *begin;
    const char *cursor;

    if (! pem || ! remaining)
        return NULL;
    begin = strstr(pem, "-----BEGIN CERTIFICATE-----");
    if (! begin)
        return NULL;
    begin += 27;
    while (*begin == '\r' || *begin == '\n')
        ++begin;
    cursor = strstr(begin, "-----END CERTIFICATE-----");
    if (! cursor || cursor <= begin)
        return NULL;
    *remaining = (ULONG)(cursor - begin);
    return begin;
}


static int CaptureCa_StoreNameIsSafe(const WCHAR *storeName)
{
    const WCHAR *cursor;

    if (! storeName || ! storeName[0])
        return 0;
    for (cursor = storeName; *cursor; ++cursor) {
        if ((*cursor >= L'A' && *cursor <= L'Z') ||
                (*cursor >= L'a' && *cursor <= L'z') ||
                (*cursor >= L'0' && *cursor <= L'9')) {
            continue;
        }
        return 0;
    }
    return 1;
}


static HCERTSTORE CaptureCa_OpenRegistryStore(
    HKEY hive,
    const WCHAR *keyPath,
    HKEY *openedKey)
{
    HKEY key = NULL;
    HCERTSTORE store;

    if (openedKey)
        *openedKey = NULL;
    if (! hive || ! keyPath || ! keyPath[0])
        return NULL;
    if (RegCreateKeyExW(
            hive, keyPath, 0, NULL, 0,
            KEY_READ | KEY_WRITE, NULL, &key, NULL) != ERROR_SUCCESS) {
        return NULL;
    }
    store = CertOpenStore(CERT_STORE_PROV_REG, 0, 0, 0, key);
    if (! store) {
        RegCloseKey(key);
        return NULL;
    }
    if (openedKey)
        *openedKey = key;
    else
        RegCloseKey(key);
    return store;
}


static int CaptureCa_FormatStorePath(
    WCHAR *keyPath,
    ULONG keyPathChars,
    const WCHAR *format,
    const WCHAR *storeName)
{
    if (! keyPath || ! format || ! CaptureCa_StoreNameIsSafe(storeName))
        return 0;
    return swprintf_s(keyPath, keyPathChars, format, storeName) >= 0;
}


static int CaptureCa_ImportPublicPemToHive(
    const char *pem,
    ULONG pemLength,
    HKEY hive,
    const WCHAR *keyPath)
{
    const char *body;
    ULONG bodyLength = 0;
    DWORD decodedSize = 0;
    BYTE *decoded = NULL;
    HCERTSTORE store = NULL;
    PCCERT_CONTEXT cert = NULL;
    HKEY storeKey = NULL;
    int status = CAPTURE_CA_ERROR;

    UNREFERENCED_PARAMETER(pemLength);
    if (! pem || ! hive || ! keyPath || ! keyPath[0])
        return CAPTURE_CA_ERROR;
    if (strstr(pem, "PRIVATE KEY"))
        return CAPTURE_CA_ERROR;

    body = CaptureCa_SkipPemHeader(pem, &bodyLength);
    if (! body || ! bodyLength)
        return CAPTURE_CA_ERROR;
    if (! CryptStringToBinaryA(
            body, bodyLength, CRYPT_STRING_BASE64, NULL, &decodedSize,
            NULL, NULL) || ! decodedSize) {
        return CAPTURE_CA_ERROR;
    }
    decoded = (BYTE *)HeapAlloc(GetProcessHeap(), 0, decodedSize);
    if (! decoded)
        return CAPTURE_CA_ERROR;
    if (! CryptStringToBinaryA(
            body, bodyLength, CRYPT_STRING_BASE64, decoded, &decodedSize,
            NULL, NULL)) {
        goto done;
    }

    store = CaptureCa_OpenRegistryStore(hive, keyPath, &storeKey);
    if (! store)
        goto done;
    if (! CertAddEncodedCertificateToStore(
            store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            decoded,
            decodedSize,
            CERT_STORE_ADD_REPLACE_EXISTING,
            &cert)) {
        goto done;
    }
    CertControlStore(store, 0, CERT_STORE_CTRL_COMMIT, NULL);
    status = CAPTURE_CA_OK;

done:
    if (cert)
        CertFreeCertificateContext(cert);
    if (store)
        CertCloseStore(store, 0);
    if (storeKey)
        RegCloseKey(storeKey);
    if (decoded)
        HeapFree(GetProcessHeap(), 0, decoded);
    return status;
}


int CaptureCa_ImportPublicPemToStoreEx(
    const char *pem,
    ULONG pemLength,
    const WCHAR *storeName,
    ULONG storeFlags)
{
    WCHAR keyPath[256];
    int anyOk = 0;

    if (! storeFlags)
        storeFlags = CAPTURE_CA_STORE_DEFAULT;
    if (storeFlags & CAPTURE_CA_STORE_CURRENT_USER) {
        if (CaptureCa_FormatStorePath(
                keyPath, ARRAYSIZE(keyPath),
                L"Software\\Microsoft\\SystemCertificates\\%s",
                storeName) &&
                CaptureCa_ImportPublicPemToHive(
                    pem, pemLength, HKEY_CURRENT_USER, keyPath) ==
                    CAPTURE_CA_OK) {
            anyOk = 1;
        }
    }
    if (storeFlags & CAPTURE_CA_STORE_LOCAL_MACHINE) {
        if (CaptureCa_FormatStorePath(
                keyPath, ARRAYSIZE(keyPath),
                L"SOFTWARE\\Microsoft\\SystemCertificates\\%s",
                storeName) &&
                CaptureCa_ImportPublicPemToHive(
                    pem, pemLength, HKEY_LOCAL_MACHINE, keyPath) ==
                    CAPTURE_CA_OK) {
            anyOk = 1;
        }
    }
    if (storeFlags & CAPTURE_CA_STORE_GROUP_POLICY) {
        if (CaptureCa_FormatStorePath(
                keyPath, ARRAYSIZE(keyPath),
                L"SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\%s",
                storeName) &&
                CaptureCa_ImportPublicPemToHive(
                    pem, pemLength, HKEY_LOCAL_MACHINE, keyPath) ==
                    CAPTURE_CA_OK) {
            anyOk = 1;
        }
    }
    return anyOk ? CAPTURE_CA_OK : CAPTURE_CA_ERROR;
}


int CaptureCa_ImportPublicPemToStore(
    const char *pem,
    ULONG pemLength,
    const WCHAR *storeName)
{
    return CaptureCa_ImportPublicPemToStoreEx(
        pem, pemLength, storeName, CAPTURE_CA_STORE_DEFAULT);
}


static int CaptureCa_RemovePublicPemFromHive(
    const char *pem,
    ULONG pemLength,
    HKEY hive,
    const WCHAR *keyPath)
{
    const char *body;
    ULONG bodyLength = 0;
    DWORD decodedSize = 0;
    BYTE *decoded = NULL;
    HCERTSTORE store = NULL;
    PCCERT_CONTEXT cert = NULL;
    HKEY storeKey = NULL;
    CRYPT_HASH_BLOB hash;
    int status = CAPTURE_CA_ERROR;

    hash.cbData = 0;
    hash.pbData = NULL;

    UNREFERENCED_PARAMETER(pemLength);
    if (! pem || ! hive || ! keyPath || ! keyPath[0])
        return CAPTURE_CA_ERROR;
    if (strstr(pem, "PRIVATE KEY"))
        return CAPTURE_CA_ERROR;

    body = CaptureCa_SkipPemHeader(pem, &bodyLength);
    if (! body || ! bodyLength)
        return CAPTURE_CA_ERROR;
    if (! CryptStringToBinaryA(
            body, bodyLength, CRYPT_STRING_BASE64, NULL, &decodedSize,
            NULL, NULL) || ! decodedSize) {
        return CAPTURE_CA_ERROR;
    }
    decoded = (BYTE *)HeapAlloc(GetProcessHeap(), 0, decodedSize);
    if (! decoded)
        return CAPTURE_CA_ERROR;
    if (! CryptStringToBinaryA(
            body, bodyLength, CRYPT_STRING_BASE64, decoded, &decodedSize,
            NULL, NULL)) {
        goto done;
    }

    cert = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, decoded, decodedSize);
    if (! cert)
        goto done;

    hash.cbData = 0;
    hash.pbData = NULL;
    if (! CertGetCertificateContextProperty(
            cert, CERT_SHA1_HASH_PROP_ID, NULL, &hash.cbData) ||
            ! hash.cbData) {
        goto done;
    }
    hash.pbData = (BYTE *)HeapAlloc(GetProcessHeap(), 0, hash.cbData);
    if (! hash.pbData)
        goto done;
    if (! CertGetCertificateContextProperty(
            cert, CERT_SHA1_HASH_PROP_ID, hash.pbData, &hash.cbData)) {
        HeapFree(GetProcessHeap(), 0, hash.pbData);
        hash.pbData = NULL;
        goto done;
    }

    store = CaptureCa_OpenRegistryStore(hive, keyPath, &storeKey);
    if (! store)
        goto done;

    //
    // delete by hash (exact match on the imported certificate);
    // absent entries are not an error so removal is idempotent
    //

    {
        PCCERT_CONTEXT found;
        while ((found = CertFindCertificateInStore(
                    store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                    CERT_FIND_HASH, &hash, NULL)) != NULL) {
            CertDeleteCertificateFromStore(found);
        }
    }
    CertControlStore(store, 0, CERT_STORE_CTRL_COMMIT, NULL);
    status = CAPTURE_CA_OK;

done:
    if (hash.pbData)
        HeapFree(GetProcessHeap(), 0, hash.pbData);
    if (cert)
        CertFreeCertificateContext(cert);
    if (store)
        CertCloseStore(store, 0);
    if (storeKey)
        RegCloseKey(storeKey);
    if (decoded)
        HeapFree(GetProcessHeap(), 0, decoded);
    return status;
}


int CaptureCa_RemovePublicPemFromStoreEx(
    const char *pem,
    ULONG pemLength,
    const WCHAR *storeName,
    ULONG storeFlags)
{
    WCHAR keyPath[256];
    int anyOk = 0;

    if (! storeFlags)
        storeFlags = CAPTURE_CA_STORE_DEFAULT;
    if (storeFlags & CAPTURE_CA_STORE_CURRENT_USER) {
        if (CaptureCa_FormatStorePath(
                keyPath, ARRAYSIZE(keyPath),
                L"Software\\Microsoft\\SystemCertificates\\%s",
                storeName) &&
                CaptureCa_RemovePublicPemFromHive(
                    pem, pemLength, HKEY_CURRENT_USER, keyPath) ==
                    CAPTURE_CA_OK) {
            anyOk = 1;
        }
    }
    if (storeFlags & CAPTURE_CA_STORE_LOCAL_MACHINE) {
        if (CaptureCa_FormatStorePath(
                keyPath, ARRAYSIZE(keyPath),
                L"SOFTWARE\\Microsoft\\SystemCertificates\\%s",
                storeName) &&
                CaptureCa_RemovePublicPemFromHive(
                    pem, pemLength, HKEY_LOCAL_MACHINE, keyPath) ==
                    CAPTURE_CA_OK) {
            anyOk = 1;
        }
    }
    if (storeFlags & CAPTURE_CA_STORE_GROUP_POLICY) {
        if (CaptureCa_FormatStorePath(
                keyPath, ARRAYSIZE(keyPath),
                L"SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\%s",
                storeName) &&
                CaptureCa_RemovePublicPemFromHive(
                    pem, pemLength, HKEY_LOCAL_MACHINE, keyPath) ==
                    CAPTURE_CA_OK) {
            anyOk = 1;
        }
    }
    return anyOk ? CAPTURE_CA_OK : CAPTURE_CA_ERROR;
}


int CaptureCa_RemovePublicPemFromStore(
    const char *pem,
    ULONG pemLength,
    const WCHAR *storeName)
{
    return CaptureCa_RemovePublicPemFromStoreEx(
        pem, pemLength, storeName, CAPTURE_CA_STORE_DEFAULT);
}


static int CaptureCa_DecodePublicPem(
    const char *pem,
    ULONG pemLength,
    BYTE **decoded,
    DWORD *decodedSize)
{
    const char *body;
    ULONG bodyLength = 0;

    UNREFERENCED_PARAMETER(pemLength);
    if (decoded)
        *decoded = NULL;
    if (decodedSize)
        *decodedSize = 0;
    if (! pem || ! decoded || ! decodedSize)
        return 0;
    if (strstr(pem, "PRIVATE KEY"))
        return 0;
    body = CaptureCa_SkipPemHeader(pem, &bodyLength);
    if (! body || ! bodyLength)
        return 0;
    if (! CryptStringToBinaryA(
            body, bodyLength, CRYPT_STRING_BASE64, NULL, decodedSize,
            NULL, NULL) || ! *decodedSize)
        return 0;
    *decoded = (BYTE *)HeapAlloc(GetProcessHeap(), 0, *decodedSize);
    if (! *decoded)
        return 0;
    if (! CryptStringToBinaryA(
            body, bodyLength, CRYPT_STRING_BASE64, *decoded, decodedSize,
            NULL, NULL)) {
        HeapFree(GetProcessHeap(), 0, *decoded);
        *decoded = NULL;
        return 0;
    }
    return 1;
}


static HCERTSTORE CaptureCa_OpenUserSystemStore(const WCHAR *storeName)
{
    if (! CaptureCa_StoreNameIsSafe(storeName))
        return NULL;
    return CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W, 0, 0,
        CERT_SYSTEM_STORE_CURRENT_USER, storeName);
}


int CaptureCa_ImportPublicPemToUserSystemStore(
    const char *pem,
    ULONG pemLength,
    const WCHAR *storeName)
{
    BYTE *decoded = NULL;
    DWORD decodedSize = 0;
    HCERTSTORE store;
    PCCERT_CONTEXT cert = NULL;
    int status = CAPTURE_CA_ERROR;

    UNREFERENCED_PARAMETER(pemLength);
    if (! CaptureCa_DecodePublicPem(pem, pemLength, &decoded, &decodedSize))
        return CAPTURE_CA_ERROR;
    store = CaptureCa_OpenUserSystemStore(storeName);
    if (store) {
        cert = CertCreateCertificateContext(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, decoded, decodedSize);
        if (cert) {
            PCCERT_CONTEXT existing = CertFindCertificateInStore(
                store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                CERT_FIND_EXISTING, cert, NULL);
            if (existing) {
                //
                // already present (idempotent re-entry)
                //
                CertFreeCertificateContext(existing);
                status = CAPTURE_CA_OK;
            }
            else if (CertAddEncodedCertificateToStore(
                         store,
                         X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                         decoded, decodedSize,
                         CERT_STORE_ADD_REPLACE_EXISTING, NULL)) {
                CertControlStore(store, 0, CERT_STORE_CTRL_COMMIT, NULL);
                status = CAPTURE_CA_OK;
            }
            CertFreeCertificateContext(cert);
        }
        CertCloseStore(store, 0);
    }
    if (decoded)
        HeapFree(GetProcessHeap(), 0, decoded);
    return status;
}


int CaptureCa_RemovePublicPemFromUserSystemStore(
    const char *pem,
    ULONG pemLength,
    const WCHAR *storeName)
{
    BYTE *decoded = NULL;
    DWORD decodedSize = 0;
    HCERTSTORE store;
    PCCERT_CONTEXT cert = NULL;
    CRYPT_HASH_BLOB hash;
    int status = CAPTURE_CA_ERROR;

    hash.cbData = 0;
    hash.pbData = NULL;
    UNREFERENCED_PARAMETER(pemLength);
    if (! CaptureCa_DecodePublicPem(pem, pemLength, &decoded, &decodedSize))
        return CAPTURE_CA_ERROR;
    store = CaptureCa_OpenUserSystemStore(storeName);
    if (store) {
        cert = CertCreateCertificateContext(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, decoded, decodedSize);
        if (cert &&
                CertGetCertificateContextProperty(
                    cert, CERT_SHA1_HASH_PROP_ID, NULL, &hash.cbData) &&
                hash.cbData) {
            hash.pbData = (BYTE *)HeapAlloc(
                GetProcessHeap(), 0, hash.cbData);
            if (hash.pbData &&
                    CertGetCertificateContextProperty(
                        cert, CERT_SHA1_HASH_PROP_ID, hash.pbData,
                        &hash.cbData)) {
                PCCERT_CONTEXT found;
                while ((found = CertFindCertificateInStore(
                            store,
                            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                            CERT_FIND_HASH, &hash, NULL)) != NULL) {
                    CertDeleteCertificateFromStore(found);
                }
                CertControlStore(store, 0, CERT_STORE_CTRL_COMMIT, NULL);
                status = CAPTURE_CA_OK;
            }
        }
        CertCloseStore(store, 0);
    }
    if (hash.pbData)
        HeapFree(GetProcessHeap(), 0, hash.pbData);
    if (cert)
        CertFreeCertificateContext(cert);
    if (decoded)
        HeapFree(GetProcessHeap(), 0, decoded);
    return status;
}
