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


static X509 *CaptureCa_NewCertificate(
    EVP_PKEY *subjectKey,
    EVP_PKEY *issuerKey,
    X509 *issuerCert,
    const char *cn,
    int isCa)
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
            ! X509_gmtime_adj(X509_getm_notAfter(cert), 24 * 60 * 60)) {
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
