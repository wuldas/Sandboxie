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
// Session CA + loopback HTTPS MITM tests
//---------------------------------------------------------------------------

#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#include "../SbieCapture/capture_ca.h"
#include "../SbieCapture/capture_ca_priv.h"
#include "../SbieCapture/https_mitm.h"
#include "../SbieCapture/capture_https_broker.h"
#include "../SbieCapture/capture_broker.h"
#include "../../Sandboxie/core/dll/crypt_https_trust.h"


static int Require(int condition, const char *message)
{
    if (! condition) {
        fprintf(stderr, "FAILED: %s\n", message);
        return 0;
    }
    return 1;
}


static void MakeTempPath(WCHAR *buffer, size_t capacity, const WCHAR *name)
{
    DWORD length = GetTempPathW((DWORD)capacity, buffer);
    if (length == 0 || length >= capacity)
        wcscpy_s(buffer, capacity, L".\\");
    wcscat_s(buffer, capacity, name);
}


static int ReadAll(const WCHAR *path, UCHAR **bytes, DWORD *size)
{
    HANDLE file = CreateFileW(
        path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return 0;

    DWORD fileSize = GetFileSize(file, NULL);
    UCHAR *buffer = (UCHAR *)malloc(fileSize + 1);
    DWORD read = 0;
    BOOL ok = buffer &&
        ReadFile(file, buffer, fileSize, &read, NULL) && read == fileSize;
    CloseHandle(file);
    if (! ok) {
        free(buffer);
        return 0;
    }
    buffer[fileSize] = 0;
    *bytes = buffer;
    *size = fileSize;
    return 1;
}


static EVP_PKEY *MakeRsaKey(void)
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


static int AddName(X509_NAME *name, const char *cn)
{
    return X509_NAME_add_entry_by_txt(
        name, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1, 0);
}


static X509 *MakeSelfSigned(
    EVP_PKEY *key,
    const char *cn,
    int isCa)
{
    X509 *cert = X509_new();
    X509_NAME *name;
    X509V3_CTX extCtx;
    X509_EXTENSION *ext;
    unsigned char serial[8];

    if (! cert)
        return NULL;
    if (X509_set_version(cert, 2) != 1)
        goto fail;
    if (RAND_bytes(serial, sizeof(serial)) != 1)
        goto fail;
    serial[0] &= 0x7f;
    if (! ASN1_INTEGER_set_uint64(X509_get_serialNumber(cert),
            ((unsigned long long)serial[0] << 56) |
            ((unsigned long long)serial[1] << 48) |
            ((unsigned long long)serial[2] << 40) |
            ((unsigned long long)serial[3] << 32) |
            ((unsigned long long)serial[4] << 24) |
            ((unsigned long long)serial[5] << 16) |
            ((unsigned long long)serial[6] << 8) |
            (unsigned long long)serial[7])) {
        /* fall back to a small serial */
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    }
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 24 * 60 * 60);
    if (X509_set_pubkey(cert, key) != 1)
        goto fail;
    name = X509_get_subject_name(cert);
    if (! AddName(name, cn))
        goto fail;
    if (X509_set_issuer_name(cert, name) != 1)
        goto fail;

    X509V3_set_ctx(&extCtx, cert, cert, NULL, NULL, 0);
    ext = X509V3_EXT_conf_nid(
        NULL, &extCtx, NID_basic_constraints,
        isCa ? "critical,CA:TRUE" : "CA:FALSE");
    if (! ext)
        goto fail;
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);

    if (! isCa) {
        char san[160];
        sprintf_s(san, sizeof(san), "DNS:%s", cn);
        ext = X509V3_EXT_conf_nid(NULL, &extCtx, NID_subject_alt_name, san);
        if (! ext)
            goto fail;
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
        ext = X509V3_EXT_conf_nid(
            NULL, &extCtx, NID_ext_key_usage, "serverAuth");
        if (ext) {
            X509_add_ext(cert, ext, -1);
            X509_EXTENSION_free(ext);
        }
    }

    if (X509_sign(cert, key, EVP_sha256()) <= 0)
        goto fail;
    return cert;

fail:
    X509_free(cert);
    return NULL;
}


static char *PemFromX509(X509 *cert)
{
    BIO *bio = BIO_new(BIO_s_mem());
    char *data = NULL;
    char *copy = NULL;
    long length = 0;
    if (! bio)
        return NULL;
    if (PEM_write_bio_X509(bio, cert) == 1)
        length = BIO_get_mem_data(bio, &data);
    if (length > 0) {
        copy = (char *)malloc((size_t)length + 1);
        if (copy) {
            memcpy(copy, data, (size_t)length);
            copy[length] = 0;
        }
    }
    BIO_free(bio);
    return copy;
}


typedef struct _UPSTREAM_SERVER {

    SOCKET listen_socket;
    USHORT port;
    EVP_PKEY *key;
    X509 *cert;
    char *ca_pem;
    HANDLE thread;
    volatile LONG stop;
    BOOL require_sni;
    BOOL chunked;

} UPSTREAM_SERVER;


static DWORD WINAPI UpstreamThread(void *param)
{
    UPSTREAM_SERVER *server = (UPSTREAM_SERVER *)param;
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (! ctx)
        return 1;
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_use_certificate(ctx, server->cert);
    SSL_CTX_use_PrivateKey(ctx, server->key);

    while (! server->stop) {
        fd_set readSet;
        struct timeval timeout;
        SOCKET client;
        SSL *ssl;
        char request[1024];
        int got;
        static const char kResponse[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 11\r\n"
            "Set-Cookie: session=abc123\r\n"
            "\r\n"
            "upstream-ok";
        /* "upstream-ok" split across two chunks */
        static const char kChunkedResponse[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Set-Cookie: session=abc123\r\n"
            "\r\n"
            "7\r\nupstrea\r\n"
            "4\r\nm-ok\r\n"
            "0\r\n\r\n";
        const char *response = server->chunked ? kChunkedResponse : kResponse;

        FD_ZERO(&readSet);
        FD_SET(server->listen_socket, &readSet);
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000;
        if (select(0, &readSet, NULL, NULL, &timeout) <= 0)
            continue;
        client = accept(server->listen_socket, NULL, NULL);
        if (client == INVALID_SOCKET)
            continue;
        ssl = SSL_new(ctx);
        if (! ssl) {
            closesocket(client);
            continue;
        }
        SSL_set_fd(ssl, (int)client);
        if (SSL_accept(ssl) == 1) {
            const char *sni = SSL_get_servername(
                ssl, TLSEXT_NAMETYPE_host_name);
            if (server->require_sni &&
                    (! sni || _stricmp(sni, "example.com") != 0)) {
                SSL_shutdown(ssl);
                SSL_free(ssl);
                closesocket(client);
                continue;
            }
            got = SSL_read(ssl, request, sizeof(request) - 1);
            if (got > 0)
                SSL_write(ssl, response, (int)strlen(response));
        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
        closesocket(client);
    }

    SSL_CTX_free(ctx);
    return 0;
}


static int StartUpstream(UPSTREAM_SERVER *server)
{
    struct sockaddr_in addr;
    int addrLen = sizeof(addr);

    memset(server, 0, sizeof(*server));
    server->listen_socket = INVALID_SOCKET;
    server->key = MakeRsaKey();
    server->cert = server->key ? MakeSelfSigned(
        server->key, "upstream.test", 1) : NULL;
    if (! server->cert)
        return 0;
    server->ca_pem = PemFromX509(server->cert);
    if (! server->ca_pem)
        return 0;

    server->listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server->listen_socket == INVALID_SOCKET)
        return 0;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(server->listen_socket, (struct sockaddr *)&addr, sizeof(addr)) != 0)
        return 0;
    if (listen(server->listen_socket, 8) != 0)
        return 0;
    if (getsockname(
            server->listen_socket, (struct sockaddr *)&addr, &addrLen) != 0)
        return 0;
    server->port = ntohs(addr.sin_port);
    server->thread = CreateThread(NULL, 0, UpstreamThread, server, 0, NULL);
    return server->thread != NULL;
}


static void StopUpstream(UPSTREAM_SERVER *server)
{
    if (! server)
        return;
    server->stop = 1;
    if (server->thread) {
        WaitForSingleObject(server->thread, 5000);
        CloseHandle(server->thread);
    }
    if (server->listen_socket != INVALID_SOCKET)
        closesocket(server->listen_socket);
    EVP_PKEY_free(server->key);
    X509_free(server->cert);
    free(server->ca_pem);
}


static HTTPS_REDIRECT_CONTEXT MakeContext(void)
{
    HTTPS_REDIRECT_CONTEXT context;
    memset(&context, 0, sizeof(context));
    context.magic = HTTPS_REDIRECT_CONTEXT_MAGIC;
    context.version = HTTPS_REDIRECT_CONTEXT_VERSION;
    context.capture_id_high = 0x1111111111111111ull;
    context.capture_id_low = 0x2222222222222222ull;
    context.generation = 7;
    context.process_id = 4242;
    context.session_id = 1;
    context.process_create_time = 133000000000000001ull;
    context.address_family = AF_INET;
    context.original_port = 443;
    context.original_address[0] = 93;
    context.original_address[1] = 184;
    context.original_address[2] = 216;
    context.original_address[3] = 34;
    return context;
}


typedef struct _SERVE_JOB {

    HTTPS_MITM *mitm;
    SOCKET client;
    HTTPS_REDIRECT_CONTEXT context;
    int have_context;
    int result;

} SERVE_JOB;


static DWORD WINAPI ServeThread(void *param)
{
    SERVE_JOB *job = (SERVE_JOB *)param;
    job->result = HttpsMitm_ServeOnce(
        job->mitm,
        job->client,
        job->have_context ? &job->context : NULL);
    return 0;
}


static int ClientGetOnSocket(
    SOCKET sock,
    const char *sessionCaPem,
    int minVersion,
    int maxVersion,
    char *response,
    ULONG responseCap)
{
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *trustBio;
    X509 *trustCert;
    X509_STORE *store;
    int ok = 0;
    int wrote;
    int got;
    static const char kRequest[] =
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Authorization: Bearer secret-token\r\n"
        "\r\n";

    if (responseCap)
        response[0] = 0;
    if (sock == INVALID_SOCKET)
        return 0;

    ctx = SSL_CTX_new(TLS_client_method());
    if (! ctx) {
        closesocket(sock);
        return 0;
    }
    SSL_CTX_set_min_proto_version(ctx, minVersion);
    SSL_CTX_set_max_proto_version(ctx, maxVersion);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    trustBio = BIO_new_mem_buf(sessionCaPem, -1);
    trustCert = trustBio ? PEM_read_bio_X509(trustBio, NULL, NULL, NULL) : NULL;
    store = SSL_CTX_get_cert_store(ctx);
    if (! trustCert || X509_STORE_add_cert(store, trustCert) != 1) {
        X509_free(trustCert);
        BIO_free(trustBio);
        SSL_CTX_free(ctx);
        closesocket(sock);
        return 0;
    }
    X509_free(trustCert);
    BIO_free(trustBio);

    ssl = SSL_new(ctx);
    if (! ssl) {
        SSL_CTX_free(ctx);
        closesocket(sock);
        return 0;
    }
    SSL_set_fd(ssl, (int)sock);
    SSL_set_tlsext_host_name(ssl, "example.com");
    if (SSL_connect(ssl) == 1) {
        wrote = SSL_write(ssl, kRequest, (int)strlen(kRequest));
        if (wrote > 0) {
            got = SSL_read(ssl, response, (int)responseCap - 1);
            if (got > 0) {
                response[got] = 0;
                ok = 1;
            }
        }
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    closesocket(sock);
    return ok;
}


static int CountOccurrences(const char *haystack, const char *needle)
{
    int count = 0;
    const char *p = haystack;
    while ((p = strstr(p, needle)) != NULL) {
        ++count;
        p += strlen(needle);
    }
    return count;
}


/* Send `count` sequential requests over one connection; append each response
   to `response`. Returns 1 if all `count` exchanges completed. */
static int ClientGetMultipleOnSocket(
    SOCKET sock,
    const char *sessionCaPem,
    int minVersion,
    int maxVersion,
    int count,
    char *response,
    ULONG responseCap)
{
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *trustBio;
    X509 *trustCert;
    X509_STORE *store;
    int total = 0;
    int i = 0;
    static const char kRequest[] =
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Authorization: Bearer secret-token\r\n"
        "\r\n";

    if (responseCap)
        response[0] = 0;
    if (sock == INVALID_SOCKET)
        return 0;

    ctx = SSL_CTX_new(TLS_client_method());
    if (! ctx) {
        closesocket(sock);
        return 0;
    }
    SSL_CTX_set_min_proto_version(ctx, minVersion);
    SSL_CTX_set_max_proto_version(ctx, maxVersion);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    trustBio = BIO_new_mem_buf(sessionCaPem, -1);
    trustCert = trustBio ? PEM_read_bio_X509(trustBio, NULL, NULL, NULL) : NULL;
    store = SSL_CTX_get_cert_store(ctx);
    if (! trustCert || X509_STORE_add_cert(store, trustCert) != 1) {
        X509_free(trustCert);
        BIO_free(trustBio);
        SSL_CTX_free(ctx);
        closesocket(sock);
        return 0;
    }
    X509_free(trustCert);
    BIO_free(trustBio);

    ssl = SSL_new(ctx);
    if (! ssl) {
        SSL_CTX_free(ctx);
        closesocket(sock);
        return 0;
    }
    SSL_set_fd(ssl, (int)sock);
    SSL_set_tlsext_host_name(ssl, "example.com");
    if (SSL_connect(ssl) == 1) {
        for (i = 0; i < count; ++i) {
            char cycle[512];
            int ctotal = 0;
            if (SSL_write(ssl, kRequest, (int)strlen(kRequest)) <= 0)
                break;
            cycle[0] = 0;
            for (;;) {
                int got = SSL_read(ssl, cycle + ctotal,
                                   (int)(sizeof(cycle) - 1 - ctotal));
                if (got <= 0)
                    break;
                ctotal += got;
                cycle[ctotal] = 0;
                if (strstr(cycle, "upstream-ok") != NULL)
                    break;
            }
            if (strstr(cycle, "upstream-ok") == NULL)
                break;
            if ((ULONG)(total + ctotal) >= responseCap)
                break;
            memcpy(response + total, cycle, ctotal);
            total += ctotal;
            response[total] = 0;
        }
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    closesocket(sock);
    return i == count;
}


static int TestChunkedResponse(void)
{
    UPSTREAM_SERVER upstream;
    CAPTURE_CA *ca;
    HTTPS_MITM_OPTIONS options;
    HTTPS_MITM *mitm;
    HTTPS_REDIRECT_CONTEXT context;
    SERVE_JOB job;
    HANDLE thread;
    SOCKET accepted;
    SOCKET probe;
    struct sockaddr_in addr;
    char sessionPem[4096];
    ULONG pemLength = 0;
    char response[1024];
    WCHAR harPath[MAX_PATH];
    UCHAR *harBytes = NULL;
    DWORD harSize = 0;
    int clientOk;
    int ok;

    if (! StartUpstream(&upstream)) {
        StopUpstream(&upstream);
        return Require(0, "chunked upstream");
    }
    upstream.chunked = TRUE;

    ca = CaptureCa_Create();
    if (! ca || CaptureCa_ExportPublicPem(
            ca, sessionPem, sizeof(sessionPem), &pemLength) != CAPTURE_CA_OK) {
        CaptureCa_Free(ca);
        StopUpstream(&upstream);
        return Require(0, "chunked session CA");
    }

    MakeTempPath(harPath, MAX_PATH, L"sbie-mitm-chunked.har");
    DeleteFileW(harPath);

    context = MakeContext();
    memset(&options, 0, sizeof(options));
    options.ca = ca;
    options.expected_context = &context;
    options.upstream_host = "127.0.0.1";
    options.upstream_port = upstream.port;
    options.upstream_ca_pem = upstream.ca_pem;
    options.har_path = harPath;
    options.redact = TRUE;
    options.include_bodies = TRUE;

    mitm = HttpsMitm_Listen(&options);
    if (! mitm) {
        CaptureCa_Free(ca);
        StopUpstream(&upstream);
        return Require(0, "chunked listen");
    }

    probe = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(HttpsMitm_ListenPort(mitm));
    if (connect(probe, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        closesocket(probe);
        HttpsMitm_Close(mitm);
        CaptureCa_Free(ca);
        StopUpstream(&upstream);
        return Require(0, "chunked connect");
    }
    accepted = HttpsMitm_Accept(mitm);
    memset(&job, 0, sizeof(job));
    job.mitm = mitm;
    job.client = accepted;
    job.context = context;
    job.have_context = 1;
    job.result = HTTPS_MITM_ERROR;
    thread = CreateThread(NULL, 0, ServeThread, &job, 0, NULL);
    if (! thread) {
        closesocket(probe);
        closesocket(accepted);
        HttpsMitm_Close(mitm);
        CaptureCa_Free(ca);
        StopUpstream(&upstream);
        return Require(0, "chunked serve thread");
    }
    clientOk = ClientGetOnSocket(
        probe, sessionPem, TLS1_2_VERSION, TLS1_2_VERSION,
        response, sizeof(response));
    WaitForSingleObject(thread, 10000);
    CloseHandle(thread);
    closesocket(probe);
    HttpsMitm_Close(mitm);
    CaptureCa_Free(ca);
    StopUpstream(&upstream);

    ok = Require(clientOk, "chunked client GET") &&
        Require(strstr(response, "Transfer-Encoding: chunked") != NULL,
                "chunked response relayed with chunked header") &&
        Require(job.result == HTTPS_MITM_OK, "chunked MITM serve success");
    if (! ok) {
        DeleteFileW(harPath);
        return 0;
    }

    if (! Require(ReadAll(harPath, &harBytes, &harSize), "read chunked HAR")) {
        DeleteFileW(harPath);
        return 0;
    }
    ok = Require(strstr((const char *)harBytes, "upstream-ok") != NULL,
                 "chunked body decoded in HAR") &&
        Require(strstr((const char *)harBytes, "upstrea\r\n4") == NULL,
                "raw chunk framing absent from HAR body");
    free(harBytes);
    DeleteFileW(harPath);
    return ok;
}


static int TestKeepAliveRoundTrip(void)
{
    UPSTREAM_SERVER upstream;
    CAPTURE_CA *ca;
    HTTPS_MITM_OPTIONS options;
    HTTPS_MITM *mitm;
    HTTPS_REDIRECT_CONTEXT context;
    SERVE_JOB job;
    HANDLE thread;
    SOCKET accepted;
    SOCKET probe;
    struct sockaddr_in addr;
    char sessionPem[4096];
    ULONG pemLength = 0;
    char response[2048];
    WCHAR harPath[MAX_PATH];
    UCHAR *harBytes = NULL;
    DWORD harSize = 0;
    int clientOk;
    int ok;

    if (! StartUpstream(&upstream)) {
        StopUpstream(&upstream);
        return Require(0, "keep-alive upstream");
    }
    ca = CaptureCa_Create();
    if (! ca || CaptureCa_ExportPublicPem(
            ca, sessionPem, sizeof(sessionPem), &pemLength) != CAPTURE_CA_OK) {
        CaptureCa_Free(ca);
        StopUpstream(&upstream);
        return Require(0, "keep-alive session CA");
    }

    MakeTempPath(harPath, MAX_PATH, L"sbie-mitm-keepalive.har");
    DeleteFileW(harPath);

    context = MakeContext();
    memset(&options, 0, sizeof(options));
    options.ca = ca;
    options.expected_context = &context;
    options.upstream_host = "127.0.0.1";
    options.upstream_port = upstream.port;
    options.upstream_ca_pem = upstream.ca_pem;
    options.har_path = harPath;
    options.redact = TRUE;
    options.include_bodies = TRUE;

    mitm = HttpsMitm_Listen(&options);
    if (! mitm) {
        CaptureCa_Free(ca);
        StopUpstream(&upstream);
        return Require(0, "keep-alive listen");
    }

    probe = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(HttpsMitm_ListenPort(mitm));
    if (connect(probe, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        closesocket(probe);
        HttpsMitm_Close(mitm);
        CaptureCa_Free(ca);
        StopUpstream(&upstream);
        return Require(0, "keep-alive connect");
    }
    accepted = HttpsMitm_Accept(mitm);
    memset(&job, 0, sizeof(job));
    job.mitm = mitm;
    job.client = accepted;
    job.context = context;
    job.have_context = 1;
    job.result = HTTPS_MITM_ERROR;
    thread = CreateThread(NULL, 0, ServeThread, &job, 0, NULL);
    if (! thread) {
        closesocket(probe);
        closesocket(accepted);
        HttpsMitm_Close(mitm);
        CaptureCa_Free(ca);
        StopUpstream(&upstream);
        return Require(0, "keep-alive serve thread");
    }
    clientOk = ClientGetMultipleOnSocket(
        probe, sessionPem, TLS1_2_VERSION, TLS1_2_VERSION, 2,
        response, sizeof(response));
    WaitForSingleObject(thread, 10000);
    CloseHandle(thread);
    closesocket(probe);
    HttpsMitm_Close(mitm);
    CaptureCa_Free(ca);
    StopUpstream(&upstream);

    ok = Require(clientOk, "two keep-alive exchanges") &&
        Require(CountOccurrences(response, "upstream-ok") == 2,
                "two responses on one connection") &&
        Require(job.result == HTTPS_MITM_OK, "keep-alive MITM serve success");
    if (! ok) {
        DeleteFileW(harPath);
        return 0;
    }

    if (! Require(ReadAll(harPath, &harBytes, &harSize), "read keep-alive HAR")) {
        DeleteFileW(harPath);
        return 0;
    }
    ok = Require(CountOccurrences((const char *)harBytes, "startedDateTime") == 2,
                 "two HAR entries for two exchanges");
    free(harBytes);
    DeleteFileW(harPath);
    return ok;
}


static int TestCaPublicPemHasNoPrivateKey(void)
{
    CAPTURE_CA *ca = CaptureCa_Create();
    char pem[4096];
    ULONG length = 0;
    WCHAR path[MAX_PATH];
    UCHAR *bytes = NULL;
    DWORD size = 0;
    int ok;

    if (! Require(ca != NULL, "create session CA"))
        return 0;
    if (! Require(CaptureCa_ExportPublicPem(ca, pem, sizeof(pem), &length) ==
                    CAPTURE_CA_OK,
                  "export public PEM") ||
            ! Require(length > 0, "public PEM length") ||
            ! Require(strstr(pem, "BEGIN CERTIFICATE") != NULL,
                      "public PEM is a certificate") ||
            ! Require(strstr(pem, "PRIVATE KEY") == NULL,
                      "public PEM has no private key")) {
        CaptureCa_Free(ca);
        return 0;
    }

    MakeTempPath(path, MAX_PATH, L"sbie-session-ca.pem");
    DeleteFileW(path);
    if (! Require(CaptureCa_WritePublicPemPath(ca, path) == CAPTURE_CA_OK,
                  "write public PEM path")) {
        CaptureCa_Free(ca);
        return 0;
    }
    if (! Require(ReadAll(path, &bytes, &size), "read written public PEM")) {
        DeleteFileW(path);
        CaptureCa_Free(ca);
        return 0;
    }
    ok = Require(strstr((const char *)bytes, "BEGIN CERTIFICATE") != NULL,
                 "written file is a certificate") &&
        Require(strstr((const char *)bytes, "PRIVATE KEY") == NULL,
                "written file has no private key");
    free(bytes);
    DeleteFileW(path);
    CaptureCa_Free(ca);
    return ok;
}


static int TestImportPublicPemToDisposableStore(void)
{
    CAPTURE_CA *ca = CaptureCa_Create();
    char pem[4096];
    ULONG length = 0;
    HCERTSTORE store;
    int ok;

    if (! Require(ca != NULL, "create CA for import"))
        return 0;
    if (! Require(CaptureCa_ExportPublicPem(ca, pem, sizeof(pem), &length) ==
                    CAPTURE_CA_OK,
                  "export PEM for import")) {
        CaptureCa_Free(ca);
        return 0;
    }
    ok = Require(CaptureCa_ImportPublicPemToStore(
                     pem, length, L"SbieCaptureTest") == CAPTURE_CA_OK,
                 "import public PEM to disposable store") &&
        Require(CaptureCa_ImportPublicPemToStore(
                    "[REDACTED PRIVATE KEY]\n",
                    60, L"SbieCaptureTest") == CAPTURE_CA_ERROR,
                "reject private key material");
    store = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W, 0, 0,
        CERT_SYSTEM_STORE_CURRENT_USER, L"SbieCaptureTest");
    if (! Require(store != NULL, "open SYSTEM store after REG import")) {
        CaptureCa_Free(ca);
        return 0;
    }
    {
        WCHAR subject[] = L"SbieCapture Session CA";
        PCCERT_CONTEXT found = CertFindCertificateInStore(
            store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
            CERT_FIND_SUBJECT_STR, subject, NULL);
        ok = ok && Require(found != NULL,
                           "SYSTEM store sees REG-imported session CA");
        if (found)
            CertFreeCertificateContext(found);
    }
    CertCloseStore(store, 0);
    store = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W, 0, 0,
        CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_DELETE_FLAG,
        L"SbieCaptureTest");
    if (store)
        CertCloseStore(store, 0);
    CaptureCa_Free(ca);
    return ok;
}


static int TestRemovePublicPemFromStore(void)
{
    CAPTURE_CA *ca = CaptureCa_Create();
    char pem[4096];
    ULONG length = 0;
    int ok;
    HCERTSTORE store;

    if (! Require(ca != NULL, "create CA for removal"))
        return 0;
    if (! Require(CaptureCa_ExportPublicPem(ca, pem, sizeof(pem), &length) ==
                    CAPTURE_CA_OK,
                  "export PEM for removal")) {
        CaptureCa_Free(ca);
        return 0;
    }
    ok = Require(CaptureCa_ImportPublicPemToStore(
                     pem, length, L"SbieCaptureTestRemove") == CAPTURE_CA_OK,
                 "import public PEM before removal");
    store = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W, 0, 0,
        CERT_SYSTEM_STORE_CURRENT_USER, L"SbieCaptureTestRemove");
    if (! Require(store != NULL, "open SYSTEM store before removal")) {
        CaptureCa_Free(ca);
        return 0;
    }
    {
        WCHAR subject[] = L"SbieCapture Session CA";
        PCCERT_CONTEXT found = CertFindCertificateInStore(
            store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
            CERT_FIND_SUBJECT_STR, subject, NULL);
        ok = ok && Require(found != NULL, "session CA present before removal");
        if (found)
            CertFreeCertificateContext(found);
    }
    CertCloseStore(store, 0);

    ok = ok && Require(CaptureCa_RemovePublicPemFromStore(
                           pem, length, L"SbieCaptureTestRemove") ==
                           CAPTURE_CA_OK,
                       "remove public PEM from store");

    store = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W, 0, 0,
        CERT_SYSTEM_STORE_CURRENT_USER, L"SbieCaptureTestRemove");
    if (! Require(store != NULL, "open SYSTEM store after removal")) {
        CaptureCa_Free(ca);
        return 0;
    }
    {
        WCHAR subject[] = L"SbieCapture Session CA";
        PCCERT_CONTEXT found = CertFindCertificateInStore(
            store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
            CERT_FIND_SUBJECT_STR, subject, NULL);
        ok = ok && Require(found == NULL, "session CA gone after removal");
        if (found)
            CertFreeCertificateContext(found);
    }
    CertCloseStore(store, 0);

    ok = ok && Require(CaptureCa_RemovePublicPemFromStore(
                           pem, length, L"SbieCaptureTestRemove") ==
                           CAPTURE_CA_OK,
                       "removal is idempotent when absent");

    store = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W, 0, 0,
        CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_DELETE_FLAG,
        L"SbieCaptureTestRemove");
    if (store)
        CertCloseStore(store, 0);
    CaptureCa_Free(ca);
    return ok;
}


static int TestImportPublicPemToMachineStoreIsBestEffort(void)
{
    CAPTURE_CA *ca = CaptureCa_Create();
    char pem[4096];
    ULONG length = 0;
    int machine;
    int policy;
    HCERTSTORE store;

    if (! Require(ca != NULL, "create CA for machine import"))
        return 0;
    if (! Require(CaptureCa_ExportPublicPem(ca, pem, sizeof(pem), &length) ==
                    CAPTURE_CA_OK,
                  "export PEM for machine import")) {
        CaptureCa_Free(ca);
        return 0;
    }
    machine = CaptureCa_ImportPublicPemToStoreEx(
        pem, length, L"SbieCaptureTest", CAPTURE_CA_STORE_LOCAL_MACHINE);
    policy = CaptureCa_ImportPublicPemToStoreEx(
        pem, length, L"SbieCaptureTest", CAPTURE_CA_STORE_GROUP_POLICY);
    if (machine == CAPTURE_CA_OK) {
        store = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W, 0, 0,
            CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_DELETE_FLAG,
            L"SbieCaptureTest");
        if (store)
            CertCloseStore(store, 0);
    }
    CaptureCa_Free(ca);
    return Require(
        machine == CAPTURE_CA_OK || machine == CAPTURE_CA_ERROR,
        "machine import is best-effort and does not crash") &&
        Require(
            policy == CAPTURE_CA_OK || policy == CAPTURE_CA_ERROR,
            "policy import is best-effort and does not crash");
}


static int EncodeX509(X509 *cert, BYTE **out, DWORD *outLen)
{
    int len;
    BYTE *der;
    BYTE *cursor;

    if (! cert || ! out || ! outLen)
        return 0;
    len = i2d_X509(cert, NULL);
    if (len <= 0)
        return 0;
    der = (BYTE *)malloc((size_t)len);
    if (! der)
        return 0;
    cursor = der;
    if (i2d_X509(cert, &cursor) != len) {
        free(der);
        return 0;
    }
    *out = der;
    *outLen = (DWORD)len;
    return 1;
}


static DWORD ChainError(PCCERT_CONTEXT leaf, HCERTSTORE extra)
{
    CERT_CHAIN_PARA para;
    PCCERT_CHAIN_CONTEXT chain = NULL;
    DWORD error = (DWORD)-1;

    memset(&para, 0, sizeof(para));
    para.cbSize = sizeof(para);
    if (! CertGetCertificateChain(
            NULL, leaf, NULL, extra, &para, 0, NULL, &chain) || ! chain)
        return error;
    error = chain->TrustStatus.dwErrorStatus;
    CertFreeCertificateChain(chain);
    return error;
}


static int RelaxAndReadError(
    PCCERT_CONTEXT leaf,
    HCERTSTORE sessionCas,
    DWORD *errorOut)
{
    CERT_CHAIN_PARA para;
    PCCERT_CHAIN_CONTEXT chain = NULL;
    BOOL relaxed;

    memset(&para, 0, sizeof(para));
    para.cbSize = sizeof(para);
    if (! CertGetCertificateChain(
            NULL, leaf, NULL, NULL, &para, 0, NULL, &chain) || ! chain)
        return 0;
    relaxed = CryptHttps_RelaxSessionCaChain(chain, sessionCas);
    *errorOut = chain->TrustStatus.dwErrorStatus;
    CertFreeCertificateChain(chain);
    return relaxed ? 1 : 0;
}


static int TestLeafTrustedWithSessionCaExtraStore(void)
{
    CAPTURE_CA *ca = CaptureCa_Create();
    X509 *leafX509 = NULL;
    EVP_PKEY *leafKey = NULL;
    BYTE *caDer = NULL;
    BYTE *leafDer = NULL;
    DWORD caLen = 0;
    DWORD leafLen = 0;
    PCCERT_CONTEXT leafCtx = NULL;
    HCERTSTORE extra = NULL;
    DWORD withoutExtra;
    DWORD withExtra;
    int extraTrusted;
    int ok;

    if (! Require(ca != NULL, "create CA for chain trust") ||
            CaptureCa_MintLeaf(ca, "example.com", &leafX509, &leafKey) !=
                CAPTURE_CA_OK) {
        CaptureCa_Free(ca);
        return Require(0, "mint leaf for chain trust");
    }
    if (! EncodeX509(ca->cert, &caDer, &caLen) ||
            ! EncodeX509(leafX509, &leafDer, &leafLen)) {
        EVP_PKEY_free(leafKey);
        X509_free(leafX509);
        CaptureCa_Free(ca);
        return Require(0, "encode CA/leaf DER");
    }
    leafCtx = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, leafDer, leafLen);
    extra = CryptHttps_StoreFromEncodedCa(caDer, caLen);
    if (! leafCtx || ! extra) {
        if (leafCtx)
            CertFreeCertificateContext(leafCtx);
        if (extra)
            CertCloseStore(extra, 0);
        free(caDer);
        free(leafDer);
        EVP_PKEY_free(leafKey);
        X509_free(leafX509);
        CaptureCa_Free(ca);
        return Require(0, "build leaf context and extra store");
    }
    withoutExtra = ChainError(leafCtx, NULL);
    extraTrusted = RelaxAndReadError(leafCtx, extra, &withExtra);
    //
    // A leaf signed by the ephemeral session CA must fail default chain
    // building.  On a clean host this surfaces as UNTRUSTED_ROOT /
    // PARTIAL_CHAIN; when a same-named persistent CA already sits in the
    // host Root store, Windows instead reports NOT_SIGNATURE_VALID because
    // the leaf's issuer name matches but the key does not.  Both mean the
    // leaf is untrusted until the exact session CA is supplied.
    //
    ok = Require(
            (withoutExtra & (CERT_TRUST_IS_UNTRUSTED_ROOT |
                             CERT_TRUST_IS_PARTIAL_CHAIN |
                             CERT_TRUST_IS_NOT_SIGNATURE_VALID)) != 0,
            "leaf is untrusted without session CA extra store") &&
        Require(extraTrusted, "relax helper verifies session-CA chain") &&
        Require(
            (withExtra & (CERT_TRUST_IS_UNTRUSTED_ROOT |
                          CERT_TRUST_IS_PARTIAL_CHAIN)) == 0,
            "leaf is trusted after session-CA chain relax");
    CertFreeCertificateContext(leafCtx);
    CertCloseStore(extra, 0);
    free(caDer);
    free(leafDer);
    EVP_PKEY_free(leafKey);
    X509_free(leafX509);
    CaptureCa_Free(ca);
    return ok;
}


static int TestPolicyRelaxClearsUntrustedRoot(void)
{
    CAPTURE_CA *ca = CaptureCa_Create();
    X509 *leafX509 = NULL;
    EVP_PKEY *leafKey = NULL;
    BYTE *caDer = NULL;
    BYTE *leafDer = NULL;
    DWORD caLen = 0;
    DWORD leafLen = 0;
    PCCERT_CONTEXT leafCtx = NULL;
    HCERTSTORE extra = NULL;
    CERT_CHAIN_PARA para;
    PCCERT_CHAIN_CONTEXT chain = NULL;
    CERT_CHAIN_POLICY_PARA policyPara;
    CERT_CHAIN_POLICY_STATUS policyStatus;
    BOOL policyOk;
    BOOL relaxed;
    int ok;

    if (! Require(ca != NULL, "create CA for policy relax") ||
            CaptureCa_MintLeaf(ca, "example.com", &leafX509, &leafKey) !=
                CAPTURE_CA_OK) {
        CaptureCa_Free(ca);
        return Require(0, "mint leaf for policy relax");
    }
    if (! EncodeX509(ca->cert, &caDer, &caLen) ||
            ! EncodeX509(leafX509, &leafDer, &leafLen)) {
        EVP_PKEY_free(leafKey);
        X509_free(leafX509);
        CaptureCa_Free(ca);
        return Require(0, "encode CA/leaf DER for policy");
    }
    leafCtx = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, leafDer, leafLen);
    extra = CryptHttps_StoreFromEncodedCa(caDer, caLen);
    memset(&para, 0, sizeof(para));
    para.cbSize = sizeof(para);
    if (! leafCtx || ! extra ||
            ! CertGetCertificateChain(
                NULL, leafCtx, NULL, NULL, &para, 0, NULL, &chain) ||
            ! chain) {
        if (chain)
            CertFreeCertificateChain(chain);
        if (leafCtx)
            CertFreeCertificateContext(leafCtx);
        if (extra)
            CertCloseStore(extra, 0);
        free(caDer);
        free(leafDer);
        EVP_PKEY_free(leafKey);
        X509_free(leafX509);
        CaptureCa_Free(ca);
        return Require(0, "build untrusted chain for policy");
    }
    memset(&policyPara, 0, sizeof(policyPara));
    policyPara.cbSize = sizeof(policyPara);
    memset(&policyStatus, 0, sizeof(policyStatus));
    policyStatus.cbSize = sizeof(policyStatus);
    policyOk = CertVerifyCertificateChainPolicy(
        CERT_CHAIN_POLICY_SSL, chain, &policyPara, &policyStatus);
    if (policyOk && policyStatus.dwError == 0) {
        policyStatus.dwError = (DWORD)CERT_E_UNTRUSTEDROOT;
    }
    relaxed = CryptHttps_RelaxSessionCaChain(chain, extra);
    if (relaxed) {
        policyStatus.dwError = 0;
        policyStatus.lChainIndex = -1;
        policyStatus.lElementIndex = -1;
    }
    ok = Require(relaxed, "policy helper matches session CA") &&
        Require(policyStatus.dwError == 0, "policy error cleared");
    CertFreeCertificateChain(chain);
    CertFreeCertificateContext(leafCtx);
    CertCloseStore(extra, 0);
    free(caDer);
    free(leafDer);
    EVP_PKEY_free(leafKey);
    X509_free(leafX509);
    CaptureCa_Free(ca);
    return ok;
}


static int TestOpenNamedRootsFromRegistry(void)
{
    CAPTURE_CA *ca = CaptureCa_Create();
    BYTE *caDer = NULL;
    DWORD caLen = 0;
    HKEY key = NULL;
    HCERTSTORE written = NULL;
    HCERTSTORE opened = NULL;
    PCCERT_CONTEXT found = NULL;
    WCHAR name[128];
    int ok;
    LONG status;

    if (! Require(ca != NULL, "create CA for registry roots") ||
            ! EncodeX509(ca->cert, &caDer, &caLen)) {
        CaptureCa_Free(ca);
        return Require(0, "encode CA for registry roots");
    }
    status = RegCreateKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\SbieCaptureHttpsTrustTest",
        0, NULL, 0, KEY_ALL_ACCESS, NULL, &key, NULL);
    if (status != 0 || ! key) {
        free(caDer);
        CaptureCa_Free(ca);
        return Require(0, "create disposable registry key");
    }
    written = CertOpenStore(CERT_STORE_PROV_REG, 0, 0, 0, key);
    if (! written ||
            ! CertAddEncodedCertificateToStore(
                written,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                caDer,
                caLen,
                CERT_STORE_ADD_REPLACE_EXISTING,
                NULL)) {
        if (written)
            CertCloseStore(written, 0);
        RegCloseKey(key);
        RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\SbieCaptureHttpsTrustTest");
        free(caDer);
        CaptureCa_Free(ca);
        return Require(0, "write CA into disposable registry store");
    }
    CertCloseStore(written, 0);
    RegCloseKey(key);
    opened = CryptHttps_OpenNamedRootsFromRegistry(
        HKEY_CURRENT_USER, L"Software\\SbieCaptureHttpsTrustTest");
    if (opened) {
        found = CertFindCertificateInStore(
            opened,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_EXISTING,
            CertCreateCertificateContext(
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, caDer, caLen),
            NULL);
        if (! found) {
            found = CertEnumCertificatesInStore(opened, NULL);
        }
        if (found) {
            name[0] = 0;
            CertGetNameStringW(
                found, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL,
                name, ARRAYSIZE(name));
        }
    }
    ok = Require(opened != NULL, "open named roots from registry") &&
        Require(found != NULL, "registry roots contain session CA");
    if (found)
        CertFreeCertificateContext(found);
    if (opened)
        CertCloseStore(opened, 0);
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\SbieCaptureHttpsTrustTest");
    free(caDer);
    CaptureCa_Free(ca);
    return ok;
}


static int RunMitmRoundTrip(int minVersion, int maxVersion, const char *label)
{
    UPSTREAM_SERVER upstream;
    CAPTURE_CA *ca;
    HTTPS_MITM_OPTIONS options;
    HTTPS_MITM *mitm;
    HTTPS_REDIRECT_CONTEXT context;
    SERVE_JOB job;
    HANDLE thread;
    SOCKET accepted;
    char sessionPem[4096];
    ULONG pemLength = 0;
    char response[1024];
    WCHAR harPath[MAX_PATH];
    UCHAR *harBytes = NULL;
    DWORD harSize = 0;
    int ok;
    char message[80];

    if (! StartUpstream(&upstream)) {
        StopUpstream(&upstream);
        return Require(0, "start upstream TLS server");
    }

    ca = CaptureCa_Create();
    if (! ca) {
        StopUpstream(&upstream);
        return Require(0, "create CA for MITM");
    }
    if (CaptureCa_ExportPublicPem(ca, sessionPem, sizeof(sessionPem),
            &pemLength) != CAPTURE_CA_OK) {
        CaptureCa_Free(ca);
        StopUpstream(&upstream);
        return Require(0, "export session CA");
    }

    MakeTempPath(harPath, MAX_PATH, L"sbie-mitm.har");
    DeleteFileW(harPath);

    context = MakeContext();
    memset(&options, 0, sizeof(options));
    options.ca = ca;
    options.expected_context = &context;
    options.upstream_host = "127.0.0.1";
    options.upstream_port = upstream.port;
    options.upstream_ca_pem = upstream.ca_pem;
    options.har_path = harPath;
    options.redact = TRUE;
    options.include_bodies = TRUE;

    mitm = HttpsMitm_Listen(&options);
    if (! mitm) {
        CaptureCa_Free(ca);
        StopUpstream(&upstream);
        return Require(0, "listen MITM");
    }

    {
        SOCKET probe = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(HttpsMitm_ListenPort(mitm));
        if (connect(probe, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            closesocket(probe);
            HttpsMitm_Close(mitm);
            CaptureCa_Free(ca);
            StopUpstream(&upstream);
            return Require(0, "client TCP connect");
        }
        accepted = HttpsMitm_Accept(mitm);
        if (accepted == INVALID_SOCKET) {
            closesocket(probe);
            HttpsMitm_Close(mitm);
            CaptureCa_Free(ca);
            StopUpstream(&upstream);
            return Require(0, "MITM accept");
        }
        memset(&job, 0, sizeof(job));
        job.mitm = mitm;
        job.client = accepted;
        job.context = context;
        job.have_context = 1;
        job.result = HTTPS_MITM_ERROR;
        thread = CreateThread(NULL, 0, ServeThread, &job, 0, NULL);
        if (! thread) {
            closesocket(probe);
            closesocket(accepted);
            HttpsMitm_Close(mitm);
            CaptureCa_Free(ca);
            StopUpstream(&upstream);
            return Require(0, "start serve thread");
        }
        ok = ClientGetOnSocket(
            probe, sessionPem, minVersion, maxVersion,
            response, sizeof(response));
        WaitForSingleObject(thread, 10000);
        CloseHandle(thread);
        closesocket(probe);
    }

    sprintf_s(message, sizeof(message), "%s client GET", label);
    if (! Require(ok, message) ||
            ! Require(strstr(response, "upstream-ok") != NULL,
                      "proxied upstream body") ||
            ! Require(job.result == HTTPS_MITM_OK, "MITM serve success")) {
        HttpsMitm_Close(mitm);
        CaptureCa_Free(ca);
        StopUpstream(&upstream);
        DeleteFileW(harPath);
        return 0;
    }

    HttpsMitm_Close(mitm);
    CaptureCa_Free(ca);
    StopUpstream(&upstream);

    if (! Require(ReadAll(harPath, &harBytes, &harSize), "read MITM HAR")) {
        DeleteFileW(harPath);
        return 0;
    }
    ok = Require(strstr((const char *)harBytes, "https://example.com/") != NULL,
                 "HAR URL uses SNI host") &&
        Require(strstr((const char *)harBytes, "https://127.0.0.1/") == NULL,
                "HAR URL is not loopback") &&
        Require(strstr((const char *)harBytes, "secret-token") == NULL,
                "authorization redacted in HAR") &&
        Require(strstr((const char *)harBytes, "upstream-ok") != NULL,
                "HAR contains body when enabled");
    free(harBytes);
    DeleteFileW(harPath);
    return ok;
}


static int TestTls13RoundTrip(void)
{
    return RunMitmRoundTrip(TLS1_3_VERSION, TLS1_3_VERSION, "TLS 1.3");
}


static int TestTls12RoundTrip(void)
{
    return RunMitmRoundTrip(TLS1_2_VERSION, TLS1_2_VERSION, "TLS 1.2");
}


static int TestMissingContextRejected(void)
{
    UPSTREAM_SERVER upstream;
    CAPTURE_CA *ca;
    HTTPS_MITM_OPTIONS options;
    HTTPS_MITM *mitm;
    HTTPS_REDIRECT_CONTEXT context;
    SERVE_JOB job;
    HANDLE thread;
    SOCKET accepted;
    SOCKET probe;
    struct sockaddr_in addr;
    char sessionPem[4096];
    ULONG pemLength = 0;
    char response[256];
    int clientOk;

    if (! StartUpstream(&upstream)) {
        StopUpstream(&upstream);
        return Require(0, "start upstream for reject test");
    }
    ca = CaptureCa_Create();
    if (! ca || CaptureCa_ExportPublicPem(
            ca, sessionPem, sizeof(sessionPem), &pemLength) != CAPTURE_CA_OK) {
        CaptureCa_Free(ca);
        StopUpstream(&upstream);
        return Require(0, "CA for reject test");
    }
    context = MakeContext();
    memset(&options, 0, sizeof(options));
    options.ca = ca;
    options.expected_context = &context;
    options.upstream_host = "127.0.0.1";
    options.upstream_port = upstream.port;
    options.upstream_ca_pem = upstream.ca_pem;
    options.har_path = NULL;
    mitm = HttpsMitm_Listen(&options);
    if (! mitm) {
        CaptureCa_Free(ca);
        StopUpstream(&upstream);
        return Require(0, "listen for reject test");
    }

    probe = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(HttpsMitm_ListenPort(mitm));
    if (connect(probe, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        closesocket(probe);
        HttpsMitm_Close(mitm);
        CaptureCa_Free(ca);
        StopUpstream(&upstream);
        return Require(0, "TCP connect for reject test");
    }
    accepted = HttpsMitm_Accept(mitm);
    memset(&job, 0, sizeof(job));
    job.mitm = mitm;
    job.client = accepted;
    job.have_context = 0;
    job.result = HTTPS_MITM_OK;
    thread = CreateThread(NULL, 0, ServeThread, &job, 0, NULL);
    clientOk = ClientGetOnSocket(
        probe, sessionPem, TLS1_3_VERSION, TLS1_3_VERSION,
        response, sizeof(response));
    WaitForSingleObject(thread, 10000);
    CloseHandle(thread);
    closesocket(probe);
    HttpsMitm_Close(mitm);
    CaptureCa_Free(ca);
    StopUpstream(&upstream);

    return Require(clientOk == 0, "client TLS without context fails") &&
        Require(job.result == HTTPS_MITM_REJECTED,
                "missing context is rejected");
}


static int TestQueryRedirectContextOnPlainSocketFails(void)
{
    SOCKET listener;
    SOCKET client;
    SOCKET accepted;
    struct sockaddr_in addr;
    int addrLen = sizeof(addr);
    HTTPS_REDIRECT_CONTEXT context;
    int queried;
    int queriedEx;
    ULONG wsaError = 0;

    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET)
        return Require(0, "query-context listener");
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
            listen(listener, 1) != 0) {
        closesocket(listener);
        return Require(0, "query-context bind");
    }
    addrLen = sizeof(addr);
    if (getsockname(listener, (struct sockaddr *)&addr, &addrLen) != 0) {
        closesocket(listener);
        return Require(0, "query-context getsockname");
    }
    client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client == INVALID_SOCKET ||
            connect(client, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        if (client != INVALID_SOCKET)
            closesocket(client);
        closesocket(listener);
        return Require(0, "query-context connect");
    }
    accepted = accept(listener, NULL, NULL);
    memset(&context, 0xCC, sizeof(context));
    queried = HttpsMitm_QueryRedirectContext(accepted, &context);
    queriedEx = HttpsMitm_QueryRedirectContextEx(
        accepted, &context, &wsaError);
    closesocket(accepted);
    closesocket(client);
    closesocket(listener);
    return Require(queried == 0, "plain socket has no WFP redirect context") &&
        Require(queriedEx == 0, "ex query fails on plain socket") &&
        Require(wsaError != 0, "plain socket query reports a WSA error") &&
        Require(HttpsMitm_QueryRedirectContext(INVALID_SOCKET, &context) == 0,
                "invalid socket query fails");
}


static CAPTURE_BROKER_SECTION *CreateBrokerSection(void)
{
    size_t size = offsetof(CAPTURE_BROKER_SECTION, records) +
        (size_t)CAPTURE_BROKER_MAX_RECORD_CAPACITY *
        sizeof(CAPTURE_PACKET_RECORD);
    CAPTURE_BROKER_SECTION *section =
        (CAPTURE_BROKER_SECTION *)calloc(1, size);
    if (! section)
        return NULL;
    section->magic = CAPTURE_BROKER_SECTION_MAGIC;
    section->version = CAPTURE_BROKER_SECTION_VERSION;
    section->size = (ULONG)size;
    section->record_capacity = CAPTURE_BROKER_MAX_RECORD_CAPACITY;
    section->capture_id_high = 0x1111111111111111ull;
    section->capture_id_low = 0x2222222222222222ull;
    section->generation = CaptureBroker_CalculateGeneration(
        section->capture_id_high, section->capture_id_low);
    wcscpy_s(section->box_name, ARRAYSIZE(section->box_name), L"DefaultBox");
    wcscpy_s(section->sid_string, ARRAYSIZE(section->sid_string),
             L"S-1-5-21-1-2-3-1001");
    return section;
}


static void FillTransportRecord(CAPTURE_PACKET_RECORD *record)
{
    memset(record, 0, sizeof(*record));
    record->sequence = 1;
    record->timestamp = 133000000000000000ull;
    record->process_create_time = 133000000000000001ull;
    record->process_id = 4242;
    record->session_id = 1;
    record->address_family = AF_INET;
    record->protocol = 6;
    record->direction = CAPTURE_PACKET_DIRECTION_OUTBOUND;
    record->layer = CAPTURE_PACKET_LAYER_TRANSPORT;
    record->original_length = 40;
    record->captured_length = 40;
    record->local_address[0] = 10;
    record->local_address[3] = 1;
    record->remote_address[0] = 1;
    record->remote_address[3] = 1;
    record->local_port = 40000;
    record->remote_port = 80;
    memset(record->data, 0xAB, 40);
}


typedef struct _BROKER_JOB {

    CAPTURE_BROKER_SECTION *section;
    CAPTURE_BROKER_OPTIONS options;
    int result;

} BROKER_JOB;


static DWORD WINAPI BrokerThread(void *param)
{
    BROKER_JOB *job = (BROKER_JOB *)param;
    job->result = CaptureBroker_Run(job->section, &job->options);
    return 0;
}


static int FileHasBytes(const WCHAR *path);

static int TestBrokerHttpsListenWritesHarAndPcapng(void)
{
    UPSTREAM_SERVER upstream;
    CAPTURE_BROKER_SECTION *section;
    CAPTURE_HTTPS_OPTIONS httpsOptions;
    CAPTURE_HTTPS_RUNTIME *https;
    BROKER_JOB job;
    HANDLE brokerThread;
    HANDLE stopEvent;
    HANDLE pcapFile;
    HANDLE harFile;
    HANDLE caFile;
    WCHAR pcapPath[MAX_PATH];
    WCHAR harPath[MAX_PATH];
    WCHAR caPath[MAX_PATH];
    HTTPS_REDIRECT_CONTEXT context;
    SOCKET probe;
    struct sockaddr_in addr;
    char sessionPem[4096];
    char response[1024];
    UCHAR *harBytes = NULL;
    DWORD harSize = 0;
    DWORD wait;
    int ok;

    if (! StartUpstream(&upstream)) {
        StopUpstream(&upstream);
        return Require(0, "start upstream for broker HTTPS");
    }

    section = CreateBrokerSection();
    if (! Require(section != NULL, "create broker section")) {
        StopUpstream(&upstream);
        return 0;
    }

    MakeTempPath(pcapPath, MAX_PATH, L"sbie-broker-https.pcapng");
    MakeTempPath(harPath, MAX_PATH, L"sbie-broker-https.har");
    MakeTempPath(caPath, MAX_PATH, L"sbie-broker-https-ca.pem");
    DeleteFileW(pcapPath);
    DeleteFileW(harPath);
    DeleteFileW(caPath);

    pcapFile = CreateFileW(
        pcapPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    harFile = CreateFileW(
        harPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    caFile = CreateFileW(
        caPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    stopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (pcapFile == INVALID_HANDLE_VALUE || harFile == INVALID_HANDLE_VALUE ||
            caFile == INVALID_HANDLE_VALUE || ! stopEvent) {
        StopUpstream(&upstream);
        free(section);
        return Require(0, "create broker HTTPS files");
    }

    context = MakeContext();
    context.original_port = upstream.port;
    memset(context.original_address, 0, sizeof(context.original_address));
    context.original_address[0] = 127;
    context.original_address[3] = 1;

    memset(&httpsOptions, 0, sizeof(httpsOptions));
    httpsOptions.har_file = harFile;
    httpsOptions.ca_file = caFile;
    httpsOptions.test_preamble = TRUE;
    httpsOptions.redact = TRUE;
    httpsOptions.include_bodies = TRUE;
    httpsOptions.expected_context = context;

    https = CaptureHttps_Start(section, &httpsOptions);
    if (! Require(https != NULL, "start broker HTTPS") ||
            ! Require(CaptureHttps_ListenPort(https) != 0,
                      "publish listen port") ||
            ! Require(section->https_listen_port ==
                      CaptureHttps_ListenPort(https),
                      "section listen port matches")) {
        CaptureHttps_Stop(https);
        CloseHandle(pcapFile);
        CloseHandle(stopEvent);
        StopUpstream(&upstream);
        free(section);
        DeleteFileW(pcapPath);
        DeleteFileW(harPath);
        DeleteFileW(caPath);
        return 0;
    }

    memset(&job, 0, sizeof(job));
    job.section = section;
    job.options.output_file = pcapFile;
    job.options.stop_event = stopEvent;
    job.options.expected_capture_id_high = section->capture_id_high;
    job.options.expected_capture_id_low = section->capture_id_low;
    job.options.expected_generation = section->generation;
    brokerThread = CreateThread(NULL, 0, BrokerThread, &job, 0, NULL);
    if (! Require(brokerThread != NULL, "start packet drain thread")) {
        CaptureHttps_Stop(https);
        CloseHandle(stopEvent);
        StopUpstream(&upstream);
        free(section);
        return 0;
    }

    FillTransportRecord(&section->records[0]);
    MemoryBarrier();
    section->write_index = 1;

    if (! Require(ReadAll(caPath, &harBytes, &harSize),
                  "read CA public pem") ||
            ! Require(strstr((const char *)harBytes, "BEGIN CERTIFICATE") != NULL,
                      "CA file is a public cert") ||
            ! Require(strstr((const char *)harBytes, "PRIVATE KEY") == NULL,
                      "CA file has no private key")) {
        free(harBytes);
        SetEvent(stopEvent);
        WaitForSingleObject(brokerThread, 5000);
        CloseHandle(brokerThread);
        CaptureHttps_Stop(https);
        CloseHandle(stopEvent);
        StopUpstream(&upstream);
        free(section);
        DeleteFileW(pcapPath);
        DeleteFileW(harPath);
        DeleteFileW(caPath);
        return 0;
    }
    if (harSize >= sizeof(sessionPem))
        harSize = sizeof(sessionPem) - 1;
    memcpy(sessionPem, harBytes, harSize);
    sessionPem[harSize] = 0;
    free(harBytes);
    harBytes = NULL;

    probe = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(CaptureHttps_ListenPort(https));
    if (connect(probe, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
            send(probe, (const char *)&context, sizeof(context), 0) !=
                (int)sizeof(context)) {
        closesocket(probe);
        SetEvent(stopEvent);
        WaitForSingleObject(brokerThread, 5000);
        CloseHandle(brokerThread);
        CaptureHttps_Stop(https);
        CloseHandle(stopEvent);
        StopUpstream(&upstream);
        free(section);
        return Require(0, "connect broker HTTPS with preamble");
    }

    ok = ClientGetOnSocket(
        probe, sessionPem, TLS1_3_VERSION, TLS1_3_VERSION,
        response, sizeof(response));
    SetEvent(stopEvent);
    wait = WaitForSingleObject(brokerThread, 10000);
    CloseHandle(brokerThread);
    CaptureHttps_Stop(https);
    CloseHandle(stopEvent);
    StopUpstream(&upstream);
    free(section);

    if (! Require(ok, "broker HTTPS client GET") ||
            ! Require(strstr(response, "upstream-ok") != NULL,
                      "broker HTTPS proxied body") ||
            ! Require(wait == WAIT_OBJECT_0, "packet drain stopped") ||
            ! Require(ReadAll(harPath, &harBytes, &harSize),
                      "read broker HAR")) {
        DeleteFileW(pcapPath);
        DeleteFileW(harPath);
        DeleteFileW(caPath);
        return 0;
    }

    ok = Require(strstr((const char *)harBytes, "https://example.com/") != NULL,
                 "broker HAR uses SNI") &&
        Require(strstr((const char *)harBytes, "secret-token") == NULL,
                "broker HAR redacts authorization") &&
        Require(FileHasBytes(pcapPath), "broker still wrote PCAPNG");
    free(harBytes);
    DeleteFileW(pcapPath);
    DeleteFileW(harPath);
    DeleteFileW(caPath);
    return ok;
}


static int FileHasBytes(const WCHAR *path)
{
    HANDLE file = CreateFileW(
        path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD size;
    if (file == INVALID_HANDLE_VALUE)
        return 0;
    size = GetFileSize(file, NULL);
    CloseHandle(file);
    return size > 32;
}


static int TestServeOnceForwardsDownstreamSni(void)
{
    UPSTREAM_SERVER upstream;
    CAPTURE_CA *ca;
    HTTPS_MITM_OPTIONS options;
    HTTPS_MITM *mitm;
    HTTPS_REDIRECT_CONTEXT context;
    SERVE_JOB job;
    HANDLE thread;
    SOCKET accepted;
    SOCKET probe;
    char sessionPem[4096];
    ULONG pemLength = 0;
    char response[1024];
    int ok;

    if (! StartUpstream(&upstream)) {
        StopUpstream(&upstream);
        return Require(0, "sni upstream start");
    }
    upstream.require_sni = TRUE;

    ca = CaptureCa_Create();
    if (! ca || CaptureCa_ExportPublicPem(
            ca, sessionPem, sizeof(sessionPem), &pemLength) != CAPTURE_CA_OK) {
        CaptureCa_Free(ca);
        StopUpstream(&upstream);
        return Require(0, "sni session CA");
    }

    context = MakeContext();
    context.original_port = upstream.port;
    memset(context.original_address, 0, sizeof(context.original_address));
    context.original_address[0] = 127;
    context.original_address[3] = 1;

    memset(&options, 0, sizeof(options));
    options.ca = ca;
    options.allow_unverified_upstream = TRUE;
    mitm = HttpsMitm_Listen(&options);
    if (! mitm) {
        CaptureCa_Free(ca);
        StopUpstream(&upstream);
        return Require(0, "sni MITM listen");
    }

    probe = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(HttpsMitm_ListenPort(mitm));
        if (probe == INVALID_SOCKET ||
                connect(probe, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            if (probe != INVALID_SOCKET)
                closesocket(probe);
            HttpsMitm_Close(mitm);
            CaptureCa_Free(ca);
            StopUpstream(&upstream);
            return Require(0, "sni client connect");
        }
    }
    accepted = HttpsMitm_Accept(mitm);
    if (accepted == INVALID_SOCKET) {
        closesocket(probe);
        HttpsMitm_Close(mitm);
        CaptureCa_Free(ca);
        StopUpstream(&upstream);
        return Require(0, "sni MITM accept");
    }
    memset(&job, 0, sizeof(job));
    job.mitm = mitm;
    job.client = accepted;
    job.context = context;
    job.have_context = 1;
    job.result = HTTPS_MITM_ERROR;
    thread = CreateThread(NULL, 0, ServeThread, &job, 0, NULL);
    if (! thread) {
        closesocket(probe);
        closesocket(accepted);
        HttpsMitm_Close(mitm);
        CaptureCa_Free(ca);
        StopUpstream(&upstream);
        return Require(0, "sni serve thread");
    }
    ok = ClientGetOnSocket(
        probe, sessionPem, TLS1_2_VERSION, TLS1_3_VERSION,
        response, sizeof(response));
    WaitForSingleObject(thread, 10000);
    CloseHandle(thread);
    HttpsMitm_Close(mitm);
    CaptureCa_Free(ca);
    StopUpstream(&upstream);
    return Require(ok, "client GET with forwarded SNI") &&
        Require(strstr(response, "upstream-ok") != NULL,
                "upstream required SNI and still answered") &&
        Require(job.result == HTTPS_MITM_OK, "ServeOnce ok with forwarded SNI");
}


int main(void)
{
    WSADATA wsa;
    int ok;

    OPENSSL_init_ssl(0, NULL);
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "FAILED: WSAStartup\n");
        return 1;
    }

    ok = TestCaPublicPemHasNoPrivateKey() &&
        TestImportPublicPemToDisposableStore() &&
        TestRemovePublicPemFromStore() &&
        TestImportPublicPemToMachineStoreIsBestEffort() &&
        TestLeafTrustedWithSessionCaExtraStore() &&
        TestPolicyRelaxClearsUntrustedRoot() &&
        TestOpenNamedRootsFromRegistry() &&
        TestTls13RoundTrip() &&
        TestTls12RoundTrip() &&
        TestChunkedResponse() &&
        TestKeepAliveRoundTrip() &&
        TestMissingContextRejected() &&
        TestQueryRedirectContextOnPlainSocketFails() &&
        TestServeOnceForwardsDownstreamSni() &&
        TestBrokerHttpsListenWritesHarAndPcapng();

    WSACleanup();
    if (! ok)
        return 1;
    printf("https mitm tests passed\n");
    return 0;
}
