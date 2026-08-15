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

#include "../SbieCapture/capture_ca.h"
#include "../SbieCapture/https_mitm.h"


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
        path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
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
            got = SSL_read(ssl, request, sizeof(request) - 1);
            if (got > 0)
                SSL_write(ssl, kResponse, (int)strlen(kResponse));
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
        TestTls13RoundTrip() &&
        TestTls12RoundTrip() &&
        TestMissingContextRejected();

    WSACleanup();
    if (! ok)
        return 1;
    printf("https mitm tests passed\n");
    return 0;
}
