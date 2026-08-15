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
// HTTPS MITM listener
//---------------------------------------------------------------------------

#include "https_mitm.h"
#include "capture_ca_priv.h"
#include "har.h"
#include "http11.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define HTTPS_MITM_IO_CAP           65536


struct _HTTPS_MITM {

    SOCKET listen_socket;
    USHORT port;
    CAPTURE_CA *ca;
    HTTPS_REDIRECT_CONTEXT expected;
    BOOL have_expected;
    char upstream_host[64];
    USHORT upstream_port;
    char *upstream_ca_pem;
    WCHAR har_path[MAX_PATH];
    HAR_WRITER *har_writer;
    BOOL redact;
    BOOL include_bodies;
    BOOL allow_unverified_upstream;

};


static int HttpsMitm_ContextEqual(
    const HTTPS_REDIRECT_CONTEXT *left,
    const HTTPS_REDIRECT_CONTEXT *right)
{
    if (! left || ! right)
        return 0;
    return left->magic == right->magic &&
        left->version == right->version &&
        left->capture_id_high == right->capture_id_high &&
        left->capture_id_low == right->capture_id_low &&
        left->generation == right->generation;
}


static int HttpsMitm_SniCallback(SSL *ssl, int *alert, void *arg)
{
    CAPTURE_CA *ca = (CAPTURE_CA *)arg;
    const char *sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    X509 *leaf = NULL;
    EVP_PKEY *key = NULL;

    UNREFERENCED_PARAMETER(alert);
    if (! ca)
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    if (CaptureCa_MintLeaf(ca, sni, &leaf, &key) != CAPTURE_CA_OK)
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    if (SSL_use_certificate(ssl, leaf) != 1 ||
            SSL_use_PrivateKey(ssl, key) != 1) {
        X509_free(leaf);
        EVP_PKEY_free(key);
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    X509_free(leaf);
    EVP_PKEY_free(key);
    return SSL_TLSEXT_ERR_OK;
}


static int HttpsMitm_AlpnSelect(
    SSL *ssl,
    const unsigned char **out,
    unsigned char *outlen,
    const unsigned char *in,
    unsigned int inlen,
    void *arg)
{
    static const unsigned char kHttp11[] = {
        8, 'h', 't', 't', 'p', '/', '1', '.', '1'
    };
    unsigned char *selected = NULL;
    unsigned char selectedLen = 0;

    UNREFERENCED_PARAMETER(ssl);
    UNREFERENCED_PARAMETER(arg);
    if (SSL_select_next_proto(
            &selected, &selectedLen, kHttp11, sizeof(kHttp11), in, inlen) !=
            OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    *out = selected;
    *outlen = selectedLen;
    return SSL_TLSEXT_ERR_OK;
}


static SSL_CTX *HttpsMitm_NewDownstreamCtx(CAPTURE_CA *ca)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (! ctx)
        return NULL;
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_tlsext_servername_callback(ctx, HttpsMitm_SniCallback);
    SSL_CTX_set_tlsext_servername_arg(ctx, ca);
    SSL_CTX_set_alpn_select_cb(ctx, HttpsMitm_AlpnSelect, NULL);
    return ctx;
}


static SSL_CTX *HttpsMitm_NewUpstreamCtx(const char *caPem, BOOL allowUnverified)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    BIO *bio;
    X509 *cert;
    X509_STORE *store;

    if (! ctx)
        return NULL;
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    if (allowUnverified || ! caPem || ! caPem[0]) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        return ctx;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    bio = BIO_new_mem_buf(caPem, -1);
    cert = bio ? PEM_read_bio_X509(bio, NULL, NULL, NULL) : NULL;
    store = SSL_CTX_get_cert_store(ctx);
    if (! cert || X509_STORE_add_cert(store, cert) != 1) {
        X509_free(cert);
        BIO_free(bio);
        SSL_CTX_free(ctx);
        return NULL;
    }
    X509_free(cert);
    BIO_free(bio);
    return ctx;
}


static int HttpsMitm_SslReadSome(SSL *ssl, char *buffer, ULONG capacity, ULONG *used)
{
    int got;
    if (! ssl || ! buffer || capacity == 0 || ! used || *used >= capacity - 1)
        return 0;
    got = SSL_read(ssl, buffer + *used, (int)(capacity - 1 - *used));
    if (got <= 0)
        return 0;
    *used += (ULONG)got;
    buffer[*used] = 0;
    return 1;
}


static int HttpsMitm_ReadMessage(
    SSL *ssl,
    char *buffer,
    ULONG capacity,
    ULONG *used,
    int isRequest,
    HTTP11_REQUEST *request,
    HTTP11_RESPONSE *response)
{
    ULONG headerBytes = 0;
    ULONG contentLength = 0;
    int status;

    *used = 0;
    buffer[0] = 0;
    while (*used < 4 || strstr(buffer, "\r\n\r\n") == NULL) {
        if (! HttpsMitm_SslReadSome(ssl, buffer, capacity, used))
            return 0;
    }

    if (isRequest) {
        status = Http11_ParseRequest((const UCHAR *)buffer, *used, request);
        if (status != HTTP11_OK)
            return 0;
        headerBytes = request->header_bytes;
        contentLength = request->content_length;
    }
    else {
        status = Http11_ParseResponse((const UCHAR *)buffer, *used, response);
        if (status != HTTP11_OK)
            return 0;
        headerBytes = response->header_bytes;
        contentLength = response->content_length;
    }

    while (*used < headerBytes + contentLength) {
        if (! HttpsMitm_SslReadSome(ssl, buffer, capacity, used))
            return 0;
    }
    return 1;
}


static int HttpsMitm_SslWriteAll(SSL *ssl, const char *buffer, ULONG size)
{
    ULONG offset = 0;
    while (offset < size) {
        int wrote = SSL_write(ssl, buffer + offset, (int)(size - offset));
        if (wrote <= 0)
            return 0;
        offset += (ULONG)wrote;
    }
    return 1;
}


static SOCKET HttpsMitm_ConnectTcp(const char *host, USHORT port)
{
    SOCKET sock;
    struct sockaddr_in addr;

    if (! host || ! host[0] || port == 0)
        return INVALID_SOCKET;
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
        return INVALID_SOCKET;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        closesocket(sock);
        return INVALID_SOCKET;
    }
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        closesocket(sock);
        return INVALID_SOCKET;
    }
    return sock;
}


static void HttpsMitm_FormatIpv4(const UCHAR address[16], char *out, ULONG cap)
{
    sprintf_s(
        out, cap, "%u.%u.%u.%u",
        address[0], address[1], address[2], address[3]);
}


static int HttpsMitm_WriteHar(
    HTTPS_MITM *mitm,
    const HTTPS_REDIRECT_CONTEXT *context,
    SSL *downstream,
    const HTTP11_REQUEST *request,
    const HTTP11_RESPONSE *response,
    const char *requestBytes,
    ULONG requestSize,
    const char *responseBytes,
    ULONG responseSize)
{
    HAR_WRITER *writer;
    HAR_EXCHANGE exchange;
    const char *sni;
    const unsigned char *alpn = NULL;
    unsigned int alpnLen = 0;
    char alpnText[32];
    char serverIp[64];
    const char *requestBody;
    const char *responseBody;
    ULONG requestBodyLen = 0;
    ULONG responseBodyLen = 0;
    int status;

    if (! mitm->har_writer)
        return HTTPS_MITM_OK;

    writer = mitm->har_writer;

    sni = SSL_get_servername(downstream, TLSEXT_NAMETYPE_host_name);
    if (! sni)
        sni = "unknown";
    SSL_get0_alpn_selected(downstream, &alpn, &alpnLen);
    alpnText[0] = 0;
    if (alpn && alpnLen > 0 && alpnLen < sizeof(alpnText)) {
        memcpy(alpnText, alpn, alpnLen);
        alpnText[alpnLen] = 0;
    }
    HttpsMitm_FormatIpv4(context->original_address, serverIp, sizeof(serverIp));

    if (requestSize > request->header_bytes) {
        requestBody = requestBytes + request->header_bytes;
        requestBodyLen = requestSize - request->header_bytes;
    }
    else {
        requestBody = NULL;
    }
    if (responseSize > response->header_bytes) {
        responseBody = responseBytes + response->header_bytes;
        responseBodyLen = responseSize - response->header_bytes;
    }
    else {
        responseBody = NULL;
    }

    memset(&exchange, 0, sizeof(exchange));
    exchange.elapsed_ms = 1;
    exchange.request = request;
    exchange.response = response;
    exchange.sni_host = sni;
    exchange.server_ip = serverIp;
    exchange.process_id = context->process_id;
    exchange.session_id = context->session_id;
    exchange.process_create_time = context->process_create_time;
    exchange.tls_version = SSL_get_version(downstream);
    exchange.alpn = alpnText[0] ? alpnText : "http/1.1";
    exchange.redact = mitm->redact;
    exchange.include_bodies = mitm->include_bodies;
    exchange.request_body = (const UCHAR *)requestBody;
    exchange.request_body_len = requestBodyLen;
    exchange.request_body_original_len = request->content_length;
    exchange.response_body = (const UCHAR *)responseBody;
    exchange.response_body_len = responseBodyLen;
    exchange.response_body_original_len = response->content_length;
    exchange.body_cap = 64 * 1024;

    status = HarWriter_WriteExchange(writer, &exchange);
    return status == HAR_OK ? HTTPS_MITM_OK : HTTPS_MITM_ERROR;
}


HTTPS_MITM *HttpsMitm_Listen(const HTTPS_MITM_OPTIONS *options)
{
    HTTPS_MITM *mitm;
    struct sockaddr_in addr;
    int addrLen = sizeof(addr);

    if (! options || ! options->ca)
        return NULL;
    mitm = (HTTPS_MITM *)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*mitm));
    if (! mitm)
        return NULL;
    mitm->listen_socket = INVALID_SOCKET;
    mitm->ca = options->ca;
    if (options->expected_context) {
        mitm->expected = *options->expected_context;
        mitm->have_expected = TRUE;
    }
    if (options->upstream_host)
        strcpy_s(mitm->upstream_host, sizeof(mitm->upstream_host),
                 options->upstream_host);
    mitm->upstream_port = options->upstream_port;
    if (options->upstream_ca_pem) {
        size_t pemLen = strlen(options->upstream_ca_pem) + 1;
        mitm->upstream_ca_pem = (char *)malloc(pemLen);
        if (mitm->upstream_ca_pem)
            memcpy(mitm->upstream_ca_pem, options->upstream_ca_pem, pemLen);
    }
    if (options->har_path)
        wcscpy_s(mitm->har_path, MAX_PATH, options->har_path);
    mitm->redact = options->redact;
    mitm->include_bodies = options->include_bodies;
    mitm->allow_unverified_upstream = options->allow_unverified_upstream;
    if (options->har_file && options->har_file != INVALID_HANDLE_VALUE)
        mitm->har_writer = HarWriter_OpenHandle(options->har_file);
    else if (options->har_path && options->har_path[0])
        mitm->har_writer = HarWriter_OpenPath(options->har_path);

    mitm->listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (mitm->listen_socket == INVALID_SOCKET)
        goto fail;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(mitm->listen_socket, (struct sockaddr *)&addr, sizeof(addr)) != 0)
        goto fail;
    if (listen(mitm->listen_socket, 8) != 0)
        goto fail;
    if (getsockname(
            mitm->listen_socket, (struct sockaddr *)&addr, &addrLen) != 0)
        goto fail;
    mitm->port = ntohs(addr.sin_port);
    return mitm;

fail:
    HttpsMitm_Close(mitm);
    return NULL;
}


USHORT HttpsMitm_ListenPort(const HTTPS_MITM *mitm)
{
    return mitm ? mitm->port : 0;
}


SOCKET HttpsMitm_Accept(HTTPS_MITM *mitm)
{
    if (! mitm || mitm->listen_socket == INVALID_SOCKET)
        return INVALID_SOCKET;
    return accept(mitm->listen_socket, NULL, NULL);
}


SOCKET HttpsMitm_TryAccept(HTTPS_MITM *mitm, ULONG timeoutMs)
{
    fd_set readSet;
    struct timeval timeout;
    u_int listenSocket;

    if (! mitm || mitm->listen_socket == INVALID_SOCKET)
        return INVALID_SOCKET;
    listenSocket = (u_int)mitm->listen_socket;
    FD_ZERO(&readSet);
    FD_SET(listenSocket, &readSet);
    timeout.tv_sec = (long)(timeoutMs / 1000);
    timeout.tv_usec = (long)((timeoutMs % 1000) * 1000);
    if (select(0, &readSet, NULL, NULL, &timeout) <= 0)
        return INVALID_SOCKET;
    return accept(mitm->listen_socket, NULL, NULL);
}


int HttpsMitm_RecvContext(SOCKET client, HTTPS_REDIRECT_CONTEXT *context)
{
    ULONG got = 0;
    char *bytes;

    if (client == INVALID_SOCKET || ! context)
        return 0;
    bytes = (char *)context;
    memset(context, 0, sizeof(*context));
    while (got < sizeof(*context)) {
        int received = recv(client, bytes + got, (int)(sizeof(*context) - got), 0);
        if (received <= 0)
            return 0;
        got += (ULONG)received;
    }
    return 1;
}


int HttpsMitm_ServeOnce(
    HTTPS_MITM *mitm,
    SOCKET client,
    const HTTPS_REDIRECT_CONTEXT *context)
{
    SSL_CTX *downCtx = NULL;
    SSL_CTX *upCtx = NULL;
    SSL *down = NULL;
    SSL *up = NULL;
    SOCKET upstream = INVALID_SOCKET;
    char requestBuf[HTTPS_MITM_IO_CAP];
    char responseBuf[HTTPS_MITM_IO_CAP];
    ULONG requestSize = 0;
    ULONG responseSize = 0;
    HTTP11_REQUEST request;
    HTTP11_RESPONSE response;
    int status = HTTPS_MITM_ERROR;

    if (! mitm || client == INVALID_SOCKET)
        return HTTPS_MITM_ERROR;
    if (! mitm->have_expected ||
            ! HttpsMitm_ContextEqual(&mitm->expected, context)) {
        shutdown(client, SD_BOTH);
        return HTTPS_MITM_REJECTED;
    }

    downCtx = HttpsMitm_NewDownstreamCtx(mitm->ca);
    upCtx = HttpsMitm_NewUpstreamCtx(
        mitm->upstream_ca_pem, mitm->allow_unverified_upstream);
    if (! downCtx || ! upCtx)
        goto done;
    down = SSL_new(downCtx);
    if (! down)
        goto done;
    SSL_set_fd(down, (int)client);
    if (SSL_accept(down) != 1)
        goto done;

    {
        char host[64];
        const char *upstreamHost = mitm->upstream_host;
        USHORT upstreamPort = mitm->upstream_port;
        if ((! upstreamHost[0] || upstreamPort == 0) && context) {
            HttpsMitm_FormatIpv4(context->original_address, host, sizeof(host));
            upstreamHost = host;
            if (upstreamPort == 0)
                upstreamPort = context->original_port;
        }
        upstream = HttpsMitm_ConnectTcp(upstreamHost, upstreamPort);
    }
    if (upstream == INVALID_SOCKET)
        goto done;
    up = SSL_new(upCtx);
    if (! up)
        goto done;
    SSL_set_fd(up, (int)upstream);
    if (SSL_connect(up) != 1)
        goto done;

    if (! HttpsMitm_ReadMessage(
            down, requestBuf, sizeof(requestBuf), &requestSize, 1,
            &request, &response)) {
        goto done;
    }
    if (! HttpsMitm_SslWriteAll(up, requestBuf, requestSize))
        goto done;
    if (! HttpsMitm_ReadMessage(
            up, responseBuf, sizeof(responseBuf), &responseSize, 0,
            &request, &response)) {
        goto done;
    }
    if (! HttpsMitm_SslWriteAll(down, responseBuf, responseSize))
        goto done;

    status = HttpsMitm_WriteHar(
        mitm, context, down, &request, &response,
        requestBuf, requestSize, responseBuf, responseSize);

done:
    if (down) {
        SSL_shutdown(down);
        SSL_free(down);
    }
    if (up) {
        SSL_shutdown(up);
        SSL_free(up);
    }
    SSL_CTX_free(downCtx);
    SSL_CTX_free(upCtx);
    if (upstream != INVALID_SOCKET)
        closesocket(upstream);
    return status;
}


void HttpsMitm_Close(HTTPS_MITM *mitm)
{
    if (! mitm)
        return;
    if (mitm->listen_socket != INVALID_SOCKET)
        closesocket(mitm->listen_socket);
    if (mitm->har_writer)
        HarWriter_Close(mitm->har_writer);
    free(mitm->upstream_ca_pem);
    HeapFree(GetProcessHeap(), 0, mitm);
}
