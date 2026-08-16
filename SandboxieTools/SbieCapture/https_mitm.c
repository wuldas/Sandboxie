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

#include <mstcpip.h>

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


typedef struct _MITM_READER {

    SSL *ssl;
    char pending[HTTPS_MITM_IO_CAP];
    ULONG pending_len;

} MITM_READER;


/* Read one complete HTTP/1.1 message (header + body, chunked or content-length)
   from the reader's SSL connection. Leftover bytes beyond the message boundary
   are preserved in reader->pending for the next exchange. Returns 1 on success,
   0 on EOF / malformed input. */
static int HttpsMitm_ReadMessage(
    MITM_READER *reader,
    char *buffer,
    ULONG capacity,
    ULONG *msg_len,
    int isRequest,
    HTTP11_REQUEST *request,
    HTTP11_RESPONSE *response)
{
    ULONG used = 0;
    ULONG headerBytes = 0;
    ULONG contentLength = 0;
    ULONG bodyLength = 0;
    BOOL chunked = FALSE;
    int status;

    *msg_len = 0;
    if (reader->pending_len > 0) {
        if (reader->pending_len >= capacity)
            return 0;
        memcpy(buffer, reader->pending, reader->pending_len);
        used = reader->pending_len;
        buffer[used] = 0;
        reader->pending_len = 0;
    }
    else {
        buffer[0] = 0;
    }

    while (used < 4 || strstr(buffer, "\r\n\r\n") == NULL) {
        if (! HttpsMitm_SslReadSome(reader->ssl, buffer, capacity, &used))
            return 0;
    }

    if (isRequest) {
        status = Http11_ParseRequest((const UCHAR *)buffer, used, request);
        if (status != HTTP11_OK)
            return 0;
        headerBytes = request->header_bytes;
        contentLength = request->content_length;
        chunked = request->chunked;
    }
    else {
        status = Http11_ParseResponse((const UCHAR *)buffer, used, response);
        if (status != HTTP11_OK)
            return 0;
        headerBytes = response->header_bytes;
        contentLength = response->content_length;
        chunked = response->chunked;
    }

    if (chunked) {
        for (;;) {
            ULONG decoded = 0;
            ULONG total = 0;
            int r = Http11_DecodeChunked(
                (const UCHAR *)buffer, used, headerBytes, NULL, 0, &decoded, &total);
            if (r == HTTP11_OK) {
                bodyLength = total;
                break;
            }
            if (r == HTTP11_ERROR)
                return 0;
            if (! HttpsMitm_SslReadSome(reader->ssl, buffer, capacity, &used))
                return 0;
        }
    }
    else {
        bodyLength = contentLength;
        while (used < headerBytes + bodyLength) {
            if (! HttpsMitm_SslReadSome(reader->ssl, buffer, capacity, &used))
                return 0;
        }
    }

    /* preserve any bytes beyond this message for the next exchange */
    if (used > headerBytes + bodyLength) {
        ULONG leftover = used - (headerBytes + bodyLength);
        if (leftover >= capacity)
            return 0;
        memcpy(reader->pending, buffer + headerBytes + bodyLength, leftover);
        reader->pending_len = leftover;
    }
    *msg_len = headerBytes + bodyLength;
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


/* Case-insensitive token match within a comma-separated header value. */
static int HttpsMitm_HeaderHasToken(const char *value, const char *token)
{
    const char *cursor;
    size_t tokenLen;

    if (! value || ! token)
        return 0;
    tokenLen = strlen(token);
    cursor = value;
    while (*cursor) {
        while (*cursor == ' ' || *cursor == '\t' || *cursor == ',')
            ++cursor;
        if (! *cursor)
            break;
        if (_strnicmp(cursor, token, tokenLen) == 0) {
            char next = cursor[tokenLen];
            if (next == 0 || next == ',' || next == ' ' || next == '\t' ||
                    next == ';')
                return 1;
        }
        while (*cursor && *cursor != ',')
            ++cursor;
    }
    return 0;
}


/* RFC 6455 opening handshake: Upgrade + Connection tokens and a key. */
static int HttpsMitm_IsWebSocketUpgrade(const HTTP11_REQUEST *request)
{
    const HTTP11_HEADER *upgrade;
    const HTTP11_HEADER *connection;
    const HTTP11_HEADER *key;

    if (! request)
        return 0;
    upgrade = Http11_FindHeader(
        request->headers, request->header_count, "Upgrade");
    connection = Http11_FindHeader(
        request->headers, request->header_count, "Connection");
    key = Http11_FindHeader(
        request->headers, request->header_count, "Sec-WebSocket-Key");
    if (! upgrade || ! connection || ! key)
        return 0;
    if (_stricmp(upgrade->value, "websocket") != 0)
        return 0;
    return HttpsMitm_HeaderHasToken(connection->value, "upgrade");
}


/* Relay bytes bidirectionally between two established TLS connections until
   both sides reach EOF.  *bytesIn counts downstream->upstream traffic,
   *bytesOut counts upstream->downstream.  No WebSocket framing is decoded:
   this is a transparent byte tunnel. */
static void HttpsMitm_Tunnel(
    SSL *down,
    SSL *up,
    ULONG64 *bytesIn,
    ULONG64 *bytesOut)
{
    char buffer[HTTPS_MITM_IO_CAP];
    SOCKET downFd = (SOCKET)SSL_get_fd(down);
    SOCKET upFd = (SOCKET)SSL_get_fd(up);
    BOOL downEof = FALSE;
    BOOL upEof = FALSE;

    *bytesIn = 0;
    *bytesOut = 0;

    for (;;) {
        fd_set readSet;
        struct timeval timeout;
        int n;

        /* drain already-decrypted data without blocking on select() */
        if (! downEof && SSL_pending(down) > 0) {
            n = SSL_read(down, buffer, sizeof(buffer));
            if (n > 0) {
                if (! HttpsMitm_SslWriteAll(up, buffer, (ULONG)n))
                    return;
                *bytesIn += (ULONG64)n;
                continue;
            }
            downEof = TRUE;
        }
        if (! upEof && SSL_pending(up) > 0) {
            n = SSL_read(up, buffer, sizeof(buffer));
            if (n > 0) {
                if (! HttpsMitm_SslWriteAll(down, buffer, (ULONG)n))
                    return;
                *bytesOut += (ULONG64)n;
                continue;
            }
            upEof = TRUE;
        }

        if (downEof && upEof)
            break;

        FD_ZERO(&readSet);
        if (! downEof)
            FD_SET((u_int)downFd, &readSet);
        if (! upEof)
            FD_SET((u_int)upFd, &readSet);
        if (readSet.fd_count == 0)
            break;

        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        if (select(0, &readSet, NULL, NULL, &timeout) <= 0)
            continue;

        if (FD_ISSET((u_int)downFd, &readSet)) {
            n = SSL_read(down, buffer, sizeof(buffer));
            if (n > 0) {
                if (! HttpsMitm_SslWriteAll(up, buffer, (ULONG)n))
                    return;
                *bytesIn += (ULONG64)n;
            }
            else {
                downEof = TRUE;
            }
        }
        if (FD_ISSET((u_int)upFd, &readSet)) {
            n = SSL_read(up, buffer, sizeof(buffer));
            if (n > 0) {
                if (! HttpsMitm_SslWriteAll(down, buffer, (ULONG)n))
                    return;
                *bytesOut += (ULONG64)n;
            }
            else {
                upEof = TRUE;
            }
        }
    }
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
    ULONG responseSize,
    ULONG64 wsTunnelBytesIn,
    ULONG64 wsTunnelBytesOut)
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

    {
        char requestBodyScratch[HTTPS_MITM_IO_CAP];
        char responseBodyScratch[HTTPS_MITM_IO_CAP];

        /* request body: decode chunked framing for HAR, else raw slice */
        if (request->chunked) {
            ULONG decoded = 0;
            ULONG total = 0;
            if (Http11_DecodeChunked(
                    (const UCHAR *)requestBytes, requestSize,
                    request->header_bytes, (UCHAR *)requestBodyScratch,
                    sizeof(requestBodyScratch), &decoded, &total) == HTTP11_OK) {
                requestBody = requestBodyScratch;
                requestBodyLen = decoded;
            }
            else {
                requestBody = NULL;
                requestBodyLen = 0;
            }
        }
        else if (requestSize > request->header_bytes) {
            requestBody = requestBytes + request->header_bytes;
            requestBodyLen = requestSize - request->header_bytes;
        }
        else {
            requestBody = NULL;
            requestBodyLen = 0;
        }

        /* response body: decode chunked framing for HAR, else raw slice */
        if (response->chunked) {
            ULONG decoded = 0;
            ULONG total = 0;
            if (Http11_DecodeChunked(
                    (const UCHAR *)responseBytes, responseSize,
                    response->header_bytes, (UCHAR *)responseBodyScratch,
                    sizeof(responseBodyScratch), &decoded, &total) == HTTP11_OK) {
                responseBody = responseBodyScratch;
                responseBodyLen = decoded;
            }
            else {
                responseBody = NULL;
                responseBodyLen = 0;
            }
        }
        else if (responseSize > response->header_bytes) {
            responseBody = responseBytes + response->header_bytes;
            responseBodyLen = responseSize - response->header_bytes;
        }
        else {
            responseBody = NULL;
            responseBodyLen = 0;
        }
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
    exchange.request_body_original_len = request->chunked
        ? requestBodyLen : request->content_length;
    exchange.response_body = (const UCHAR *)responseBody;
    exchange.response_body_len = responseBodyLen;
    exchange.response_body_original_len = response->chunked
        ? responseBodyLen : response->content_length;
    exchange.body_cap = 64 * 1024;
    exchange.ws_tunnel_bytes_in = wsTunnelBytesIn;
    exchange.ws_tunnel_bytes_out = wsTunnelBytesOut;

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


int HttpsMitm_QueryRedirectContext(
    SOCKET client,
    HTTPS_REDIRECT_CONTEXT *context)
{
    ULONG ignored = 0;
    return HttpsMitm_QueryRedirectContextEx(client, context, &ignored);
}


static int HttpsMitm_IoctlTimed(
    SOCKET client,
    DWORD code,
    void *outBuf,
    DWORD outLen,
    DWORD *bytes,
    ULONG timeoutMs,
    ULONG *wsaError)
{
    WSAOVERLAPPED overlapped;
    DWORD localBytes = 0;
    DWORD flags = 0;
    HANDLE eventHandle;

    if (bytes)
        *bytes = 0;
    memset(&overlapped, 0, sizeof(overlapped));
    eventHandle = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (! eventHandle) {
        if (wsaError)
            *wsaError = GetLastError();
        return 0;
    }
    overlapped.hEvent = eventHandle;
    if (WSAIoctl(
            client, code, NULL, 0, outBuf, outLen, &localBytes,
            &overlapped, NULL) == 0) {
        if (bytes)
            *bytes = localBytes;
        CloseHandle(eventHandle);
        if (wsaError)
            *wsaError = 0;
        return 1;
    }
    if (WSAGetLastError() != WSA_IO_PENDING) {
        if (wsaError)
            *wsaError = (ULONG)WSAGetLastError();
        CloseHandle(eventHandle);
        return 0;
    }
    if (WaitForSingleObject(eventHandle, timeoutMs) != WAIT_OBJECT_0) {
        CancelIo((HANDLE)(ULONG_PTR)client);
        if (wsaError)
            *wsaError = WSAETIMEDOUT;
        CloseHandle(eventHandle);
        return 0;
    }
    if (! WSAGetOverlappedResult(
            client, &overlapped, &localBytes, FALSE, &flags)) {
        if (wsaError)
            *wsaError = (ULONG)WSAGetLastError();
        CloseHandle(eventHandle);
        return 0;
    }
    if (bytes)
        *bytes = localBytes;
    CloseHandle(eventHandle);
    if (wsaError)
        *wsaError = 0;
    return 1;
}


int HttpsMitm_QueryRedirectContextEx(
    SOCKET client,
    HTTPS_REDIRECT_CONTEXT *context,
    ULONG *wsaError)
{
    UCHAR stackBuf[512];
    UCHAR *buffer = stackBuf;
    DWORD bytes = 0;
    ULONG error = 0;
    int ok = 0;

    if (wsaError)
        *wsaError = WSAEINVAL;
    if (client == INVALID_SOCKET || ! context)
        return 0;
    memset(context, 0, sizeof(*context));
    if (! HttpsMitm_IoctlTimed(
            client, SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT,
            stackBuf, sizeof(stackBuf), &bytes, 300, &error)) {
        if (error == WSAENOBUFS && bytes > sizeof(stackBuf) && bytes < 8192) {
            buffer = (UCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytes);
            if (! buffer) {
                if (wsaError)
                    *wsaError = ERROR_NOT_ENOUGH_MEMORY;
                return 0;
            }
            if (! HttpsMitm_IoctlTimed(
                    client, SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT,
                    buffer, bytes, &bytes, 300, &error)) {
                HeapFree(GetProcessHeap(), 0, buffer);
                if (wsaError)
                    *wsaError = error;
                return 0;
            }
        }
        else {
            if (wsaError)
                *wsaError = error;
            return 0;
        }
    }
    if (bytes >= sizeof(*context) &&
            ((HTTPS_REDIRECT_CONTEXT *)buffer)->magic ==
                HTTPS_REDIRECT_CONTEXT_MAGIC) {
        memcpy(context, buffer, sizeof(*context));
        ok = 1;
        error = 0;
    }
    else if (wsaError && error == 0)
        error = WSAEINVAL;
    if (buffer != stackBuf)
        HeapFree(GetProcessHeap(), 0, buffer);
    if (wsaError)
        *wsaError = error;
    return ok;
}


static void HttpsMitm_ForwardRedirectRecords(SOCKET accepted, SOCKET upstream)
{
    UCHAR records[4096];
    DWORD bytes = 0;
    ULONG error = 0;

    if (accepted == INVALID_SOCKET || upstream == INVALID_SOCKET)
        return;
    if (! HttpsMitm_IoctlTimed(
            accepted, SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS,
            records, sizeof(records), &bytes, 300, &error) ||
            bytes == 0) {
        return;
    }
    WSAIoctl(
        upstream, SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS,
        records, bytes, NULL, 0, &bytes, NULL, NULL);
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
    HTTP11_REQUEST request;
    HTTP11_RESPONSE response;
    MITM_READER downReader;
    char host[64];
    const char *upstreamHost;
    USHORT upstreamPort;
    const char *sni;
    BOOL served = FALSE;
    int status = HTTPS_MITM_ERROR;

    if (! mitm || client == INVALID_SOCKET)
        return HTTPS_MITM_ERROR;
    if (! context || context->magic != HTTPS_REDIRECT_CONTEXT_MAGIC) {
        shutdown(client, SD_BOTH);
        return HTTPS_MITM_REJECTED;
    }
    if (mitm->have_expected &&
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

    /* resolve the upstream destination once for the whole connection */
    upstreamHost = mitm->upstream_host;
    upstreamPort = mitm->upstream_port;
    sni = SSL_get_servername(down, TLSEXT_NAMETYPE_host_name);
    if ((! upstreamHost[0] || upstreamPort == 0) && context) {
        HttpsMitm_FormatIpv4(context->original_address, host, sizeof(host));
        upstreamHost = host;
        if (upstreamPort == 0)
            upstreamPort = context->original_port;
    }

    memset(&downReader, 0, sizeof(downReader));
    downReader.ssl = down;

    for (;;) {
        MITM_READER upReader;
        ULONG requestSize = 0;
        ULONG responseSize = 0;
        BOOL isWebSocket;

        /* read one request from the downstream client (EOF ends keep-alive) */
        if (! HttpsMitm_ReadMessage(&downReader, requestBuf, sizeof(requestBuf),
                &requestSize, 1, &request, &response)) {
            break;
        }
        isWebSocket = HttpsMitm_IsWebSocketUpgrade(&request);

        /* open a fresh upstream connection for this request */
        upstream = HttpsMitm_ConnectTcp(upstreamHost, upstreamPort);
        if (upstream == INVALID_SOCKET)
            goto done;
        HttpsMitm_ForwardRedirectRecords(client, upstream);
        up = SSL_new(upCtx);
        if (! up)
            goto done;
        SSL_set_fd(up, (int)upstream);
        if (sni && sni[0])
            SSL_set_tlsext_host_name(up, sni);
        if (SSL_connect(up) != 1)
            goto done;

        /* forward the request upstream */
        if (! HttpsMitm_SslWriteAll(up, requestBuf, requestSize))
            goto done;

        /* read the response from upstream */
        memset(&upReader, 0, sizeof(upReader));
        upReader.ssl = up;
        if (! HttpsMitm_ReadMessage(&upReader, responseBuf, sizeof(responseBuf),
                &responseSize, 0, &request, &response)) {
            goto done;
        }

        /* forward the response downstream */
        if (! HttpsMitm_SslWriteAll(down, responseBuf, responseSize))
            goto done;

        if (isWebSocket && response.status == 101) {
            ULONG64 wsIn = 0;
            ULONG64 wsOut = 0;

            /* fold any bytes the readers already buffered past the handshake
               into the tunnel's byte accounting */
            if (downReader.pending_len > 0) {
                if (! HttpsMitm_SslWriteAll(
                        up, downReader.pending, downReader.pending_len)) {
                    goto done;
                }
                wsIn += downReader.pending_len;
                downReader.pending_len = 0;
            }
            if (upReader.pending_len > 0) {
                if (! HttpsMitm_SslWriteAll(
                        down, upReader.pending, upReader.pending_len)) {
                    goto done;
                }
                wsOut += upReader.pending_len;
                upReader.pending_len = 0;
            }

            /* switch to a transparent byte tunnel until both sides close */
            HttpsMitm_Tunnel(down, up, &wsIn, &wsOut);

            HttpsMitm_WriteHar(mitm, context, down, &request, &response,
                requestBuf, requestSize, responseBuf, responseSize, wsIn, wsOut);

            served = TRUE;
            break;   /* the tunneled connection is done; up/upstream are
                        released in the done: block */
        }

        /* record the exchange (best-effort) */
        HttpsMitm_WriteHar(mitm, context, down, &request, &response,
            requestBuf, requestSize, responseBuf, responseSize, 0, 0);

        served = TRUE;

        /* release this request's upstream connection */
        SSL_shutdown(up);
        SSL_free(up);
        up = NULL;
        closesocket(upstream);
        upstream = INVALID_SOCKET;
    }

    status = served ? HTTPS_MITM_OK : HTTPS_MITM_ERROR;

done:
    if (up) {
        SSL_shutdown(up);
        SSL_free(up);
    }
    if (upstream != INVALID_SOCKET)
        closesocket(upstream);
    if (down) {
        SSL_shutdown(down);
        SSL_free(down);
    }
    SSL_CTX_free(downCtx);
    SSL_CTX_free(upCtx);
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
