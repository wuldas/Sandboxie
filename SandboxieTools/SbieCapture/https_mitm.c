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
#include "hpack.h"
#include "http2.h"
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
    HANDLE keylog_file;
    CRITICAL_SECTION keylog_lock;
    int have_keylog;

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
    static const unsigned char kProtocols[] = {
        2, 'h', '2',
        8, 'h', 't', 't', 'p', '/', '1', '.', '1'
    };
    unsigned char *selected = NULL;
    unsigned char selectedLen = 0;

    UNREFERENCED_PARAMETER(ssl);
    UNREFERENCED_PARAMETER(arg);
    if (SSL_select_next_proto(
            &selected, &selectedLen, kProtocols, sizeof(kProtocols), in, inlen) !=
            OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    *out = selected;
    *outlen = selectedLen;
    return SSL_TLSEXT_ERR_OK;
}


/* TLS key-log: emit "CLIENT_RANDOM <client_random> <master_secret>" lines to a
   caller-opened file so Wireshark can decrypt the captured PCAPNG.  Opt-in only
   -- no lines are written unless the session was started with a key-log handle. */
static int g_keylog_ex_index = -1;

static void HttpsMitm_InitKeylogIndex(void)
{
    int idx;

    if (g_keylog_ex_index >= 0)
        return;
    idx = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    if (idx >= 0)
        InterlockedCompareExchange((LONG *)&g_keylog_ex_index, idx, -1);
}


static void HttpsMitm_KeylogCallback(const SSL *ssl, const char *line)
{
    HTTPS_MITM *mitm;
    char text[512];
    DWORD written;
    int len;

    if (g_keylog_ex_index < 0 || ! ssl || ! line || ! line[0])
        return;
    mitm = (HTTPS_MITM *)SSL_get_ex_data(ssl, g_keylog_ex_index);
    if (! mitm || ! mitm->have_keylog ||
            ! mitm->keylog_file || mitm->keylog_file == INVALID_HANDLE_VALUE)
        return;
    len = sprintf_s(text, sizeof(text), "%s\n", line);
    if (len <= 0)
        return;
    EnterCriticalSection(&mitm->keylog_lock);
    WriteFile(mitm->keylog_file, text, (DWORD)len, &written, NULL);
    LeaveCriticalSection(&mitm->keylog_lock);
}


/* associate a freshly-created SSL with its MITM so the key-log callback can
   find the file handle (key-log is opt-in; a no-op otherwise). */
static void HttpsMitm_AttachKeylog(HTTPS_MITM *mitm, SSL *ssl)
{
    if (! mitm || ! ssl || g_keylog_ex_index < 0)
        return;
    SSL_set_ex_data(ssl, g_keylog_ex_index, mitm);
}


static SSL_CTX *HttpsMitm_NewDownstreamCtx(CAPTURE_CA *ca)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (! ctx)
        return NULL;
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_keylog_callback(ctx, HttpsMitm_KeylogCallback);
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
    SSL_CTX_set_keylog_callback(ctx, HttpsMitm_KeylogCallback);
    {
        /* offer h2 first so an h2-capable origin uses it (Slice 6) */
        static const unsigned char kUpstreamAlpn[] = {
            2, 'h', '2',
            8, 'h', 't', 't', 'p', '/', '1', '.', '1'
        };
        SSL_CTX_set_alpn_protos(ctx, kUpstreamAlpn, sizeof(kUpstreamAlpn));
    }
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


/* Extra per-exchange metadata the broker records alongside the HAR entry. */
typedef struct _MITM_HAR_META {

    ULONG64 ws_tunnel_bytes_in;
    ULONG64 ws_tunnel_bytes_out;
    ULONG stream_id;
    const char *grpc_status;
    const char *grpc_message;
    ULONG grpc_message_count;

} MITM_HAR_META;


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
    const MITM_HAR_META *meta)
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
    if (meta) {
        exchange.ws_tunnel_bytes_in = meta->ws_tunnel_bytes_in;
        exchange.ws_tunnel_bytes_out = meta->ws_tunnel_bytes_out;
        exchange.stream_id = meta->stream_id;
        exchange.grpc_status = meta->grpc_status;
        exchange.grpc_message = meta->grpc_message;
        exchange.grpc_message_count = meta->grpc_message_count;
    }

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
    if (options->keylog_file &&
            options->keylog_file != INVALID_HANDLE_VALUE) {
        mitm->keylog_file = options->keylog_file;
        mitm->have_keylog = 1;
        InitializeCriticalSection(&mitm->keylog_lock);
        HttpsMitm_InitKeylogIndex();
    }
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


//---------------------------------------------------------------------------
// HTTP/2 downstream termination -> HTTP/1.1 upstream relay
//---------------------------------------------------------------------------

#define HTTP2_RELAY_BODY_CAP    (64 * 1024)

typedef struct _H2_RELAY_STREAM {

    BOOL active;
    ULONG stream_id;
    char method[HTTP11_MAX_METHOD];
    char target[HTTP11_MAX_TARGET];
    char authority[HTTP11_MAX_TARGET];
    HTTP11_HEADER headers[HTTP11_MAX_HEADERS];
    ULONG header_count;
    UCHAR body[HTTP2_RELAY_BODY_CAP];
    ULONG body_len;
    BOOL have_request;

} H2_RELAY_STREAM;


static H2_RELAY_STREAM *HttpsMitm_H2GetStream(
    H2_RELAY_STREAM *streams,
    ULONG stream_id)
{
    ULONG i;

    for (i = 0; i < HTTP2_MAX_STREAMS; ++i) {
        if (streams[i].active && streams[i].stream_id == stream_id)
            return &streams[i];
    }
    for (i = 0; i < HTTP2_MAX_STREAMS; ++i) {
        if (! streams[i].active) {
            memset(&streams[i], 0, sizeof(streams[i]));
            streams[i].active = TRUE;
            streams[i].stream_id = stream_id;
            return &streams[i];
        }
    }
    return NULL;
}


static void HttpsMitm_H2Lower(char *s)
{
    while (*s) {
        if (*s >= 'A' && *s <= 'Z')
            *s = (char)(*s - 'A' + 'a');
        ++s;
    }
}


/* connection-specific headers that must not be forwarded over h2
   (RFC 7540 8.1.2.2). */
static int HttpsMitm_H2IsConnectionHeader(const char *name)
{
    static const char *const kSkip[] = {
        "connection", "keep-alive", "proxy-connection", "transfer-encoding",
        "upgrade", "te"
    };
    ULONG i;

    for (i = 0; i < ARRAYSIZE(kSkip); ++i) {
        if (_stricmp(name, kSkip[i]) == 0)
            return 1;
    }
    return 0;
}


static int HttpsMitm_H2WriteFrame(
    SSL *ssl,
    UCHAR type,
    UCHAR flags,
    ULONG stream_id,
    const UCHAR *payload,
    ULONG payload_len)
{
    UCHAR header[HTTP2_FRAME_HEADER_LEN];
    HTTP2_FRAME_HEADER fh;

    fh.length = payload_len;
    fh.type = type;
    fh.flags = flags;
    fh.stream_id = stream_id;
    if (Http2_WriteFrameHeader(header, sizeof(header), &fh) != HTTP2_OK)
        return 0;
    if (! HttpsMitm_SslWriteAll(ssl, (const char *)header, sizeof(header)))
        return 0;
    if (payload_len > 0 &&
            ! HttpsMitm_SslWriteAll(ssl, (const char *)payload, payload_len))
        return 0;
    return 1;
}


static int HttpsMitm_H2ReadFrame(
    SSL *ssl,
    HTTP2_FRAME_HEADER *fh,
    UCHAR *payload,
    ULONG payload_cap)
{
    UCHAR header[HTTP2_FRAME_HEADER_LEN];
    ULONG got = 0;
    int n;

    while (got < HTTP2_FRAME_HEADER_LEN) {
        n = SSL_read(ssl, header + got, (int)(HTTP2_FRAME_HEADER_LEN - got));
        if (n <= 0)
            return 0;
        got += (ULONG)n;
    }
    if (Http2_ParseFrameHeader(header, got, fh) != HTTP2_OK)
        return 0;
    if (fh->length > payload_cap)
        return 0;
    got = 0;
    while (got < fh->length) {
        n = SSL_read(ssl, payload + got, (int)(fh->length - got));
        if (n <= 0)
            return 0;
        got += (ULONG)n;
    }
    return 1;
}


static int HttpsMitm_H2SendSettings(SSL *ssl)
{
    return HttpsMitm_H2WriteFrame(ssl, HTTP2_FRAME_SETTINGS, 0, 0, NULL, 0);
}


static int HttpsMitm_H2SendSettingsAck(SSL *ssl)
{
    return HttpsMitm_H2WriteFrame(
        ssl, HTTP2_FRAME_SETTINGS, HTTP2_FLAG_ACK, 0, NULL, 0);
}


static int HttpsMitm_H2SendPingAck(SSL *ssl, const UCHAR *payload)
{
    return HttpsMitm_H2WriteFrame(
        ssl, HTTP2_FRAME_PING, HTTP2_FLAG_ACK, 0, payload, 8);
}


static int HttpsMitm_H2SendGoAway(SSL *ssl, ULONG last_stream, ULONG error)
{
    UCHAR payload[8];

    payload[0] = (UCHAR)(last_stream >> 24);
    payload[1] = (UCHAR)(last_stream >> 16);
    payload[2] = (UCHAR)(last_stream >> 8);
    payload[3] = (UCHAR)last_stream;
    payload[4] = (UCHAR)(error >> 24);
    payload[5] = (UCHAR)(error >> 16);
    payload[6] = (UCHAR)(error >> 8);
    payload[7] = (UCHAR)error;
    return HttpsMitm_H2WriteFrame(
        ssl, HTTP2_FRAME_GOAWAY, 0, 0, payload, sizeof(payload));
}


/* Decode a complete h2 header block into a logical request (pseudo-headers
   become method/target/authority; regular headers are kept, connection-
   specific ones dropped). */
static int HttpsMitm_H2DecodeRequest(
    HPACK_DECODER *decoder,
    const UCHAR *block,
    ULONG block_len,
    H2_RELAY_STREAM *stream)
{
    HPACK_HEADER *headers;
    ULONG count = 0;
    ULONG consumed = 0;
    ULONG i;
    ULONG header_count = 0;

    /* HPACK_HEADER is ~4 KB; a 128-entry array is too large for the stack. */
    headers = (HPACK_HEADER *)malloc(HPACK_MAX_HEADERS * sizeof(*headers));
    if (! headers)
        return 0;
    if (Hpack_DecodeBlock(decoder, block, block_len,
            headers, HPACK_MAX_HEADERS, &count, &consumed) != HPACK_OK) {
        free(headers);
        return 0;
    }

    stream->method[0] = 0;
    stream->target[0] = 0;
    stream->authority[0] = 0;
    stream->header_count = 0;
    stream->body_len = 0;

    for (i = 0; i < count; ++i) {
        const char *name = headers[i].name;
        const char *value = headers[i].value;

        if (name[0] == ':') {
            if (_stricmp(name, ":method") == 0)
                strcpy_s(stream->method, sizeof(stream->method), value);
            else if (_stricmp(name, ":path") == 0)
                strcpy_s(stream->target, sizeof(stream->target), value);
            else if (_stricmp(name, ":authority") == 0)
                strcpy_s(stream->authority, sizeof(stream->authority), value);
            continue;   /* :scheme and any other pseudo-header are ignored */
        }
        if (HttpsMitm_H2IsConnectionHeader(name))
            continue;
        if (header_count >= HTTP11_MAX_HEADERS)
            continue;
        strcpy_s(stream->headers[header_count].name,
                 sizeof(stream->headers[header_count].name), name);
        strcpy_s(stream->headers[header_count].value,
                 sizeof(stream->headers[header_count].value), value);
        ++header_count;
    }
    stream->header_count = header_count;
    stream->have_request = TRUE;
    free(headers);
    return 1;
}


/* Rebuild an HTTP/1.1 request (request line + Host + headers + body) from a
   translated h2 request. */
static int HttpsMitm_H2BuildH1Request(
    const H2_RELAY_STREAM *stream,
    char *out,
    ULONG cap,
    ULONG *out_len)
{
    ULONG pos = 0;
    ULONG i;
    int n;

    n = sprintf_s(out, cap, "%s %s HTTP/1.1\r\n",
                  stream->method[0] ? stream->method : "GET",
                  stream->target[0] ? stream->target : "/");
    if (n < 0)
        return 0;
    pos = (ULONG)n;

    if (stream->authority[0]) {
        n = sprintf_s(out + pos, cap - pos, "Host: %s\r\n", stream->authority);
        if (n < 0)
            return 0;
        pos += (ULONG)n;
    }
    for (i = 0; i < stream->header_count; ++i) {
        n = sprintf_s(out + pos, cap - pos, "%s: %s\r\n",
                      stream->headers[i].name, stream->headers[i].value);
        if (n < 0)
            return 0;
        pos += (ULONG)n;
    }
    if (stream->body_len > 0) {
        n = sprintf_s(out + pos, cap - pos, "Content-Length: %lu\r\n",
                      stream->body_len);
        if (n < 0)
            return 0;
        pos += (ULONG)n;
    }
    if (pos + 2 > cap)
        return 0;
    out[pos++] = '\r';
    out[pos++] = '\n';
    if (stream->body_len > 0) {
        if (pos + stream->body_len > cap)
            return 0;
        memcpy(out + pos, stream->body, stream->body_len);
        pos += stream->body_len;
    }
    *out_len = pos;
    return 1;
}


static int HttpsMitm_H2EncodeOne(
    HPACK_ENCODER *encoder,
    const char *name,
    const char *value,
    UCHAR *block,
    ULONG block_cap,
    ULONG *block_len)
{
    UCHAR tmp[HPACK_MAX_VALUE * 2 + 64];
    ULONG n = 0;

    if (Hpack_EncodeHeader(encoder, name, value, tmp, sizeof(tmp), &n) !=
            HPACK_OK)
        return 0;
    if (*block_len + n > block_cap)
        return 0;
    memcpy(block + *block_len, tmp, n);
    *block_len += n;
    return 1;
}


/* Translate an HTTP/1.1 response into downstream h2 HEADERS + DATA frames. */
static int HttpsMitm_H2SendResponse(
    SSL *down,
    HPACK_ENCODER *encoder,
    ULONG stream_id,
    const HTTP11_RESPONSE *response,
    const char *responseBytes,
    ULONG responseSize)
{
    UCHAR block[HTTP2_MAX_HEADER_BLOCK];
    ULONG block_len = 0;
    char status[16];
    const UCHAR *body = NULL;
    ULONG body_len = 0;
    UCHAR *heapBody = NULL;
    ULONG i;
    int ok = 0;

    sprintf_s(status, sizeof(status), "%lu", response->status);
    if (! HttpsMitm_H2EncodeOne(encoder, ":status", status,
            block, sizeof(block), &block_len))
        goto done;

    for (i = 0; i < response->header_count; ++i) {
        char name[HTTP11_MAX_NAME];
        strcpy_s(name, sizeof(name), response->headers[i].name);
        HttpsMitm_H2Lower(name);
        if (HttpsMitm_H2IsConnectionHeader(name))
            continue;
        if (! HttpsMitm_H2EncodeOne(encoder, name, response->headers[i].value,
                block, sizeof(block), &block_len))
            goto done;
    }

    if (response->chunked) {
        ULONG decoded = 0;
        ULONG total = 0;
        heapBody = (UCHAR *)malloc(HTTPS_MITM_IO_CAP);
        if (! heapBody)
            goto done;
        if (Http11_DecodeChunked((const UCHAR *)responseBytes, responseSize,
                response->header_bytes, heapBody, HTTPS_MITM_IO_CAP,
                &decoded, &total) == HTTP11_OK) {
            body = heapBody;
            body_len = decoded;
        }
    }
    else if (responseSize > response->header_bytes) {
        body = (const UCHAR *)responseBytes + response->header_bytes;
        body_len = responseSize - response->header_bytes;
    }

    if (! HttpsMitm_H2WriteFrame(down, HTTP2_FRAME_HEADERS,
            (UCHAR)(body_len == 0
                ? HTTP2_FLAG_END_HEADERS | HTTP2_FLAG_END_STREAM
                : HTTP2_FLAG_END_HEADERS),
            stream_id, block, block_len))
        goto done;

    if (body_len > 0 &&
            ! HttpsMitm_H2WriteFrame(down, HTTP2_FRAME_DATA,
                HTTP2_FLAG_END_STREAM, stream_id, body, body_len))
        goto done;

    ok = 1;

done:
    free(heapBody);
    return ok;
}


/* Count complete gRPC messages in a length-prefixed body (1-byte compressed
   flag + 4-byte big-endian length per message, repeated). */
static ULONG HttpsMitm_GrpcMessageCount(const UCHAR *data, ULONG len)
{
    ULONG pos = 0;
    ULONG count = 0;

    while (pos + 5 <= len) {
        ULONG msgLen = ((ULONG)data[pos + 1] << 24) |
                       ((ULONG)data[pos + 2] << 16) |
                       ((ULONG)data[pos + 3] << 8) |
                       data[pos + 4];
        pos += 5;
        if (msgLen > len - pos)
            break;   /* truncated message */
        pos += msgLen;
        ++count;
    }
    return count;
}


/* Returns TRUE when the request is a gRPC call (content-type: application/grpc). */
static int HttpsMitm_IsGrpc(const H2_RELAY_STREAM *stream)
{
    const HTTP11_HEADER *ct = Http11_FindHeader(
        stream->headers, stream->header_count, "content-type");

    if (! ct)
        return 0;
    return _strnicmp(ct->value, "application/grpc", 16) == 0;
}


/* Build an HTTP/1.1-shaped response struct from decoded h2 response headers
   (for HAR).  header_bytes stays 0; the body is passed separately. */
static void HttpsMitm_H2BuildH1Response(
    const HPACK_HEADER *headers,
    ULONG count,
    ULONG status,
    HTTP11_RESPONSE *out)
{
    ULONG i;
    ULONG hc = 0;

    memset(out, 0, sizeof(*out));
    strcpy_s(out->version, sizeof(out->version), "HTTP/2");
    out->status = status;
    strcpy_s(out->reason, sizeof(out->reason), "OK");
    for (i = 0; i < count; ++i) {
        if (headers[i].name[0] == ':')
            continue;   /* pseudo-headers */
        if (HttpsMitm_H2IsConnectionHeader(headers[i].name))
            continue;
        if (hc >= HTTP11_MAX_HEADERS)
            continue;
        strcpy_s(out->headers[hc].name,
                 sizeof(out->headers[hc].name), headers[i].name);
        strcpy_s(out->headers[hc].value,
                 sizeof(out->headers[hc].value), headers[i].value);
        ++hc;
    }
    out->header_count = hc;
    out->content_length = 0;
    out->chunked = FALSE;
}


/* Decode one h2 header block into a heap array (caller frees). */
static HPACK_HEADER *HttpsMitm_H2DecodeHeaders(
    HPACK_DECODER *decoder,
    const UCHAR *block,
    ULONG block_len,
    ULONG *out_count)
{
    HPACK_HEADER *headers = (HPACK_HEADER *)malloc(
        HPACK_MAX_HEADERS * sizeof(*headers));
    ULONG count = 0;
    ULONG consumed = 0;

    if (! headers)
        return NULL;
    if (Hpack_DecodeBlock(decoder, block, block_len, headers,
            HPACK_MAX_HEADERS, &count, &consumed) != HPACK_OK) {
        free(headers);
        return NULL;
    }
    *out_count = count;
    return headers;
}


static const char *HttpsMitm_H2FindHeaderValue(
    const HPACK_HEADER *headers,
    ULONG count,
    const char *name)
{
    ULONG i;

    for (i = 0; i < count; ++i) {
        if (_stricmp(headers[i].name, name) == 0)
            return headers[i].value;
    }
    return NULL;
}


/* Fill an HTTP/1.1-shaped request struct directly from a translated h2 stream
   (no h1 bytes are built; the body is passed to the HAR separately). */
static void HttpsMitm_H2BuildH1RequestStruct(
    const H2_RELAY_STREAM *stream,
    HTTP11_REQUEST *out)
{
    ULONG i;

    memset(out, 0, sizeof(*out));
    strcpy_s(out->method, sizeof(out->method),
             stream->method[0] ? stream->method : "GET");
    strcpy_s(out->target, sizeof(out->target),
             stream->target[0] ? stream->target : "/");
    strcpy_s(out->version, sizeof(out->version), "HTTP/2");
    for (i = 0; i < stream->header_count && i < HTTP11_MAX_HEADERS; ++i) {
        strcpy_s(out->headers[i].name, sizeof(out->headers[i].name),
                 stream->headers[i].name);
        strcpy_s(out->headers[i].value, sizeof(out->headers[i].value),
                 stream->headers[i].value);
    }
    out->header_count = stream->header_count;
    out->content_length = stream->body_len;
    out->chunked = FALSE;
}


/* Relay one completed downstream h2 stream over an HTTP/2 upstream leg.  The
   upstream TLS connection is already established and negotiated "h2". */
static int HttpsMitm_H2RelayStreamH2(
    HTTPS_MITM *mitm,
    SSL *down,
    SSL *up,
    const HTTPS_REDIRECT_CONTEXT *context,
    HPACK_ENCODER *downEncoder,
    H2_RELAY_STREAM *stream)
{
    HTTP2_SESSION upSession;
    HPACK_ENCODER upEncoder;
    HPACK_DECODER upDecoder;
    UCHAR payload[HTTP2_MAX_HEADER_BLOCK];
    UCHAR reqBlock[HTTP2_MAX_HEADER_BLOCK];
    ULONG reqBlockLen = 0;
    HPACK_HEADER *respHeaders = NULL;
    ULONG respHeaderCount = 0;
    UCHAR *respBody = NULL;
    ULONG respBodyLen = 0;
    char grpcStatus[32];
    char grpcMessage[256];
    ULONG grpcMsgCount = 0;
    ULONG respStatus = 0;
    BOOL isGrpc;
    BOOL gotInitialHeaders = FALSE;
    int ok = 0;
    ULONG i;

    grpcStatus[0] = 0;
    grpcMessage[0] = 0;
    isGrpc = HttpsMitm_IsGrpc(stream);

    Http2_SessionInit(&upSession);
    Hpack_EncoderInit(&upEncoder, HTTP2_DEFAULT_HEADER_TABLE_SIZE, FALSE);
    Hpack_DecoderInit(&upDecoder, HTTP2_DEFAULT_HEADER_TABLE_SIZE);

    /* 1. client preface + SETTINGS */
    {
        static const char kMagic[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        if (! HttpsMitm_SslWriteAll(up, kMagic, (ULONG)strlen(kMagic)))
            goto done;
        if (! HttpsMitm_H2WriteFrame(up, HTTP2_FRAME_SETTINGS, 0, 0, NULL, 0))
            goto done;
    }

    /* 2. request HEADERS + DATA on stream 1 */
    if (! HttpsMitm_H2EncodeOne(&upEncoder, ":method",
            stream->method[0] ? stream->method : "GET",
            reqBlock, sizeof(reqBlock), &reqBlockLen) ||
            ! HttpsMitm_H2EncodeOne(&upEncoder, ":scheme", "https",
                reqBlock, sizeof(reqBlock), &reqBlockLen) ||
            ! HttpsMitm_H2EncodeOne(&upEncoder, ":path",
                stream->target[0] ? stream->target : "/",
                reqBlock, sizeof(reqBlock), &reqBlockLen) ||
            ! HttpsMitm_H2EncodeOne(&upEncoder, ":authority",
                stream->authority[0] ? stream->authority : "example.com",
                reqBlock, sizeof(reqBlock), &reqBlockLen))
        goto done;
    for (i = 0; i < stream->header_count; ++i) {
        if (! HttpsMitm_H2EncodeOne(&upEncoder,
                stream->headers[i].name, stream->headers[i].value,
                reqBlock, sizeof(reqBlock), &reqBlockLen))
            goto done;
    }
    {
        UCHAR flags = (UCHAR)(stream->body_len == 0
            ? HTTP2_FLAG_END_HEADERS | HTTP2_FLAG_END_STREAM
            : HTTP2_FLAG_END_HEADERS);
        if (! HttpsMitm_H2WriteFrame(up, HTTP2_FRAME_HEADERS, flags, 1,
                reqBlock, reqBlockLen))
            goto done;
    }
    if (stream->body_len > 0 &&
            ! HttpsMitm_H2WriteFrame(up, HTTP2_FRAME_DATA,
                HTTP2_FLAG_END_STREAM, 1, stream->body, stream->body_len))
        goto done;

    /* 3. read the upstream response until END_STREAM */
    respBody = (UCHAR *)malloc(HTTPS_MITM_IO_CAP);
    if (! respBody)
        goto done;
    {
        BOOL doneReading = FALSE;

        while (! doneReading) {
            HTTP2_FRAME_HEADER fh;
            HTTP2_FRAME_RESULT result;
            int rc;

            if (! HttpsMitm_H2ReadFrame(up, &fh, payload, sizeof(payload)))
                goto done;

            rc = Http2_ProcessFrame(&upSession, &fh, payload, &result);
            if (rc != HTTP2_OK)
                goto done;

            switch (fh.type) {
            case HTTP2_FRAME_SETTINGS:
                if (! (fh.flags & HTTP2_FLAG_ACK))
                    HttpsMitm_H2WriteFrame(
                        up, HTTP2_FRAME_SETTINGS, HTTP2_FLAG_ACK, 0, NULL, 0);
                break;
            case HTTP2_FRAME_PING:
                if (! (fh.flags & HTTP2_FLAG_ACK))
                    HttpsMitm_H2WriteFrame(
                        up, HTTP2_FRAME_PING, HTTP2_FLAG_ACK, 0, payload, 8);
                break;
            case HTTP2_FRAME_HEADERS:
                if (fh.flags & HTTP2_FLAG_END_HEADERS) {
                    if (! gotInitialHeaders) {
                        respHeaders = HttpsMitm_H2DecodeHeaders(
                            &upDecoder, payload, fh.length, &respHeaderCount);
                        if (! respHeaders)
                            goto done;
                        {
                            const char *st = HttpsMitm_H2FindHeaderValue(
                                respHeaders, respHeaderCount, ":status");
                            if (st)
                                respStatus = (ULONG)strtoul(st, NULL, 10);
                        }
                        gotInitialHeaders = TRUE;
                    }
                    else {
                        /* trailers (gRPC): grpc-status / grpc-message */
                        HPACK_HEADER *tr = HttpsMitm_H2DecodeHeaders(
                            &upDecoder, payload, fh.length, &respHeaderCount);
                        if (tr) {
                            const char *gs = HttpsMitm_H2FindHeaderValue(
                                tr, respHeaderCount, "grpc-status");
                            const char *gm = HttpsMitm_H2FindHeaderValue(
                                tr, respHeaderCount, "grpc-message");
                            if (gs)
                                strcpy_s(grpcStatus, sizeof(grpcStatus), gs);
                            if (gm)
                                strcpy_s(grpcMessage, sizeof(grpcMessage), gm);
                            free(tr);
                        }
                    }
                }
                if (fh.flags & HTTP2_FLAG_END_STREAM)
                    doneReading = TRUE;
                break;
            case HTTP2_FRAME_DATA:
                if (fh.length > 0 &&
                        respBodyLen + fh.length <= HTTPS_MITM_IO_CAP) {
                    memcpy(respBody + respBodyLen, payload, fh.length);
                    respBodyLen += fh.length;
                }
                if (fh.flags & HTTP2_FLAG_END_STREAM)
                    doneReading = TRUE;
                break;
            case HTTP2_FRAME_GOAWAY:
                doneReading = TRUE;
                break;
            default:
                break;
            }
        }
    }

    if (isGrpc)
        grpcMsgCount = HttpsMitm_GrpcMessageCount(respBody, respBodyLen);

    /* 4. forward the response downstream */
    {
        UCHAR block[HTTP2_MAX_HEADER_BLOCK];
        ULONG blockLen = 0;
        char status[16];
        BOOL hasBody = respBodyLen > 0;
        BOOL hasTrailers = grpcStatus[0] != 0;

        sprintf_s(status, sizeof(status), "%lu", respStatus ? respStatus : 200);
        if (! HttpsMitm_H2EncodeOne(downEncoder, ":status", status,
                block, sizeof(block), &blockLen))
            goto done;
        for (i = 0; i < respHeaderCount; ++i) {
            char name[HTTP11_MAX_NAME];
            if (respHeaders[i].name[0] == ':')
                continue;
            if (HttpsMitm_H2IsConnectionHeader(respHeaders[i].name))
                continue;
            strcpy_s(name, sizeof(name), respHeaders[i].name);
            HttpsMitm_H2Lower(name);
            if (! HttpsMitm_H2EncodeOne(downEncoder, name,
                    respHeaders[i].value, block, sizeof(block), &blockLen))
                goto done;
        }

        {
            UCHAR flags = HTTP2_FLAG_END_HEADERS;
            if (! hasBody && ! hasTrailers)
                flags |= HTTP2_FLAG_END_STREAM;
            if (! HttpsMitm_H2WriteFrame(down, HTTP2_FRAME_HEADERS, flags,
                    stream->stream_id, block, blockLen))
                goto done;
        }
        if (hasBody &&
                ! HttpsMitm_H2WriteFrame(down, HTTP2_FRAME_DATA,
                    hasTrailers ? 0 : HTTP2_FLAG_END_STREAM,
                    stream->stream_id, respBody, respBodyLen))
            goto done;
        if (hasTrailers) {
            UCHAR tblk[512];
            ULONG tblkLen = 0;
            if (! HttpsMitm_H2EncodeOne(downEncoder, "grpc-status", grpcStatus,
                    tblk, sizeof(tblk), &tblkLen))
                goto done;
            if (grpcMessage[0] &&
                    ! HttpsMitm_H2EncodeOne(downEncoder, "grpc-message",
                        grpcMessage, tblk, sizeof(tblk), &tblkLen))
                goto done;
            if (! HttpsMitm_H2WriteFrame(down, HTTP2_FRAME_HEADERS,
                    HTTP2_FLAG_END_HEADERS | HTTP2_FLAG_END_STREAM,
                    stream->stream_id, tblk, tblkLen))
                goto done;
        }
    }

    /* 5. HAR */
    {
        HTTP11_REQUEST *request = (HTTP11_REQUEST *)malloc(sizeof(*request));
        HTTP11_RESPONSE *response = (HTTP11_RESPONSE *)malloc(sizeof(*response));
        MITM_HAR_META meta;

        if (request && response) {
            HttpsMitm_H2BuildH1RequestStruct(stream, request);
            HttpsMitm_H2BuildH1Response(
                respHeaders, respHeaderCount, respStatus, response);
            response->content_length = respBodyLen;

            memset(&meta, 0, sizeof(meta));
            meta.stream_id = stream->stream_id;
            if (isGrpc) {
                meta.grpc_status = grpcStatus[0] ? grpcStatus : NULL;
                meta.grpc_message = grpcMessage[0] ? grpcMessage : NULL;
                meta.grpc_message_count = grpcMsgCount;
            }
            HttpsMitm_WriteHar(mitm, context, down, request, response,
                (const char *)stream->body, stream->body_len,
                (const char *)respBody, respBodyLen, &meta);
        }
        free(request);
        free(response);
    }

    ok = 1;

done:
    free(respHeaders);
    free(respBody);
    return ok;
}


/* Relay one completed h2 request stream through an HTTP/1.1 upstream. */
static int HttpsMitm_H2RelayStream(
    HTTPS_MITM *mitm,
    SSL *down,
    SSL_CTX *upCtx,
    const char *upstreamHost,
    USHORT upstreamPort,
    const char *sni,
    const HTTPS_REDIRECT_CONTEXT *context,
    HPACK_ENCODER *encoder,
    H2_RELAY_STREAM *stream)
{
    char h1Request[HTTPS_MITM_IO_CAP];
    char h1Response[HTTPS_MITM_IO_CAP];
    ULONG requestSize = 0;
    ULONG responseSize = 0;
    HTTP11_REQUEST *request = NULL;
    HTTP11_RESPONSE *response = NULL;
    MITM_READER upReader;
    SOCKET upstream = INVALID_SOCKET;
    SSL *up = NULL;
    int ok = 0;

    request = (HTTP11_REQUEST *)malloc(sizeof(*request));
    response = (HTTP11_RESPONSE *)malloc(sizeof(*response));
    if (! request || ! response)
        goto done;

    if (! HttpsMitm_H2BuildH1Request(
            stream, h1Request, sizeof(h1Request), &requestSize))
        goto done;
    if (Http11_ParseRequest((const UCHAR *)h1Request, requestSize,
            request) != HTTP11_OK)
        goto done;
    strcpy_s(request->version, sizeof(request->version), "HTTP/2");

    upstream = HttpsMitm_ConnectTcp(upstreamHost, upstreamPort);
    if (upstream == INVALID_SOCKET)
        goto done;
    up = SSL_new(upCtx);
    if (! up)
        goto done;
    SSL_set_fd(up, (int)upstream);
    HttpsMitm_AttachKeylog(mitm, up);
    if (sni && sni[0])
        SSL_set_tlsext_host_name(up, sni);
    if (SSL_connect(up) != 1)
        goto done;

    /* origin negotiated h2: relay over h2 instead of translating to h1 */
    {
        const unsigned char *alpn = NULL;
        unsigned int alpnLen = 0;

        SSL_get0_alpn_selected(up, &alpn, &alpnLen);
        if (alpn && alpnLen == 2 && alpn[0] == 'h' && alpn[1] == '2') {
            ok = HttpsMitm_H2RelayStreamH2(
                mitm, down, up, context, encoder, stream);
            goto done;
        }
    }

    if (! HttpsMitm_SslWriteAll(up, h1Request, requestSize))
        goto done;

    memset(&upReader, 0, sizeof(upReader));
    upReader.ssl = up;
    if (! HttpsMitm_ReadMessage(&upReader, h1Response, sizeof(h1Response),
            &responseSize, 0, request, response))
        goto done;
    if (Http11_ParseResponse((const UCHAR *)h1Response, responseSize,
            response) != HTTP11_OK)
        goto done;
    strcpy_s(response->version, sizeof(response->version), "HTTP/2");

    if (! HttpsMitm_H2SendResponse(down, encoder, stream->stream_id,
            response, h1Response, responseSize))
        goto done;

    {
        MITM_HAR_META meta;
        memset(&meta, 0, sizeof(meta));
        meta.stream_id = stream->stream_id;
        HttpsMitm_WriteHar(mitm, context, down, request, response,
            h1Request, requestSize, h1Response, responseSize, &meta);
    }

    ok = 1;

done:
    free(request);
    free(response);
    if (up) {
        SSL_shutdown(up);
        SSL_free(up);
    }
    if (upstream != INVALID_SOCKET)
        closesocket(upstream);
    return ok;
}


/* Terminate a downstream HTTP/2 connection: demultiplex streams, translate
   each to HTTP/1.1 upstream, and emit HAR. */
static int HttpsMitm_ServeHttp2(
    HTTPS_MITM *mitm,
    SSL *down,
    const HTTPS_REDIRECT_CONTEXT *context,
    SSL_CTX *upCtx,
    const char *upstreamHost,
    USHORT upstreamPort,
    const char *sni)
{
    HTTP2_SESSION session;
    HPACK_DECODER decoder;
    HPACK_ENCODER encoder;
    H2_RELAY_STREAM *streams;
    UCHAR payload[HTTP2_MAX_HEADER_BLOCK];
    UCHAR magic[24];
    BOOL served = FALSE;
    ULONG got = 0;
    int n;

    Http2_SessionInit(&session);
    Hpack_DecoderInit(&decoder, HTTP2_DEFAULT_HEADER_TABLE_SIZE);
    Hpack_EncoderInit(&encoder, HTTP2_DEFAULT_HEADER_TABLE_SIZE, FALSE);
    /* per-stream relay state is large (~200 KB * 256), so heap-allocate it
       instead of blowing the broker's stack. */
    streams = (H2_RELAY_STREAM *)calloc(HTTP2_MAX_STREAMS, sizeof(*streams));
    if (! streams)
        return HTTPS_MITM_ERROR;

    /* client connection preface (RFC 7540 3.5): 24-byte magic string */
    while (got < sizeof(magic)) {
        n = SSL_read(down, magic + got, (int)(sizeof(magic) - got));
        if (n <= 0) {
            free(streams);
            return HTTPS_MITM_ERROR;
        }
        got += (ULONG)n;
    }

    HttpsMitm_H2SendSettings(down);

    for (;;) {
        HTTP2_FRAME_HEADER fh;
        HTTP2_FRAME_RESULT result;
        H2_RELAY_STREAM *stream;
        int rc;

        if (! HttpsMitm_H2ReadFrame(down, &fh, payload, sizeof(payload)))
            break;

        rc = Http2_ProcessFrame(&session, &fh, payload, &result);
        if (rc != HTTP2_OK) {
            HttpsMitm_H2SendGoAway(down, session.last_stream_id,
                                   HTTP2_PROTOCOL_ERROR);
            break;
        }

        switch (fh.type) {
        case HTTP2_FRAME_SETTINGS:
            if (! (fh.flags & HTTP2_FLAG_ACK))
                HttpsMitm_H2SendSettingsAck(down);
            break;
        case HTTP2_FRAME_PING:
            if (! (fh.flags & HTTP2_FLAG_ACK))
                HttpsMitm_H2SendPingAck(down, payload);
            break;
        case HTTP2_FRAME_GOAWAY: {
            int status = served ? HTTPS_MITM_OK : HTTPS_MITM_ERROR;
            free(streams);
            return status;
        }
        case HTTP2_FRAME_HEADERS:
        case HTTP2_FRAME_CONTINUATION:
            if (result.have_header_block) {
                stream = HttpsMitm_H2GetStream(streams, result.stream_id);
                if (! stream ||
                        ! HttpsMitm_H2DecodeRequest(&decoder,
                            result.header_block, result.header_block_len,
                            stream)) {
                    HttpsMitm_H2SendGoAway(down, session.last_stream_id,
                                           HTTP2_COMPRESSION_ERROR);
                    {
                        int status = served ? HTTPS_MITM_OK : HTTPS_MITM_ERROR;
                        free(streams);
                        return status;
                    }
                }
            }
            break;
        case HTTP2_FRAME_DATA:
            if (result.is_data) {
                stream = HttpsMitm_H2GetStream(streams, result.stream_id);
                if (stream &&
                        stream->body_len + result.data_len <=
                            HTTP2_RELAY_BODY_CAP) {
                    memcpy(stream->body + stream->body_len,
                           result.data, result.data_len);
                    stream->body_len += result.data_len;
                }
            }
            break;
        default:
            break;
        }

        if (result.end_stream) {
            stream = HttpsMitm_H2GetStream(streams, result.stream_id);
            if (stream && stream->have_request &&
                    HttpsMitm_H2RelayStream(mitm, down, upCtx, upstreamHost,
                        upstreamPort, sni, context, &encoder, stream))
                served = TRUE;
        }
    }

    {
        int status = served ? HTTPS_MITM_OK : HTTPS_MITM_ERROR;
        free(streams);
        return status;
    }
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
    HttpsMitm_AttachKeylog(mitm, down);
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

    /* HTTP/2 downstream: terminate and translate to upstream HTTP/1.1 */
    {
        const unsigned char *alpn = NULL;
        unsigned int alpnLen = 0;

        SSL_get0_alpn_selected(down, &alpn, &alpnLen);
        if (alpn && alpnLen == 2 && alpn[0] == 'h' && alpn[1] == '2') {
            status = HttpsMitm_ServeHttp2(mitm, down, context, upCtx,
                upstreamHost, upstreamPort, sni);
            goto done;
        }
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
        HttpsMitm_AttachKeylog(mitm, up);
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
            MITM_HAR_META wsMeta;

            memset(&wsMeta, 0, sizeof(wsMeta));

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

            wsMeta.ws_tunnel_bytes_in = wsIn;
            wsMeta.ws_tunnel_bytes_out = wsOut;
            HttpsMitm_WriteHar(mitm, context, down, &request, &response,
                requestBuf, requestSize, responseBuf, responseSize, &wsMeta);

            served = TRUE;
            break;   /* the tunneled connection is done; up/upstream are
                        released in the done: block */
        }

        /* record the exchange (best-effort) */
        {
            MITM_HAR_META meta;
            memset(&meta, 0, sizeof(meta));
            HttpsMitm_WriteHar(mitm, context, down, &request, &response,
                requestBuf, requestSize, responseBuf, responseSize, &meta);
        }

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
    if (mitm->have_keylog)
        DeleteCriticalSection(&mitm->keylog_lock);
    free(mitm->upstream_ca_pem);
    HeapFree(GetProcessHeap(), 0, mitm);
}
