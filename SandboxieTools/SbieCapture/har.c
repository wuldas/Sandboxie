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
// HAR 1.2 writer -- HTTP/1.1 exchanges only
//---------------------------------------------------------------------------

#include "har.h"
#include "redact.h"

#include <stdio.h>
#include <string.h>


#define HAR_JSON_CHUNK              4096
#define HAR_DEFAULT_BODY_CAP        (64u * 1024u)


struct _HAR_WRITER {

    HANDLE file;
    BOOL started;
    BOOL failed;
    BOOL owns_file;

};


static BOOL Har_WriteRaw(HAR_WRITER *writer, const void *data, ULONG size)
{
    DWORD written = 0;
    if (! writer || writer->failed || writer->file == INVALID_HANDLE_VALUE)
        return FALSE;
    if (! WriteFile(writer->file, data, size, &written, NULL) ||
            written != size) {
        writer->failed = TRUE;
        return FALSE;
    }
    return TRUE;
}


static BOOL Har_WriteText(HAR_WRITER *writer, const char *text)
{
    if (! text)
        text = "";
    return Har_WriteRaw(writer, text, (ULONG)strlen(text));
}


static BOOL Har_WriteJsonString(HAR_WRITER *writer, const char *text)
{
    ULONG index;
    if (! Har_WriteText(writer, "\""))
        return FALSE;
    if (! text)
        return Har_WriteText(writer, "\"");

    for (index = 0; text[index]; ++index) {
        unsigned char value = (unsigned char)text[index];
        char escape[8];
        const char *chunk = NULL;
        if (value == '"')
            chunk = "\\\"";
        else if (value == '\\')
            chunk = "\\\\";
        else if (value == '\b')
            chunk = "\\b";
        else if (value == '\f')
            chunk = "\\f";
        else if (value == '\n')
            chunk = "\\n";
        else if (value == '\r')
            chunk = "\\r";
        else if (value == '\t')
            chunk = "\\t";
        else if (value < 0x20) {
            sprintf_s(escape, sizeof(escape), "\\u%04x", value);
            chunk = escape;
        }
        else {
            escape[0] = (char)value;
            escape[1] = 0;
            chunk = escape;
        }
        if (! Har_WriteText(writer, chunk))
            return FALSE;
    }
    return Har_WriteText(writer, "\"");
}


static BOOL Har_WriteWideUtf8Json(HAR_WRITER *writer, const WCHAR *text)
{
    char utf8[256];
    utf8[0] = 0;
    if (text) {
        WideCharToMultiByte(
            CP_UTF8, 0, text, -1, utf8, sizeof(utf8), NULL, NULL);
        utf8[sizeof(utf8) - 1] = 0;
    }
    return Har_WriteJsonString(writer, utf8);
}


static BOOL Har_WriteULong(HAR_WRITER *writer, ULONG value)
{
    char buffer[16];
    sprintf_s(buffer, sizeof(buffer), "%lu", value);
    return Har_WriteText(writer, buffer);
}


static BOOL Har_WriteULong64(HAR_WRITER *writer, ULONG64 value)
{
    char buffer[32];
    sprintf_s(buffer, sizeof(buffer), "%llu", value);
    return Har_WriteText(writer, buffer);
}


static BOOL Har_WriteBool(HAR_WRITER *writer, BOOL value)
{
    return Har_WriteText(writer, value ? "true" : "false");
}


static void Har_CopyHeaders(
    HTTP11_HEADER *dest,
    ULONG *count,
    const HTTP11_HEADER *source,
    ULONG sourceCount,
    BOOL redact)
{
    ULONG index;
    *count = sourceCount;
    if (sourceCount > HTTP11_MAX_HEADERS)
        *count = HTTP11_MAX_HEADERS;
    for (index = 0; index < *count; ++index)
        dest[index] = source[index];
    if (redact)
        Redact_ApplyToHeaders(dest, *count);
}


static BOOL Har_WriteHeaders(
    HAR_WRITER *writer,
    const HTTP11_HEADER *headers,
    ULONG count)
{
    ULONG index;
    if (! Har_WriteText(writer, "["))
        return FALSE;
    for (index = 0; index < count; ++index) {
        if (index && ! Har_WriteText(writer, ", "))
            return FALSE;
        if (! Har_WriteText(writer, "{\"name\": ") ||
                ! Har_WriteJsonString(writer, headers[index].name) ||
                ! Har_WriteText(writer, ", \"value\": ") ||
                ! Har_WriteJsonString(writer, headers[index].value) ||
                ! Har_WriteText(writer, "}")) {
            return FALSE;
        }
    }
    return Har_WriteText(writer, "]");
}


static BOOL Har_WriteQueryString(HAR_WRITER *writer, const char *target)
{
    const char *query;
    BOOL first = TRUE;

    if (! Har_WriteText(writer, "["))
        return FALSE;
    if (! target)
        return Har_WriteText(writer, "]");

    query = strchr(target, '?');
    if (! query)
        return Har_WriteText(writer, "]");
    ++query;

    while (query[0]) {
        const char *amp = strchr(query, '&');
        const char *eq;
        ULONG nameLen;
        ULONG valueLen;
        const char *value;
        char name[HTTP11_MAX_TARGET];
        char valueBuf[HTTP11_MAX_TARGET];
        ULONG pairLen = amp ? (ULONG)(amp - query) : (ULONG)strlen(query);

        eq = (const char *)memchr(query, '=', pairLen);
        if (eq) {
            nameLen = (ULONG)(eq - query);
            value = eq + 1;
            valueLen = pairLen - nameLen - 1;
        }
        else {
            nameLen = pairLen;
            value = "";
            valueLen = 0;
        }
        if (nameLen >= sizeof(name))
            nameLen = sizeof(name) - 1;
        if (valueLen >= sizeof(valueBuf))
            valueLen = sizeof(valueBuf) - 1;
        memcpy(name, query, nameLen);
        name[nameLen] = 0;
        memcpy(valueBuf, value, valueLen);
        valueBuf[valueLen] = 0;

        if (! first && ! Har_WriteText(writer, ", "))
            return FALSE;
        first = FALSE;
        if (! Har_WriteText(writer, "{\"name\": ") ||
                ! Har_WriteJsonString(writer, name) ||
                ! Har_WriteText(writer, ", \"value\": ") ||
                ! Har_WriteJsonString(writer, valueBuf) ||
                ! Har_WriteText(writer, "}")) {
            return FALSE;
        }

        if (! amp)
            break;
        query = amp + 1;
    }

    return Har_WriteText(writer, "]");
}


static BOOL Har_WriteUrl(
    HAR_WRITER *writer,
    const char *sniHost,
    const char *target)
{
    char url[HTTP11_MAX_TARGET + 80];
    if (target && (_strnicmp(target, "http://", 7) == 0 ||
            _strnicmp(target, "https://", 8) == 0)) {
        return Har_WriteJsonString(writer, target);
    }
    sprintf_s(
        url,
        sizeof(url),
        "https://%s%s",
        sniHost ? sniHost : "unknown",
        (target && target[0]) ? target : "/");
    return Har_WriteJsonString(writer, url);
}


static const char *Har_HeaderValue(
    const HTTP11_HEADER *headers,
    ULONG count,
    const char *name)
{
    const HTTP11_HEADER *header = Http11_FindHeader(headers, count, name);
    return header ? header->value : "";
}


static BOOL Har_WriteContent(
    HAR_WRITER *writer,
    const HTTP11_HEADER *headers,
    ULONG headerCount,
    BOOL includeBodies,
    const UCHAR *body,
    ULONG bodyLen,
    ULONG originalLen,
    ULONG bodyCap)
{
    ULONG emitLen = bodyLen;
    char text[HAR_JSON_CHUNK];

    if (! Har_WriteText(writer, "{\"size\": "))
        return FALSE;
    if (! Har_WriteULong(writer, originalLen))
        return FALSE;
    if (! Har_WriteText(writer, ", \"mimeType\": "))
        return FALSE;
    if (! Har_WriteJsonString(
            writer, Har_HeaderValue(headers, headerCount, "Content-Type"))) {
        return FALSE;
    }

    if (! includeBodies) {
        return Har_WriteText(writer, ", \"_omitted\": true}");
    }

    if (bodyCap == 0)
        bodyCap = HAR_DEFAULT_BODY_CAP;
    if (emitLen > bodyCap)
        emitLen = bodyCap;
    if (emitLen >= sizeof(text))
        emitLen = sizeof(text) - 1;
    memset(text, 0, sizeof(text));
    if (body && emitLen)
        memcpy(text, body, emitLen);

    if (! Har_WriteText(writer, ", \"text\": "))
        return FALSE;
    return Har_WriteJsonString(writer, text) && Har_WriteText(writer, "}");
}


static BOOL Har_WriteOpenedPrefix(HAR_WRITER *writer)
{
    return Har_WriteText(
        writer,
        "{\n  \"log\": {\n    \"version\": \"1.2\",\n"
        "    \"creator\": {\"name\": \"SbieCapture\", \"version\": \"1.0\"},\n"
        "    \"entries\": [\n");
}


static HAR_WRITER *Har_Create(HANDLE file, BOOL ownsFile)
{
    HAR_WRITER *writer;
    if (file == NULL || file == INVALID_HANDLE_VALUE)
        return NULL;
    writer = (HAR_WRITER *)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*writer));
    if (! writer) {
        if (ownsFile)
            CloseHandle(file);
        return NULL;
    }
    writer->file = file;
    writer->owns_file = ownsFile;
    return writer;
}


HAR_WRITER *HarWriter_OpenPath(const WCHAR *path)
{
    HANDLE file;
    if (! path || ! path[0])
        return NULL;
    file = CreateFileW(
        path,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    return Har_Create(file, TRUE);
}


HAR_WRITER *HarWriter_OpenHandle(HANDLE file)
{
    return Har_Create(file, FALSE);
}


int HarWriter_WriteExchange(HAR_WRITER *writer, const HAR_EXCHANGE *exchange)
{
    HTTP11_HEADER requestHeaders[HTTP11_MAX_HEADERS];
    HTTP11_HEADER responseHeaders[HTTP11_MAX_HEADERS];
    ULONG requestCount = 0;
    ULONG responseCount = 0;
    const HTTP11_REQUEST *request;
    const HTTP11_RESPONSE *response;

    if (! writer || ! exchange || ! exchange->request || ! exchange->response)
        return HAR_ERROR;
    if (writer->failed)
        return HAR_ERROR;

    if (! writer->started) {
        if (! Har_WriteOpenedPrefix(writer))
            return HAR_ERROR;
        writer->started = TRUE;
    }
    else if (! Har_WriteText(writer, ",\n")) {
        return HAR_ERROR;
    }

    request = exchange->request;
    response = exchange->response;
    Har_CopyHeaders(
        requestHeaders, &requestCount, request->headers,
        request->header_count, exchange->redact);
    Har_CopyHeaders(
        responseHeaders, &responseCount, response->headers,
        response->header_count, exchange->redact);

    if (! Har_WriteText(writer, "      {\n        \"startedDateTime\": ") ||
            ! Har_WriteJsonString(writer, "1970-01-01T00:00:00.000Z") ||
            ! Har_WriteText(writer, ",\n        \"time\": ") ||
            ! Har_WriteULong(writer, exchange->elapsed_ms) ||
            ! Har_WriteText(writer, ",\n        \"request\": {\n") ||
            ! Har_WriteText(writer, "          \"method\": ") ||
            ! Har_WriteJsonString(writer, request->method) ||
            ! Har_WriteText(writer, ",\n          \"url\": ") ||
            ! Har_WriteUrl(writer, exchange->sni_host, request->target) ||
            ! Har_WriteText(writer, ",\n          \"httpVersion\": ") ||
            ! Har_WriteJsonString(writer, request->version) ||
            ! Har_WriteText(writer, ",\n          \"cookies\": [],\n") ||
            ! Har_WriteText(writer, "          \"headers\": ") ||
            ! Har_WriteHeaders(writer, requestHeaders, requestCount) ||
            ! Har_WriteText(writer, ",\n          \"queryString\": ") ||
            ! Har_WriteQueryString(writer, request->target) ||
            ! Har_WriteText(
                writer,
                ",\n          \"headersSize\": -1,\n"
                "          \"bodySize\": ") ||
            ! Har_WriteULong(writer, exchange->request_body_original_len) ||
            ! Har_WriteText(writer, "\n        },\n        \"response\": {\n") ||
            ! Har_WriteText(writer, "          \"status\": ") ||
            ! Har_WriteULong(writer, response->status) ||
            ! Har_WriteText(writer, ",\n          \"statusText\": ") ||
            ! Har_WriteJsonString(writer, response->reason) ||
            ! Har_WriteText(writer, ",\n          \"httpVersion\": ") ||
            ! Har_WriteJsonString(writer, response->version) ||
            ! Har_WriteText(writer, ",\n          \"cookies\": [],\n") ||
            ! Har_WriteText(writer, "          \"headers\": ") ||
            ! Har_WriteHeaders(writer, responseHeaders, responseCount) ||
            ! Har_WriteText(writer, ",\n          \"content\": ") ||
            ! Har_WriteContent(
                writer,
                responseHeaders,
                responseCount,
                exchange->include_bodies,
                exchange->response_body,
                exchange->response_body_len,
                exchange->response_body_original_len,
                exchange->body_cap) ||
            ! Har_WriteText(
                writer,
                ",\n          \"redirectURL\": \"\",\n"
                "          \"headersSize\": -1,\n"
                "          \"bodySize\": ") ||
            ! Har_WriteULong(writer, exchange->response_body_original_len) ||
            ! Har_WriteText(
                writer,
                "\n        },\n        \"cache\": {},\n"
                "        \"timings\": {\"send\": 0, \"wait\": ") ||
            ! Har_WriteULong(writer, exchange->elapsed_ms) ||
            ! Har_WriteText(writer, ", \"receive\": 0},\n") ||
            ! Har_WriteText(writer, "        \"serverIPAddress\": ") ||
            ! Har_WriteJsonString(
                writer, exchange->server_ip ? exchange->server_ip : "") ||
            ! Har_WriteText(writer, ",\n        \"_sandboxie\": {\n") ||
            ! Har_WriteText(writer, "          \"pid\": ") ||
            ! Har_WriteULong(writer, exchange->process_id) ||
            ! Har_WriteText(writer, ",\n          \"createTime\": ") ||
            ! Har_WriteULong64(writer, exchange->process_create_time) ||
            ! Har_WriteText(writer, ",\n          \"session\": ") ||
            ! Har_WriteULong(writer, exchange->session_id) ||
            ! Har_WriteText(writer, ",\n          \"box\": ") ||
            ! Har_WriteWideUtf8Json(writer, exchange->box_name) ||
            ! Har_WriteText(writer, ",\n          \"sid\": ") ||
            ! Har_WriteWideUtf8Json(writer, exchange->sid_string) ||
            ! Har_WriteText(writer, ",\n          \"sni\": ") ||
            ! Har_WriteJsonString(
                writer, exchange->sni_host ? exchange->sni_host : "") ||
            ! Har_WriteText(writer, ",\n          \"alpn\": ") ||
            ! Har_WriteJsonString(
                writer, exchange->alpn ? exchange->alpn : "") ||
            ! Har_WriteText(writer, ",\n          \"tlsVersion\": ") ||
            ! Har_WriteJsonString(
                writer, exchange->tls_version ? exchange->tls_version : "") ||
            ! Har_WriteText(writer, ",\n          \"pinningFailed\": ") ||
            ! Har_WriteBool(writer, exchange->pinning_failed) ||
            ! Har_WriteText(writer, ",\n          \"wsTunnelBytesIn\": ") ||
            ! Har_WriteULong64(writer, exchange->ws_tunnel_bytes_in) ||
            ! Har_WriteText(writer, ",\n          \"wsTunnelBytesOut\": ") ||
            ! Har_WriteULong64(writer, exchange->ws_tunnel_bytes_out) ||
            ! Har_WriteText(writer, ",\n          \"streamId\": ") ||
            ! Har_WriteULong(writer, exchange->stream_id) ||
            ! Har_WriteText(writer, ",\n          \"grpcStatus\": ") ||
            ! Har_WriteJsonString(
                writer, exchange->grpc_status ? exchange->grpc_status : "") ||
            ! Har_WriteText(writer, ",\n          \"grpcMessage\": ") ||
            ! Har_WriteJsonString(
                writer, exchange->grpc_message ? exchange->grpc_message : "") ||
            ! Har_WriteText(writer, ",\n          \"grpcMessageCount\": ") ||
            ! Har_WriteULong(writer, exchange->grpc_message_count) ||
            ! Har_WriteText(writer, "\n        }\n      }")) {
        return HAR_ERROR;
    }

    return writer->failed ? HAR_ERROR : HAR_OK;
}


void HarWriter_Close(HAR_WRITER *writer)
{
    if (! writer)
        return;
    if (writer->started && ! writer->failed)
        Har_WriteText(writer, "\n    ]\n  }\n}\n");
    if (writer->owns_file && writer->file != INVALID_HANDLE_VALUE)
        CloseHandle(writer->file);
    HeapFree(GetProcessHeap(), 0, writer);
}
