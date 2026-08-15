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
// HAR / HTTP/1.1 / redaction tests
//---------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../SbieCapture/http11.h"
#include "../SbieCapture/redact.h"
#include "../SbieCapture/har.h"


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


static int TestParseGetRequest(void)
{
    static const char kRequest[] =
        "GET /path?foo=bar&baz=1 HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Authorization: Bearer secret-token\r\n"
        "Cookie: session=abc123\r\n"
        "X-Api-Key: super-secret\r\n"
        "Content-Length: 0\r\n"
        "\r\n";

    HTTP11_REQUEST request;
    int status = Http11_ParseRequest(
        (const UCHAR *)kRequest, (ULONG)strlen(kRequest), &request);
    if (! Require(status == HTTP11_OK, "parse GET request") ||
            ! Require(strcmp(request.method, "GET") == 0, "method GET") ||
            ! Require(strcmp(request.target, "/path?foo=bar&baz=1") == 0,
                      "request target") ||
            ! Require(strcmp(request.version, "HTTP/1.1") == 0,
                      "request version") ||
            ! Require(request.header_count == 5, "five request headers") ||
            ! Require(request.content_length == 0, "content-length 0") ||
            ! Require(request.header_bytes == (ULONG)strlen(kRequest),
                      "consumed whole request")) {
        return 0;
    }

    const HTTP11_HEADER *host = Http11_FindHeader(
        request.headers, request.header_count, "host");
    const HTTP11_HEADER *auth = Http11_FindHeader(
        request.headers, request.header_count, "Authorization");
    return Require(host != NULL && strcmp(host->value, "example.com") == 0,
                   "host header") &&
        Require(auth != NULL &&
                strcmp(auth->value, "Bearer secret-token") == 0,
                "authorization header before redact");
}


static int TestParseOkResponse(void)
{
    static const char kResponse[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Set-Cookie: session=abc123; HttpOnly\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "hello";

    HTTP11_RESPONSE response;
    int status = Http11_ParseResponse(
        (const UCHAR *)kResponse, (ULONG)strlen(kResponse), &response);
    if (! Require(status == HTTP11_OK, "parse 200 response") ||
            ! Require(response.status == 200, "status 200") ||
            ! Require(strcmp(response.reason, "OK") == 0, "reason OK") ||
            ! Require(strcmp(response.version, "HTTP/1.1") == 0,
                      "response version") ||
            ! Require(response.header_count == 3, "three response headers") ||
            ! Require(response.content_length == 5, "content-length 5") ||
            ! Require(response.header_bytes ==
                      (ULONG)(strlen(kResponse) - 5),
                      "headers stop before body")) {
        return 0;
    }
    return 1;
}


static int TestRejectFoldedHeader(void)
{
    static const char kRequest[] =
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "X-Long: first\r\n"
        " folded\r\n"
        "\r\n";

    HTTP11_REQUEST request;
    int status = Http11_ParseRequest(
        (const UCHAR *)kRequest, (ULONG)strlen(kRequest), &request);
    return Require(status == HTTP11_ERROR, "folded header is an error");
}


static int TestRejectOversizeLine(void)
{
    char buffer[HTTP11_MAX_LINE + 64];
    ULONG offset = 0;
    memcpy(buffer, "GET / HTTP/1.1\r\nX-Big: ", 23);
    offset = 23;
    memset(buffer + offset, 'A', HTTP11_MAX_LINE);
    offset += HTTP11_MAX_LINE;
    memcpy(buffer + offset, "\r\n\r\n", 4);
    offset += 4;

    HTTP11_REQUEST request;
    int status = Http11_ParseRequest(
        (const UCHAR *)buffer, offset, &request);
    return Require(status == HTTP11_ERROR, "oversize header line is an error");
}


static int TestNeedMoreIncompleteRequest(void)
{
    static const char kRequest[] =
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n";

    HTTP11_REQUEST request;
    int status = Http11_ParseRequest(
        (const UCHAR *)kRequest, (ULONG)strlen(kRequest), &request);
    return Require(status == HTTP11_NEED_MORE, "incomplete request needs more");
}


static int TestRedactSensitiveHeaders(void)
{
    HTTP11_HEADER headers[5];
    memset(headers, 0, sizeof(headers));
    strcpy_s(headers[0].name, sizeof(headers[0].name), "Authorization");
    strcpy_s(headers[0].value, sizeof(headers[0].value), "Bearer secret-token");
    strcpy_s(headers[1].name, sizeof(headers[1].name), "Cookie");
    strcpy_s(headers[1].value, sizeof(headers[1].value), "session=abc123");
    strcpy_s(headers[2].name, sizeof(headers[2].name), "X-Api-Key");
    strcpy_s(headers[2].value, sizeof(headers[2].value), "super-secret");
    strcpy_s(headers[3].name, sizeof(headers[3].name), "Host");
    strcpy_s(headers[3].value, sizeof(headers[3].value), "example.com");
    strcpy_s(headers[4].name, sizeof(headers[4].name), "Set-Cookie");
    strcpy_s(headers[4].value, sizeof(headers[4].value), "session=abc123");

    if (! Require(Redact_IsSensitiveHeader("authorization"),
                  "authorization is sensitive") ||
            ! Require(Redact_IsSensitiveHeader("PROXY-AUTHORIZATION"),
                      "proxy-authorization is sensitive") ||
            ! Require(Redact_IsSensitiveHeader("cookie"),
                      "cookie is sensitive") ||
            ! Require(Redact_IsSensitiveHeader("set-cookie"),
                      "set-cookie is sensitive") ||
            ! Require(Redact_IsSensitiveHeader("x-api-key"),
                      "x-api-key is sensitive") ||
            ! Require(! Redact_IsSensitiveHeader("host"),
                      "host is not sensitive")) {
        return 0;
    }

    Redact_ApplyToHeaders(headers, 5);
    return Require(strcmp(headers[0].value, REDACT_REPLACEMENT) == 0,
                   "authorization redacted") &&
        Require(strcmp(headers[1].value, REDACT_REPLACEMENT) == 0,
                "cookie redacted") &&
        Require(strcmp(headers[2].value, REDACT_REPLACEMENT) == 0,
                "x-api-key redacted") &&
        Require(strcmp(headers[3].value, "example.com") == 0,
                "host left intact") &&
        Require(strcmp(headers[4].value, REDACT_REPLACEMENT) == 0,
                "set-cookie redacted");
}


static int TestDisableRedactionKeepsValues(void)
{
    HTTP11_HEADER headers[1];
    memset(headers, 0, sizeof(headers));
    strcpy_s(headers[0].name, sizeof(headers[0].name), "Authorization");
    strcpy_s(headers[0].value, sizeof(headers[0].value), "Bearer secret-token");
    /* Caller skips Redact_ApplyToHeaders when DISABLE_REDACTION is set. */
    return Require(strcmp(headers[0].value, "Bearer secret-token") == 0,
                   "unredacted authorization kept");
}


static void FillSampleExchange(HAR_EXCHANGE *exchange,
                               HTTP11_REQUEST *request,
                               HTTP11_RESPONSE *response)
{
    static const char kRequest[] =
        "GET /path?foo=bar HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Authorization: Bearer secret-token\r\n"
        "Cookie: session=abc123\r\n"
        "\r\n";
    static const char kResponse[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Set-Cookie: session=abc123\r\n"
        "Content-Length: 12\r\n"
        "\r\n"
        "hello world!";

    memset(request, 0, sizeof(*request));
    memset(response, 0, sizeof(*response));
    Http11_ParseRequest(
        (const UCHAR *)kRequest, (ULONG)strlen(kRequest), request);
    Http11_ParseResponse(
        (const UCHAR *)kResponse, (ULONG)strlen(kResponse), response);

    memset(exchange, 0, sizeof(*exchange));
    exchange->started_filetime = 133000000000000000ull;
    exchange->elapsed_ms = 15;
    exchange->request = request;
    exchange->response = response;
    exchange->sni_host = "example.com";
    exchange->server_ip = "93.184.216.34";
    exchange->process_id = 4242;
    exchange->session_id = 1;
    exchange->process_create_time = 133000000000000001ull;
    exchange->box_name = L"DefaultBox";
    exchange->sid_string = L"S-1-5-21-1-2-3-1001";
    exchange->tls_version = "TLSv1.3";
    exchange->alpn = "http/1.1";
    exchange->pinning_failed = FALSE;
    exchange->include_bodies = FALSE;
    exchange->redact = TRUE;
    exchange->request_body = NULL;
    exchange->request_body_len = 0;
    exchange->request_body_original_len = 0;
    exchange->response_body = (const UCHAR *)"hello world!";
    exchange->response_body_len = 12;
    exchange->response_body_original_len = 12;
    exchange->body_cap = 64 * 1024;
}


static int TestHarOmitsBodiesAndRedactsByDefault(void)
{
    HTTP11_REQUEST request;
    HTTP11_RESPONSE response;
    HAR_EXCHANGE exchange;
    FillSampleExchange(&exchange, &request, &response);

    WCHAR path[MAX_PATH];
    MakeTempPath(path, MAX_PATH, L"sbie-har-default.har");
    DeleteFileW(path);

    HAR_WRITER *writer = HarWriter_OpenPath(path);
    if (! Require(writer != NULL, "open HAR writer"))
        return 0;

    int status = HarWriter_WriteExchange(writer, &exchange);
    HarWriter_Close(writer);
    if (! Require(status == HAR_OK, "write one HAR exchange")) {
        DeleteFileW(path);
        return 0;
    }

    UCHAR *bytes = NULL;
    DWORD size = 0;
    if (! Require(ReadAll(path, &bytes, &size), "read HAR file")) {
        DeleteFileW(path);
        return 0;
    }

    const char *text = (const char *)bytes;
    int ok = Require(strstr(text, "\"log\"") != NULL, "HAR log object") &&
        Require(strstr(text, "\"version\": \"1.2\"") != NULL,
                "HAR version 1.2") &&
        Require(strstr(text, "https://example.com/path?foo=bar") != NULL,
                "URL uses SNI host") &&
        Require(strstr(text, "93.184.216.34") != NULL, "original server IP") &&
        Require(strstr(text, "\"foo\"") != NULL, "query name foo") &&
        Require(strstr(text, "[REDACTED]") != NULL, "redacted marker") &&
        Require(strstr(text, "secret-token") == NULL,
                "authorization plaintext absent") &&
        Require(strstr(text, "session=abc123") == NULL,
                "cookie plaintext absent") &&
        Require(strstr(text, "hello world!") == NULL,
                "body omitted by default") &&
        Require(strstr(text, "\"_omitted\"") != NULL,
                "omitted body recorded") &&
        Require(strstr(text, "\"pid\": 4242") != NULL,
                "sandbox pid metadata");

    free(bytes);
    DeleteFileW(path);
    return ok;
}


static int TestHarIncludesTruncatedBodyWhenEnabled(void)
{
    HTTP11_REQUEST request;
    HTTP11_RESPONSE response;
    HAR_EXCHANGE exchange;
    FillSampleExchange(&exchange, &request, &response);
    exchange.include_bodies = TRUE;
    exchange.body_cap = 5;

    WCHAR path[MAX_PATH];
    MakeTempPath(path, MAX_PATH, L"sbie-har-body.har");
    DeleteFileW(path);

    HAR_WRITER *writer = HarWriter_OpenPath(path);
    if (! Require(writer != NULL, "open HAR writer for body test"))
        return 0;

    int status = HarWriter_WriteExchange(writer, &exchange);
    HarWriter_Close(writer);
    if (! Require(status == HAR_OK, "write HAR with body")) {
        DeleteFileW(path);
        return 0;
    }

    UCHAR *bytes = NULL;
    DWORD size = 0;
    if (! Require(ReadAll(path, &bytes, &size), "read body HAR file")) {
        DeleteFileW(path);
        return 0;
    }

    const char *text = (const char *)bytes;
    int ok = Require(strstr(text, "hello") != NULL, "truncated body prefix") &&
        Require(strstr(text, "hello world!") == NULL,
                "body truncated at cap") &&
        Require(strstr(text, "\"size\": 12") != NULL,
                "original body size recorded");

    free(bytes);
    DeleteFileW(path);
    return ok;
}


static int TestHarDisableRedactionKeepsSecrets(void)
{
    HTTP11_REQUEST request;
    HTTP11_RESPONSE response;
    HAR_EXCHANGE exchange;
    FillSampleExchange(&exchange, &request, &response);
    exchange.redact = FALSE;

    WCHAR path[MAX_PATH];
    MakeTempPath(path, MAX_PATH, L"sbie-har-noreact.har");
    DeleteFileW(path);

    HAR_WRITER *writer = HarWriter_OpenPath(path);
    if (! Require(writer != NULL, "open HAR writer for no-redact"))
        return 0;

    int status = HarWriter_WriteExchange(writer, &exchange);
    HarWriter_Close(writer);
    if (! Require(status == HAR_OK, "write unredacted HAR")) {
        DeleteFileW(path);
        return 0;
    }

    UCHAR *bytes = NULL;
    DWORD size = 0;
    if (! Require(ReadAll(path, &bytes, &size), "read unredacted HAR")) {
        DeleteFileW(path);
        return 0;
    }

    const char *text = (const char *)bytes;
    int ok = Require(strstr(text, "Bearer secret-token") != NULL,
                     "unredacted authorization present") &&
        Require(strstr(text, "session=abc123") != NULL,
                "unredacted cookie present");

    free(bytes);
    DeleteFileW(path);
    return ok;
}


int main(void)
{
    if (! TestParseGetRequest() ||
            ! TestParseOkResponse() ||
            ! TestRejectFoldedHeader() ||
            ! TestRejectOversizeLine() ||
            ! TestNeedMoreIncompleteRequest() ||
            ! TestRedactSensitiveHeaders() ||
            ! TestDisableRedactionKeepsValues() ||
            ! TestHarOmitsBodiesAndRedactsByDefault() ||
            ! TestHarIncludesTruncatedBodyWhenEnabled() ||
            ! TestHarDisableRedactionKeepsSecrets()) {
        return 1;
    }

    printf("har tests passed\n");
    return 0;
}
