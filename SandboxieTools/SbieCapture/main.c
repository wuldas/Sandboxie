/*
 * Copyright 2026 David Xanatos, xanasoft.com
 *
 * This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

//---------------------------------------------------------------------------
// SbieCapture broker process entry point
//---------------------------------------------------------------------------

#define WIN32_LEAN_AND_MEAN

#include "capture_https_broker.h"
#include "capture_broker.h"
#include "capture_ca.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>


static BOOL ParseUInt64(const WCHAR *text, int base, ULONG64 *value)
{
    WCHAR *end = NULL;
    unsigned __int64 parsed;

    if (! text || ! text[0])
        return FALSE;
    errno = 0;
    parsed = _wcstoui64(text, &end, base);
    if (errno || end == text || ! end || *end != L'\0')
        return FALSE;
    *value = (ULONG64)parsed;
    return TRUE;
}


static BOOL ReadOption(
    int argc, WCHAR **argv, int *index, const WCHAR *name,
    const WCHAR **value)
{
    size_t nameLength = wcslen(name);
    const WCHAR *argument = argv[*index];

    if (_wcsicmp(argument, name) == 0) {
        if (*index + 1 >= argc)
            return FALSE;
        ++*index;
        *value = argv[*index];
        return TRUE;
    }

    if (_wcsnicmp(argument, name, nameLength) == 0 &&
            argument[nameLength] == L'=') {
        *value = argument + nameLength + 1;
        return (*value)[0] != L'\0';
    }

    return FALSE;
}


static void PrintUsage(void)
{
    fwprintf(stderr,
        L"Usage: SbieCapture.exe --section HANDLE --file HANDLE "
        L"--capture-high N --capture-low N --generation N "
        L"[--stop-event HANDLE] [--snaplen N] [--max-file-bytes N] "
        L"[--max-seconds N] [--rotate-count N] "
        L"[--https-listen --har HANDLE --ca-file HANDLE "
        L"[--https-test-preamble]]\n");
}


int __cdecl wmain(int argc, WCHAR **argv)
{
    ULONG64 rawSection = 0;
    ULONG64 rawFile = 0;
    ULONG64 rawStopEvent = 0;
    ULONG64 rawCaptureHigh = 0;
    ULONG64 rawCaptureLow = 0;
    ULONG64 rawGeneration = 0;
    ULONG64 rawHar = 0;
    ULONG64 rawCa = 0;
    ULONG64 value = 0;
    BOOL haveSection = FALSE;
    BOOL haveFile = FALSE;
    BOOL haveCaptureHigh = FALSE;
    BOOL haveCaptureLow = FALSE;
    BOOL haveGeneration = FALSE;
    BOOL httpsListen = FALSE;
    BOOL httpsTestPreamble = FALSE;
    BOOL httpsImportHostRoot = FALSE;
    BOOL importCa = FALSE;
    BOOL removeCa = FALSE;
    BOOL systemStore = FALSE;
    ULONG64 rawImport = 0;
    HANDLE importHandle = NULL;
    const WCHAR *importPath = NULL;
    const WCHAR *storeName = L"Root";
    HANDLE sectionHandle = NULL;
    HANDLE outputFile = NULL;
    HANDLE stopEvent = NULL;
    HANDLE harFile = NULL;
    HANDLE caFile = NULL;
    ULONG snapLength = 0;
    ULONG maxFileBytes = 0;
    ULONG maxSeconds = 0;
    ULONG rotateCount = 0;
    int index;

    for (index = 1; index < argc; ++index) {
        const WCHAR *text = NULL;
        if (ReadOption(argc, argv, &index, L"--section", &text)) {
            if (haveSection || ! ParseUInt64(text, 16, &rawSection) ||
                    rawSection == 0)
                goto InvalidArguments;
            haveSection = TRUE;
        }
        else if (ReadOption(argc, argv, &index, L"--file", &text)) {
            if (haveFile || ! ParseUInt64(text, 16, &rawFile) ||
                    rawFile == 0)
                goto InvalidArguments;
            haveFile = TRUE;
        }
        else if (ReadOption(argc, argv, &index, L"--capture-high", &text)) {
            if (haveCaptureHigh ||
                    ! ParseUInt64(text, 16, &rawCaptureHigh) ||
                    rawCaptureHigh == 0)
                goto InvalidArguments;
            haveCaptureHigh = TRUE;
        }
        else if (ReadOption(argc, argv, &index, L"--capture-low", &text)) {
            if (haveCaptureLow ||
                    ! ParseUInt64(text, 16, &rawCaptureLow) ||
                    rawCaptureLow == 0)
                goto InvalidArguments;
            haveCaptureLow = TRUE;
        }
        else if (ReadOption(argc, argv, &index, L"--generation", &text)) {
            if (haveGeneration ||
                    ! ParseUInt64(text, 16, &rawGeneration) ||
                    rawGeneration == 0)
                goto InvalidArguments;
            haveGeneration = TRUE;
        }
        else if (ReadOption(argc, argv, &index, L"--stop-event", &text)) {
            if (stopEvent || ! ParseUInt64(text, 16, &rawStopEvent) ||
                    rawStopEvent == 0)
                goto InvalidArguments;
            stopEvent = (HANDLE)(ULONG_PTR)rawStopEvent;
        }
        else if (ReadOption(argc, argv, &index, L"--snaplen", &text)) {
            if (! ParseUInt64(text, 0, &value) || value > 0xFFFFFFFFull)
                goto InvalidArguments;
            snapLength = (ULONG)value;
        }
        else if (ReadOption(
                     argc, argv, &index, L"--max-file-bytes", &text)) {
            if (! ParseUInt64(text, 0, &value) || value > 0xFFFFFFFFull)
                goto InvalidArguments;
            maxFileBytes = (ULONG)value;
        }
        else if (ReadOption(argc, argv, &index, L"--max-seconds", &text)) {
            if (! ParseUInt64(text, 0, &value) || value > 0xFFFFFFFFull)
                goto InvalidArguments;
            maxSeconds = (ULONG)value;
        }
        else if (ReadOption(argc, argv, &index, L"--rotate-count", &text)) {
            if (! ParseUInt64(text, 0, &value) || value > 0xFFFFFFFFull)
                goto InvalidArguments;
            rotateCount = (ULONG)value;
        }
        else if (ReadOption(argc, argv, &index, L"--har", &text)) {
            if (harFile || ! ParseUInt64(text, 16, &rawHar) || rawHar == 0)
                goto InvalidArguments;
            harFile = (HANDLE)(ULONG_PTR)rawHar;
        }
        else if (ReadOption(argc, argv, &index, L"--ca-file", &text)) {
            if (caFile || ! ParseUInt64(text, 16, &rawCa) || rawCa == 0)
                goto InvalidArguments;
            caFile = (HANDLE)(ULONG_PTR)rawCa;
        }
        else if (_wcsicmp(argv[index], L"--https-listen") == 0) {
            httpsListen = TRUE;
        }
        else if (_wcsicmp(argv[index], L"--https-test-preamble") == 0) {
            httpsTestPreamble = TRUE;
        }
        else if (_wcsicmp(argv[index], L"--https-import-host-root") == 0) {
            httpsImportHostRoot = TRUE;
        }
        else if (ReadOption(argc, argv, &index, L"--import-ca", &text)) {
            if (importCa || ! ParseUInt64(text, 16, &rawImport) || rawImport == 0)
                goto InvalidArguments;
            importCa = TRUE;
            importHandle = (HANDLE)(ULONG_PTR)rawImport;
        }
        else if (ReadOption(argc, argv, &index, L"--import-ca-path", &text)) {
            if (importCa || ! text || ! text[0])
                goto InvalidArguments;
            importCa = TRUE;
            importPath = text;
        }
        else if (ReadOption(argc, argv, &index, L"--remove-ca-path", &text)) {
            if (removeCa || ! text || ! text[0])
                goto InvalidArguments;
            removeCa = TRUE;
            importPath = text;
        }
        else if (ReadOption(argc, argv, &index, L"--store", &text)) {
            if (! text || ! text[0])
                goto InvalidArguments;
            storeName = text;
        }
        else if (_wcsicmp(argv[index], L"--system-store") == 0) {
            systemStore = TRUE;
        }
        else if (_wcsicmp(argv[index], L"--help") == 0 ||
                 _wcsicmp(argv[index], L"-h") == 0) {
            PrintUsage();
            return CAPTURE_BROKER_INVALID;
        }
        else {
            goto InvalidArguments;
        }
    }

    if (importCa || removeCa) {
        HANDLE file = importHandle;
        int importStatus;
        if (haveSection || haveFile || httpsListen)
            goto InvalidArguments;
        if (importPath) {
            file = CreateFileW(
                importPath, GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (file == INVALID_HANDLE_VALUE)
                return CAPTURE_BROKER_ERROR;
        }
        if (file == NULL || file == INVALID_HANDLE_VALUE)
            goto InvalidArguments;
        {
            char pem[4096];
            DWORD readSize = 0;
            SetFilePointer(file, 0, NULL, FILE_BEGIN);
            if (! ReadFile(file, pem, sizeof(pem) - 1, &readSize, NULL) ||
                    ! readSize) {
                if (importPath)
                    CloseHandle(file);
                return CAPTURE_BROKER_ERROR;
            }
            pem[readSize] = 0;
            if (systemStore)
                importStatus = importCa
                    ? CaptureCa_ImportPublicPemToUserSystemStore(
                          pem, readSize, storeName)
                    : CaptureCa_RemovePublicPemFromUserSystemStore(
                          pem, readSize, storeName);
            else
                importStatus = importCa
                    ? CaptureCa_ImportPublicPemToStore(
                          pem, readSize, storeName)
                    : CaptureCa_RemovePublicPemFromStore(
                          pem, readSize, storeName);
        }
        if (importPath)
            CloseHandle(file);
        return importStatus == CAPTURE_CA_OK ?
            CAPTURE_BROKER_OK : CAPTURE_BROKER_ERROR;
    }

    if (! haveSection || ! haveFile || !haveCaptureHigh ||
            !haveCaptureLow || !haveGeneration)
        goto InvalidArguments;
    if (httpsListen && (! harFile || ! caFile))
        goto InvalidArguments;
    if (! httpsListen && (harFile || caFile || httpsTestPreamble))
        goto InvalidArguments;

    sectionHandle = (HANDLE)(ULONG_PTR)rawSection;
    outputFile = (HANDLE)(ULONG_PTR)rawFile;
    void *mapped = MapViewOfFile(
        sectionHandle, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
    if (! mapped) {
        fwprintf(stderr, L"SbieCapture: MapViewOfFile failed: %lu\n",
                 GetLastError());
        CloseHandle(outputFile);
        return CAPTURE_BROKER_ERROR;
    }

    CAPTURE_BROKER_OPTIONS options;
    CAPTURE_HTTPS_RUNTIME *https = NULL;
    WSADATA wsa;
    int status;

    memset(&options, 0, sizeof(options));
    options.output_file = outputFile;
    options.stop_event = stopEvent;
    options.snap_length = snapLength;
    options.max_file_bytes = maxFileBytes;
    options.max_seconds = maxSeconds;
    options.rotate_count = rotateCount;
    options.expected_capture_id_high = rawCaptureHigh;
    options.expected_capture_id_low = rawCaptureLow;
    options.expected_generation = rawGeneration;

    if (httpsListen) {
        CAPTURE_HTTPS_OPTIONS httpsOptions;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            UnmapViewOfFile(mapped);
            CloseHandle(outputFile);
            return CAPTURE_BROKER_ERROR;
        }
        memset(&httpsOptions, 0, sizeof(httpsOptions));
        httpsOptions.har_file = harFile;
        httpsOptions.ca_file = caFile;
        httpsOptions.test_preamble = httpsTestPreamble;
        httpsOptions.redact = TRUE;
        httpsOptions.include_bodies = FALSE;
        httpsOptions.import_host_root = httpsImportHostRoot;
        httpsOptions.expected_context.magic = HTTPS_REDIRECT_CONTEXT_MAGIC;
        httpsOptions.expected_context.version = HTTPS_REDIRECT_CONTEXT_VERSION;
        httpsOptions.expected_context.capture_id_high = rawCaptureHigh;
        httpsOptions.expected_context.capture_id_low = rawCaptureLow;
        httpsOptions.expected_context.generation = rawGeneration;
        https = CaptureHttps_Start(
            (CAPTURE_BROKER_SECTION *)mapped, &httpsOptions);
        if (! https) {
            WSACleanup();
            UnmapViewOfFile(mapped);
            CloseHandle(outputFile);
            return CAPTURE_BROKER_ERROR;
        }
    }

    status = CaptureBroker_Run(
        (CAPTURE_BROKER_SECTION *)mapped, &options);
    if (https) {
        CaptureHttps_Stop(https);
        WSACleanup();
    }
    UnmapViewOfFile(mapped);
    CloseHandle(sectionHandle);
    if (stopEvent)
        CloseHandle(stopEvent);
    if (harFile)
        CloseHandle(harFile);
    if (caFile)
        CloseHandle(caFile);
    return status;

InvalidArguments:
    PrintUsage();
    return CAPTURE_BROKER_INVALID;
}
