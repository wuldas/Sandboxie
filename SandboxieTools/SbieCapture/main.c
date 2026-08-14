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

#include "capture_broker.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>


static BOOL ParseUInt64(const WCHAR *text, ULONG64 *value)
{
    WCHAR *end = NULL;
    unsigned __int64 parsed;

    if (! text || ! text[0])
        return FALSE;
    errno = 0;
    parsed = _wcstoui64(text, &end, 0);
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
        L"[--stop-event HANDLE] [--snaplen N] [--max-file-bytes N] "
        L"[--max-seconds N] [--rotate-count N]\n");
}


int __cdecl wmain(int argc, WCHAR **argv)
{
    ULONG64 rawSection = 0;
    ULONG64 rawFile = 0;
    ULONG64 rawStopEvent = 0;
    ULONG64 value = 0;
    BOOL haveSection = FALSE;
    BOOL haveFile = FALSE;
    HANDLE sectionHandle = NULL;
    HANDLE outputFile = NULL;
    HANDLE stopEvent = NULL;
    ULONG snapLength = 0;
    ULONG maxFileBytes = 0;
    ULONG maxSeconds = 0;
    ULONG rotateCount = 0;
    int index;

    for (index = 1; index < argc; ++index) {
        const WCHAR *text = NULL;
        if (ReadOption(argc, argv, &index, L"--section", &text)) {
            if (haveSection || ! ParseUInt64(text, &rawSection) ||
                    rawSection == 0)
                goto InvalidArguments;
            haveSection = TRUE;
        }
        else if (ReadOption(argc, argv, &index, L"--file", &text)) {
            if (haveFile || ! ParseUInt64(text, &rawFile) ||
                    rawFile == 0)
                goto InvalidArguments;
            haveFile = TRUE;
        }
        else if (ReadOption(argc, argv, &index, L"--stop-event", &text)) {
            if (stopEvent || ! ParseUInt64(text, &rawStopEvent) ||
                    rawStopEvent == 0)
                goto InvalidArguments;
            stopEvent = (HANDLE)(ULONG_PTR)rawStopEvent;
        }
        else if (ReadOption(argc, argv, &index, L"--snaplen", &text)) {
            if (! ParseUInt64(text, &value) || value > 0xFFFFFFFFull)
                goto InvalidArguments;
            snapLength = (ULONG)value;
        }
        else if (ReadOption(
                     argc, argv, &index, L"--max-file-bytes", &text)) {
            if (! ParseUInt64(text, &value) || value > 0xFFFFFFFFull)
                goto InvalidArguments;
            maxFileBytes = (ULONG)value;
        }
        else if (ReadOption(argc, argv, &index, L"--max-seconds", &text)) {
            if (! ParseUInt64(text, &value) || value > 0xFFFFFFFFull)
                goto InvalidArguments;
            maxSeconds = (ULONG)value;
        }
        else if (ReadOption(argc, argv, &index, L"--rotate-count", &text)) {
            if (! ParseUInt64(text, &value) || value > 0xFFFFFFFFull)
                goto InvalidArguments;
            rotateCount = (ULONG)value;
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

    if (! haveSection || ! haveFile)
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
    memset(&options, 0, sizeof(options));
    options.output_file = outputFile;
    options.stop_event = stopEvent;
    options.snap_length = snapLength;
    options.max_file_bytes = maxFileBytes;
    options.max_seconds = maxSeconds;
    options.rotate_count = rotateCount;

    int status = CaptureBroker_Run(
        (CAPTURE_BROKER_SECTION *)mapped, &options);
    UnmapViewOfFile(mapped);
    CloseHandle(sectionHandle);
    if (stopEvent)
        CloseHandle(stopEvent);
    return status;

InvalidArguments:
    PrintUsage();
    return CAPTURE_BROKER_INVALID;
}
