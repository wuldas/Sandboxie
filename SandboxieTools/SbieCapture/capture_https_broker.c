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
// Broker HTTPS listen helper
//---------------------------------------------------------------------------

#define WIN32_LEAN_AND_MEAN

#include "capture_https_broker.h"
#include "capture_ca.h"

#include <stdio.h>


struct _CAPTURE_HTTPS_RUNTIME {

    HTTPS_MITM *mitm;
    CAPTURE_CA *ca;
    HANDLE thread;
    volatile LONG stop;
    BOOL test_preamble;
    HTTPS_REDIRECT_CONTEXT expected;
    CAPTURE_BROKER_SECTION *section;

};


static DWORD WINAPI CaptureHttps_AcceptThread(void *param)
{
    CAPTURE_HTTPS_RUNTIME *runtime = (CAPTURE_HTTPS_RUNTIME *)param;

    while (! runtime->stop) {
        SOCKET client = HttpsMitm_TryAccept(runtime->mitm, 100);
        HTTPS_REDIRECT_CONTEXT context;
        const HTTPS_REDIRECT_CONTEXT *serveContext = NULL;
        ULONG queryError = 0;

        if (client == INVALID_SOCKET)
            continue;
        if (runtime->test_preamble) {
            if (! HttpsMitm_RecvContext(client, &context)) {
                closesocket(client);
                continue;
            }
            serveContext = &context;
        } else if (HttpsMitm_QueryRedirectContextEx(
                client, &context, &queryError)) {
            serveContext = &context;
        } else {
            UNREFERENCED_PARAMETER(queryError);
            closesocket(client);
            continue;
        }
        HttpsMitm_ServeOnce(runtime->mitm, client, serveContext);
        closesocket(client);
    }
    return 0;
}


CAPTURE_HTTPS_RUNTIME *CaptureHttps_Start(
    CAPTURE_BROKER_SECTION *section,
    const CAPTURE_HTTPS_OPTIONS *options)
{
    CAPTURE_HTTPS_RUNTIME *runtime;
    HTTPS_MITM_OPTIONS mitmOptions;

    if (! section || ! options ||
            options->har_file == NULL ||
            options->har_file == INVALID_HANDLE_VALUE ||
            options->ca_file == NULL ||
            options->ca_file == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    runtime = (CAPTURE_HTTPS_RUNTIME *)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*runtime));
    if (! runtime)
        return NULL;
    runtime->section = section;
    runtime->test_preamble = options->test_preamble;
    runtime->expected = options->expected_context;
    if (options->import_host_root) {
        //
        // persistent CA: reuse one CA across capture sessions so the host
        // Root trust is granted only once.  the private key lives in the
        // owner's per-user config directory; create it first.
        //
        WCHAR caDir[512];
        WCHAR tmp[512];
        DWORD evLen = GetEnvironmentVariableW(L"LOCALAPPDATA", tmp, ARRAYSIZE(tmp));
        if (evLen == 0 || evLen >= ARRAYSIZE(tmp))
            goto fail;
        if (swprintf_s(caDir, ARRAYSIZE(caDir), L"%s\\SbieCapture", tmp) < 0)
            goto fail;
        if (! CreateDirectoryW(caDir, NULL) &&
                GetLastError() != ERROR_ALREADY_EXISTS) {
            goto fail;
        }
        runtime->ca = CaptureCa_LoadOrCreatePersistent(caDir);
        if (! runtime->ca)
            goto fail;
    }
    else {
        runtime->ca = CaptureCa_Create();
    }
    if (! runtime->ca)
        goto fail;
    if (CaptureCa_WritePublicPemHandle(runtime->ca, options->ca_file) !=
            CAPTURE_CA_OK) {
        goto fail;
    }
    FlushFileBuffers(options->ca_file);

    if (options->import_host_root) {
        //
        // import the session CA into the HOST user's real Root store:
        // trust decisions for sandboxed schannel clients are taken by
        // host-side machinery which cannot see the sandboxed registry
        // copy.  the import is idempotent: if this CA is already trusted
        // (the persistent case) the add is skipped and no UI is raised.
        //
        char pem[4096];
        ULONG pemLength = 0;
        if (CaptureCa_ExportPublicPem(
                runtime->ca, pem, sizeof(pem), &pemLength) != CAPTURE_CA_OK ||
                CaptureCa_ImportPublicPemToUserSystemStore(
                    pem, pemLength, L"Root") != CAPTURE_CA_OK) {
            goto fail;
        }
    }

    memset(&mitmOptions, 0, sizeof(mitmOptions));
    mitmOptions.ca = runtime->ca;
    mitmOptions.expected_context = options->test_preamble ?
        &runtime->expected : NULL;
    mitmOptions.har_file = options->har_file;
    mitmOptions.redact = options->redact;
    mitmOptions.include_bodies = options->include_bodies;
    mitmOptions.allow_unverified_upstream = options->test_preamble;
    runtime->mitm = HttpsMitm_Listen(&mitmOptions);
    if (! runtime->mitm)
        goto fail;

    section->https_listen_port = HttpsMitm_ListenPort(runtime->mitm);
    MemoryBarrier();

    runtime->thread = CreateThread(
        NULL, 4 * 1024 * 1024, CaptureHttps_AcceptThread, runtime, 0, NULL);
    if (! runtime->thread)
        goto fail;
    return runtime;

fail:
    CaptureHttps_Stop(runtime);
    return NULL;
}


USHORT CaptureHttps_ListenPort(const CAPTURE_HTTPS_RUNTIME *runtime)
{
    return runtime ? HttpsMitm_ListenPort(runtime->mitm) : 0;
}


void CaptureHttps_Stop(CAPTURE_HTTPS_RUNTIME *runtime)
{
    if (! runtime)
        return;
    InterlockedExchange(&runtime->stop, 1);
    if (runtime->thread) {
        WaitForSingleObject(runtime->thread, 5000);
        CloseHandle(runtime->thread);
    }
    HttpsMitm_Close(runtime->mitm);
    CaptureCa_Free(runtime->ca);
    if (runtime->section)
        runtime->section->https_listen_port = 0;
    HeapFree(GetProcessHeap(), 0, runtime);
}
