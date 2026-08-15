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
// Capture Server -- using PipeServer
//---------------------------------------------------------------------------

#include "stdafx.h"

#include "CaptureServer.h"
#include "capturewire.h"
#include "capturebrokerwire.h"
#include "core/dll/sbieapi.h"
#include "core/drv/api_defs.h"
#include "core/drv/api_flags.h"

#include <wincrypt.h>
#include <sddl.h>
#include <stddef.h>


//---------------------------------------------------------------------------
// Defines and Types
//---------------------------------------------------------------------------


#define CAPTURE_MAX_SESSIONS_PER_OWNER  16
#define CAPTURE_MAX_SESSIONS_GLOBAL     256
#define CAPTURE_MAX_STOPPED_PER_OWNER   16
#define CAPTURE_MAX_LIST_ENTRIES        64
#define CAPTURE_MAX_ACTIVE_PER_PRINCIPAL 16
#define CAPTURE_MAX_ACTIVE_GLOBAL       CAPTURE_DRIVER_MAX_SESSIONS
#define CAPTURE_DEFAULT_SNAP_LENGTH     256
#define CAPTURE_DEFAULT_MAX_FILE_BYTES  (64u * 1024u * 1024u)
#define CAPTURE_DEFAULT_MAX_SECONDS     300


typedef struct _CAPTURE_SESSION_OBJ {

    LIST_ELEM list_elem;
    ULONG owner_pid;
    ULONG owner_session_id;
    ULONG64 owner_create_time;
    WCHAR owner_sid[96];
    BOOLEAN backend_active;
    HANDLE export_file;
    HANDLE section_handle;
    HANDLE broker_job;
    HANDLE broker_process;
    HANDLE broker_thread;
    HANDLE broker_stop_event;
    ULONG snap_length;
    ULONG max_file_bytes;
    ULONG max_seconds;
    ULONG rotate_count;
    ULONG64 waiting_deadline;
    ULONG stopped_event_head;
    ULONG stopped_event_count;
    CAPTURE_CONNECTION_EVENT *stopped_events;
    CAPTURE_SESSION_INFO info;

} CAPTURE_SESSION_OBJ;


static_assert(sizeof(CAPTURE_DRIVER_SESSION_ID) == sizeof(CAPTURE_SESSION_ID),
              "driver and service capture identifiers differ");
static_assert(sizeof(CAPTURE_DRIVER_EVENT) == sizeof(CAPTURE_CONNECTION_EVENT),
              "driver and service capture events differ");
static_assert(sizeof(CAPTURE_DRIVER_PACKET_READ) ==
              CAPTURE_DRIVER_PACKET_READ_BASE_SIZE + sizeof(CAPTURE_PACKET_RECORD),
              "driver packet read ABI differs");
static_assert(sizeof(CAPTURE_PACKET_EVENT) == sizeof(CAPTURE_PACKET_RECORD),
              "service packet event ABI differs");
static_assert(FIELD_OFFSET(CAPTURE_DRIVER_EVENT, local_address) ==
              FIELD_OFFSET(CAPTURE_CONNECTION_EVENT, local_address),
              "driver and service capture event layout differs");


//---------------------------------------------------------------------------
// Helpers
//---------------------------------------------------------------------------


static BOOLEAN CaptureServer_QueryTokenIdentity(
    HANDLE token, ULONG *sessionId, TOKEN_USER **tokenUser)
{
    ULONG returnedSize = 0;
    if (! GetTokenInformation(token, TokenSessionId, sessionId,
                              sizeof(*sessionId), &returnedSize)) {
        return FALSE;
    }

    ULONG tokenSize = 0;
    GetTokenInformation(token, TokenUser, NULL, 0, &tokenSize);
    if (! tokenSize)
        return FALSE;

    *tokenUser = (TOKEN_USER *)HeapAlloc(GetProcessHeap(), 0, tokenSize);
    if (! *tokenUser)
        return FALSE;

    if (! GetTokenInformation(
            token, TokenUser, *tokenUser, tokenSize, &returnedSize)) {
        HeapFree(GetProcessHeap(), 0, *tokenUser);
        *tokenUser = NULL;
        return FALSE;
    }

    return TRUE;
}


static BOOLEAN CaptureServer_TokenMatchesOwner(
    HANDLE token, ULONG expectedSessionId, const WCHAR *expectedSid)
{
    ULONG sessionId = 0;
    TOKEN_USER *user = NULL;
    LPWSTR sidString = NULL;
    BOOLEAN matched = FALSE;
    if (CaptureServer_QueryTokenIdentity(token, &sessionId, &user) &&
            ConvertSidToStringSidW(user->User.Sid, &sidString)) {
        matched = sessionId == expectedSessionId &&
            _wcsicmp(sidString, expectedSid) == 0;
    }
    if (sidString)
        LocalFree(sidString);
    if (user)
        HeapFree(GetProcessHeap(), 0, user);
    return matched;
}


#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

#ifndef STATUS_NO_TOKEN
#define STATUS_NO_TOKEN                 ((ULONG)0xC000007CL)
#endif
#ifndef STATUS_NO_IMPERSONATION_TOKEN
#define STATUS_NO_IMPERSONATION_TOKEN   ((ULONG)0xC000005CL)
#endif
#ifndef STATUS_CONTEXT_MISMATCH
#define STATUS_CONTEXT_MISMATCH         ((ULONG)0xC0000206L)
#endif
#ifndef STATUS_INVALID_SID
#define STATUS_INVALID_SID              ((ULONG)0xC0000078L)
#endif

static HANDLE CaptureServer_OpenCallerProcess(ULONG processId)
{
    HANDLE process = OpenProcess(
        PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (process)
        return process;
    return OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
}

static BOOLEAN CaptureServer_IsValidBoxName(const WCHAR *boxName)
{
    ULONG index;
    for (index = 0; index < BOXNAME_COUNT - 2; ++index) {
        WCHAR value = boxName[index];
        if (! value)
            break;
        if ((value >= L'0' && value <= L'9') ||
                (value >= L'A' && value <= L'Z') ||
                (value >= L'a' && value <= L'z') || value == L'_') {
            continue;
        }
        return FALSE;
    }

    return index != 0 && ! boxName[index];
}


static ULONG CaptureServer_GetCallerIdentity(
    ULONG *processId, ULONG *sessionId, ULONG64 *createTime,
    WCHAR sidString[96])
{
    ULONG status = STATUS_ACCESS_DENIED;
    HANDLE process = NULL;
    HANDLE processToken = NULL;
    HANDLE callerToken = NULL;
    TOKEN_USER *processUser = NULL;
    TOKEN_USER *callerUser = NULL;
    LPWSTR allocatedSid = NULL;
    BOOLEAN impersonated = FALSE;
    ULONG processTokenSession = 0;
    ULONG callerTokenSession = 0;
    ULONG64 connectedCreateTime = 0;
    ULONG64 liveCreateTime = 0;
    FILETIME processTime = { 0 };
    FILETIME exitTime = { 0 };
    FILETIME kernelTime = { 0 };
    FILETIME userTime = { 0 };

    *processId = PipeServer::GetCallerProcessId();

    LONG queryStatus = SbieApi_QueryProcess(
        (HANDLE)(ULONG_PTR)*processId, NULL, NULL, NULL, NULL);
    if (NT_SUCCESS(queryStatus))
        return STATUS_ACCESS_DENIED;
    if (queryStatus != STATUS_INVALID_CID)
        return queryStatus;

    if (! PipeServer::GetCallerProcessCreateTime(&connectedCreateTime))
        return STATUS_INVALID_CID;

    process = CaptureServer_OpenCallerProcess(*processId);
    if (! process) {
        status = STATUS_INVALID_CID;
        goto cleanup;
    }

    if (! GetProcessTimes(
            process, &processTime, &exitTime, &kernelTime, &userTime)) {
        status = STATUS_INVALID_CID;
        goto cleanup;
    }

    liveCreateTime =
        ((ULONG64)processTime.dwHighDateTime << 32) |
        processTime.dwLowDateTime;
    if (! liveCreateTime || liveCreateTime != connectedCreateTime) {
        status = STATUS_REVISION_MISMATCH;
        goto cleanup;
    }

    if (! OpenProcessToken(process, TOKEN_QUERY, &processToken) ||
            ! CaptureServer_QueryTokenIdentity(
                processToken, &processTokenSession, &processUser)) {
        status = STATUS_NO_TOKEN;
        goto cleanup;
    }

    status = PipeServer::ImpersonateCaller();
    if (! NT_SUCCESS(status))
        goto cleanup;
    impersonated = TRUE;

    if (! OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &callerToken) ||
            ! CaptureServer_QueryTokenIdentity(
                callerToken, &callerTokenSession, &callerUser)) {
        status = STATUS_NO_IMPERSONATION_TOKEN;
        goto cleanup;
    }

    if (processTokenSession != callerTokenSession ||
            ! EqualSid(processUser->User.Sid, callerUser->User.Sid)) {
        status = STATUS_CONTEXT_MISMATCH;
        goto cleanup;
    }

    if (! ConvertSidToStringSidW(processUser->User.Sid, &allocatedSid) ||
            wcslen(allocatedSid) >= 96) {
        status = STATUS_INVALID_SID;
        goto cleanup;
    }

    wcscpy_s(sidString, 96, allocatedSid);
    *sessionId = processTokenSession;
    *createTime = liveCreateTime;
    status = STATUS_SUCCESS;

cleanup:
    if (allocatedSid)
        LocalFree(allocatedSid);
    if (callerUser)
        HeapFree(GetProcessHeap(), 0, callerUser);
    if (processUser)
        HeapFree(GetProcessHeap(), 0, processUser);
    if (callerToken)
        CloseHandle(callerToken);
    if (impersonated)
        RevertToSelf();
    if (processToken)
        CloseHandle(processToken);
    if (process)
        CloseHandle(process);

    return status;
}


static ULONG64 CaptureServer_GetSystemTime(void)
{
    FILETIME time;
    GetSystemTimeAsFileTime(&time);
    return ((ULONG64)time.dwHighDateTime << 32) | time.dwLowDateTime;
}


static BOOLEAN CaptureServer_GenerateId(CAPTURE_SESSION_ID *captureId)
{
    HCRYPTPROV provider = NULL;
    BOOLEAN ok = CryptAcquireContext(&provider, NULL, MS_ENH_RSA_AES_PROV,
                                     PROV_RSA_AES,
                                     CRYPT_VERIFYCONTEXT | CRYPT_SILENT);
    if (! ok)
        return FALSE;

    ok = CryptGenRandom(provider, sizeof(*captureId), (BYTE *)captureId);
    CryptReleaseContext(provider, 0);

    return ok && (captureId->high != 0 || captureId->low != 0);
}


static BOOLEAN CaptureServer_IdExists(
    LIST *sessions, const CAPTURE_SESSION_ID *captureId)
{
    CAPTURE_SESSION_OBJ *entry =
        (CAPTURE_SESSION_OBJ *)List_Head(sessions);
    while (entry) {
        if (entry->info.capture_id.high == captureId->high &&
                entry->info.capture_id.low == captureId->low)
            return TRUE;
        entry = (CAPTURE_SESSION_OBJ *)List_Next(entry);
    }

    return FALSE;
}


static BOOLEAN CaptureServer_IdEquals(
    const CAPTURE_SESSION_ID *left, const CAPTURE_SESSION_ID *right)
{
    return left->high == right->high && left->low == right->low;
}


static ULONG CaptureServer_GetProcessCreateTime(
    HANDLE process, ULONG64 *createTime)
{
    FILETIME creation = { 0 };
    FILETIME exitTime = { 0 };
    FILETIME kernelTime = { 0 };
    FILETIME userTime = { 0 };
    if (! process || ! createTime ||
            ! GetProcessTimes(
                process, &creation, &exitTime, &kernelTime, &userTime)) {
        return STATUS_INVALID_CID;
    }

    *createTime = ((ULONG64)creation.dwHighDateTime << 32) |
        creation.dwLowDateTime;
    return *createTime ? STATUS_SUCCESS : STATUS_INVALID_CID;
}


static ULONG CaptureServer_DuplicateWritableFile(
    ULONG callerPid,
    ULONG64 expectedCreateTime,
    ULONG64 rawHandle,
    HANDLE *fileHandle)
{
    if (! callerPid || ! rawHandle || ! fileHandle)
        return STATUS_INVALID_PARAMETER;

    *fileHandle = NULL;
    HANDLE callerProcess = OpenProcess(
        PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE, callerPid);
    if (! callerProcess)
        return STATUS_INVALID_CID;

    ULONG64 liveCreateTime = 0;
    ULONG identityStatus = CaptureServer_GetProcessCreateTime(
        callerProcess, &liveCreateTime);
    if (! NT_SUCCESS(identityStatus) ||
            liveCreateTime != expectedCreateTime) {
        CloseHandle(callerProcess);
        return STATUS_REVISION_MISMATCH;
    }

    HANDLE duplicate = NULL;
    BOOL ok = DuplicateHandle(
        callerProcess,
        (HANDLE)(ULONG_PTR)rawHandle,
        GetCurrentProcess(),
        &duplicate,
        GENERIC_READ | GENERIC_WRITE,
        FALSE,
        0);
    CloseHandle(callerProcess);
    if (! ok || ! duplicate)
        return STATUS_INVALID_HANDLE;

    if (GetFileType(duplicate) != FILE_TYPE_DISK) {
        CloseHandle(duplicate);
        return STATUS_INVALID_PARAMETER;
    }

    BY_HANDLE_FILE_INFORMATION information;
    if (! GetFileInformationByHandle(duplicate, &information) ||
            (information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        CloseHandle(duplicate);
        return STATUS_INVALID_PARAMETER;
    }

    *fileHandle = duplicate;
    return STATUS_SUCCESS;
}


static BOOLEAN CaptureServer_IsPacketMode(
    const CAPTURE_SESSION_OBJ *session)
{
    return session && session->info.mode == CAPTURE_MODE_PACKETS;
}


static BOOLEAN CaptureServer_IsWaitingForBackend(
    const CAPTURE_SESSION_OBJ *session)
{
    return session && session->info.state == CAPTURE_STATE_WAITING_FOR_BACKEND;
}


static ULONG CaptureServer_StartBroker(CAPTURE_SESSION_OBJ *session);
static ULONG CaptureServer_StopBroker(CAPTURE_SESSION_OBJ *session);
static void CaptureServer_PollBroker(CAPTURE_SESSION_OBJ *session);
static void CaptureServer_UpdateBrokerCounters(CAPTURE_SESSION_OBJ *session);


#define SBIE_PROC_THREAD_ATTRIBUTE_HANDLE_LIST 0x00020002

typedef struct _SBIE_STARTUPINFOEXW {
    STARTUPINFOW StartupInfo;
    PVOID attribute_list;
} SBIE_STARTUPINFOEXW;

typedef BOOL (WINAPI *SBIE_INITIALIZE_ATTRIBUTE_LIST)(
    PVOID, DWORD, DWORD, PSIZE_T);
typedef BOOL (WINAPI *SBIE_UPDATE_ATTRIBUTE)(
    PVOID, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID, PSIZE_T);
typedef void (WINAPI *SBIE_DELETE_ATTRIBUTE_LIST)(PVOID);


static ULONG CaptureServer_QueryDriver(ULONG *driverFlags)
{
    UCHAR buffer[CAPTURE_DRIVER_CONTROL_BASE_SIZE];
    memzero(buffer, sizeof(buffer));

    CAPTURE_DRIVER_CONTROL *control = (CAPTURE_DRIVER_CONTROL *)buffer;
    control->version = CAPTURE_DRIVER_VERSION;
    control->size = sizeof(buffer);
    control->operation = CAPTURE_DRIVER_CONTROL_QUERY;

    LONG status = SbieApi_Call(API_CAPTURE_CONTROL, 1, (ULONG_PTR)control);
    if (! NT_SUCCESS(status))
        return status;
    if (control->version != CAPTURE_DRIVER_VERSION ||
            control->size != sizeof(buffer) ||
            control->queue_capacity != CAPTURE_DRIVER_QUEUE_CAPACITY) {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    if (driverFlags)
        *driverFlags = control->flags;

    return STATUS_SUCCESS;
}


static ULONG CaptureServer_StartDriver(
    CAPTURE_SESSION_OBJ *session, const WCHAR *targetSid)
{
    UCHAR buffer[CAPTURE_DRIVER_CONTROL_BASE_SIZE];
    memzero(buffer, sizeof(buffer));

    CAPTURE_DRIVER_CONTROL *control = (CAPTURE_DRIVER_CONTROL *)buffer;
    control->version = CAPTURE_DRIVER_VERSION;
    control->size = sizeof(buffer);
    control->operation = CAPTURE_DRIVER_CONTROL_START;
    control->scope = session->info.scope;
    control->flags = session->info.flags;
    if (session->info.mode == CAPTURE_MODE_PACKETS)
        control->flags |= CAPTURE_DRIVER_FLAG_INCLUDE_PAYLOAD;
    control->target_pid = session->info.target_pid;
    control->target_session_id = session->info.target_session_id;
    control->queue_capacity = CAPTURE_DRIVER_QUEUE_CAPACITY;
    control->target_process_create_time =
        session->info.target_process_create_time;
    control->capture_id.high = session->info.capture_id.high;
    control->capture_id.low = session->info.capture_id.low;
    wcscpy_s(control->box_name, ARRAYSIZE(control->box_name),
             session->info.box_name);
    wcscpy_s(control->sid_string, ARRAYSIZE(control->sid_string), targetSid);

    return SbieApi_Call(API_CAPTURE_CONTROL, 1, (ULONG_PTR)control);
}


static ULONG CaptureServer_MapDriver(CAPTURE_SESSION_OBJ *session)
{
    CAPTURE_DRIVER_MAP map;
    memzero(&map, sizeof(map));
    map.version = CAPTURE_DRIVER_VERSION;
    map.size = sizeof(map);
    map.capture_id.high = session->info.capture_id.high;
    map.capture_id.low = session->info.capture_id.low;

    ULONG status = SbieApi_Call(API_CAPTURE_MAP, 1, (ULONG_PTR)&map);
    if (! NT_SUCCESS(status))
        return status;
    if (map.version != CAPTURE_DRIVER_VERSION ||
            map.size != sizeof(map) ||
            map.record_capacity == 0 ||
            map.section_size == 0 ||
            map.section_handle == 0 ||
            map.reserved) {
        if (map.section_handle)
            CloseHandle((HANDLE)(ULONG_PTR)map.section_handle);
        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    session->section_handle = (HANDLE)(ULONG_PTR)map.section_handle;
    return STATUS_SUCCESS;
}


static ULONG CaptureServer_StopDriver(const CAPTURE_SESSION_ID *captureId)
{
    UCHAR buffer[CAPTURE_DRIVER_CONTROL_BASE_SIZE];
    memzero(buffer, sizeof(buffer));

    CAPTURE_DRIVER_CONTROL *control = (CAPTURE_DRIVER_CONTROL *)buffer;
    control->version = CAPTURE_DRIVER_VERSION;
    control->size = sizeof(buffer);
    control->operation = CAPTURE_DRIVER_CONTROL_STOP;
    control->capture_id.high = captureId->high;
    control->capture_id.low = captureId->low;

    return SbieApi_Call(API_CAPTURE_CONTROL, 1, (ULONG_PTR)control);
}


static ULONG CaptureServer_ReadDriverEvents(
    CAPTURE_SESSION_OBJ *session,
    CAPTURE_CONNECTION_EVENT *events,
    ULONG maxEvents,
    ULONG *returnedEvents,
    ULONG *remainingEvents,
    ULONG64 *nextSequence,
    ULONG64 *oldestSequence,
    ULONG64 *newestSequence,
    ULONG64 *droppedCount)
{
    if (! maxEvents || maxEvents > CAPTURE_MAX_EVENT_ENTRIES)
        return STATUS_INVALID_PARAMETER;

    ULONG readSize = CAPTURE_DRIVER_READ_BASE_SIZE +
        maxEvents * sizeof(CAPTURE_DRIVER_EVENT);
    CAPTURE_DRIVER_READ *read = (CAPTURE_DRIVER_READ *)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, readSize);
    if (! read)
        return STATUS_INSUFFICIENT_RESOURCES;

    read->version = CAPTURE_DRIVER_VERSION;
    read->size = readSize;
    read->capture_id.high = session->info.capture_id.high;
    read->capture_id.low = session->info.capture_id.low;
    read->max_events = maxEvents;

    ULONG status = SbieApi_Call(
        API_CAPTURE_READ, 2, (ULONG_PTR)read, (ULONG_PTR)readSize);
    if (NT_SUCCESS(status)) {
        if (read->version != CAPTURE_DRIVER_VERSION ||
                read->size != readSize ||
                read->capture_id.high != session->info.capture_id.high ||
                read->capture_id.low != session->info.capture_id.low ||
                read->max_events != maxEvents ||
                read->returned_events > maxEvents ||
                read->remaining_events > CAPTURE_DRIVER_QUEUE_CAPACITY ||
                read->reserved) {
            status = STATUS_INVALID_NETWORK_RESPONSE;
        }
    }

    if (NT_SUCCESS(status)) {
        for (ULONG index = 0; index < read->returned_events; ++index) {
            const CAPTURE_DRIVER_EVENT *event = &read->events[index];
            if ((event->address_family != CAPTURE_ADDRESS_FAMILY_IPV4 &&
                 event->address_family != CAPTURE_ADDRESS_FAMILY_IPV6) ||
                    (event->event_type != CAPTURE_DRIVER_EVENT_CONNECT &&
                     event->event_type != CAPTURE_DRIVER_EVENT_ACCEPT) ||
                    (event->direction != CAPTURE_DRIVER_DIRECTION_OUTBOUND &&
                     event->direction != CAPTURE_DRIVER_DIRECTION_INBOUND) ||
                    event->reserved1 || event->reserved2 ||
                    event->session_id != session->info.target_session_id) {
                status = STATUS_INVALID_NETWORK_RESPONSE;
                break;
            }

            if (session->info.scope == CAPTURE_SCOPE_PROCESS &&
                    (event->process_id != session->info.target_pid ||
                     event->process_create_time !=
                        session->info.target_process_create_time)) {
                status = STATUS_INVALID_NETWORK_RESPONSE;
                break;
            }
        }
    }

    if (NT_SUCCESS(status)) {
        if (read->returned_events) {
            memcpy(events, read->events,
                   read->returned_events * sizeof(CAPTURE_CONNECTION_EVENT));
        }
        *returnedEvents = read->returned_events;
        *remainingEvents = read->remaining_events;
        *nextSequence = read->next_sequence;
        *oldestSequence = read->oldest_sequence;
        *newestSequence = read->newest_sequence;
        *droppedCount = read->dropped_count;
    }

    HeapFree(GetProcessHeap(), 0, read);
    return status;
}


static ULONG CaptureServer_ValidateVersion(
    const CAPTURE_VERSIONED_REQUEST *request, ULONG minimumSize)
{
    if (request->h.length < minimumSize || request->struct_size < minimumSize ||
            request->struct_size > request->h.length)
        return STATUS_INVALID_PARAMETER;

    if (request->wire_version != CAPTURE_WIRE_VERSION)
        return STATUS_NOT_SUPPORTED;

    return STATUS_SUCCESS;
}


#if 0
static ULONG CaptureServer_ReadDriverPayload(
    CAPTURE_SESSION_OBJ *session,
    BOOLEAN stream,
    CAPTURE_PACKET_EVENT *records,
    ULONG maxRecords,
    ULONG *returnedRecords,
    ULONG *remainingRecords,
    ULONG64 *nextSequence,
    ULONG64 *oldestSequence,
    ULONG64 *newestSequence,
    ULONG64 *droppedCount)
{
    const ULONG maximumRecords = stream ?
        CAPTURE_MAX_STREAM_ENTRIES : CAPTURE_MAX_PACKET_ENTRIES;
    if (! session || ! records || ! returnedRecords || ! remainingRecords ||
            ! nextSequence || ! oldestSequence || ! newestSequence ||
            ! droppedCount || ! maxRecords || maxRecords > maximumRecords) {
        return STATUS_INVALID_PARAMETER;
    }

    ULONG readSize = CAPTURE_DRIVER_PACKET_READ_BASE_SIZE +
        maxRecords * sizeof(CAPTURE_PACKET_RECORD);
    CAPTURE_DRIVER_PACKET_READ *read =
        (CAPTURE_DRIVER_PACKET_READ *)HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, readSize);
    if (! read)
        return STATUS_INSUFFICIENT_RESOURCES;

    read->version = CAPTURE_DRIVER_VERSION;
    read->size = readSize;
    read->capture_id.high = session->info.capture_id.high;
    read->capture_id.low = session->info.capture_id.low;
    read->max_records = maxRecords;

    ULONG status = SbieApi_Call(
        stream ? API_CAPTURE_READ_STREAMS : API_CAPTURE_READ_PACKETS,
        2, (ULONG_PTR)read, (ULONG_PTR)readSize);
    if (NT_SUCCESS(status)) {
        if (read->version != CAPTURE_DRIVER_VERSION ||
                read->size != readSize ||
                read->capture_id.high != session->info.capture_id.high ||
                read->capture_id.low != session->info.capture_id.low ||
                read->max_records != maxRecords ||
                read->returned_records > maxRecords ||
                read->remaining_records > CAPTURE_DRIVER_QUEUE_CAPACITY ||
                read->reserved) {
            status = STATUS_INVALID_NETWORK_RESPONSE;
        }
    }

    if (NT_SUCCESS(status)) {
        for (ULONG index = 0; index < read->returned_records; ++index) {
            const CAPTURE_PACKET_RECORD *record = &read->records[index];
            const BOOLEAN validLayer = stream ?
                record->layer == CAPTURE_PACKET_LAYER_STREAM :
                (record->layer == CAPTURE_PACKET_LAYER_TRANSPORT ||
                 record->layer == CAPTURE_PACKET_LAYER_DATAGRAM);
            if (! validLayer ||
                    (record->direction !=
                        CAPTURE_PACKET_DIRECTION_OUTBOUND &&
                     record->direction != CAPTURE_PACKET_DIRECTION_INBOUND) ||
                    (record->address_family != CAPTURE_ADDRESS_FAMILY_IPV4 &&
                     record->address_family != CAPTURE_ADDRESS_FAMILY_IPV6) ||
                    record->captured_length > CAPTURE_PACKET_SNAPLEN_MAX ||
                    record->original_length < record->captured_length ||
                    record->reserved1 || record->reserved2 ||
                    record->session_id != session->info.target_session_id) {
                status = STATUS_INVALID_NETWORK_RESPONSE;
                break;
            }

            if (session->info.scope == CAPTURE_SCOPE_PROCESS &&
                    (record->process_id != session->info.target_pid ||
                     record->process_create_time !=
                        session->info.target_process_create_time)) {
                status = STATUS_INVALID_NETWORK_RESPONSE;
                break;
            }
        }
    }

    if (NT_SUCCESS(status)) {
        if (read->returned_records) {
            memcpy(records, read->records,
                   read->returned_records * sizeof(CAPTURE_PACKET_EVENT));
        }
        *returnedRecords = read->returned_records;
        *remainingRecords = read->remaining_records;
        *nextSequence = read->next_sequence;
        *oldestSequence = read->oldest_sequence;
        *newestSequence = read->newest_sequence;
        *droppedCount = read->dropped_count;
    }

    HeapFree(GetProcessHeap(), 0, read);
    return status;
}
#endif


//---------------------------------------------------------------------------
// Constructor and Destructor
//---------------------------------------------------------------------------


CaptureServer::CaptureServer(PipeServer *pipeServer)
{
    m_heap = HeapCreate(0, 0, 0);
    if (! m_heap)
        m_heap = GetProcessHeap();

    InitializeCriticalSectionAndSpinCount(&m_lock, 1000);
    List_Init(&m_sessions);

    pipeServer->Register(MSGID_CAPTURE, this, Handler);
}


CaptureServer::~CaptureServer()
{
    EnterCriticalSection(&m_lock);

    while (List_Head(&m_sessions))
        DeleteSession((CAPTURE_SESSION_OBJ *)List_Head(&m_sessions));

    LeaveCriticalSection(&m_lock);
    DeleteCriticalSection(&m_lock);

    if (m_heap != GetProcessHeap())
        HeapDestroy(m_heap);
}


//---------------------------------------------------------------------------
// Handler
//---------------------------------------------------------------------------


MSG_HEADER *CaptureServer::Handler(void *_this, MSG_HEADER *msg)
{
    CaptureServer *pThis = (CaptureServer *)_this;

    if (msg->msgid == MSGID_CAPTURE_NOTIFICATION) {
        ULONG64 ownerCreateTime = 0;
        if (PipeServer::GetCallerProcessCreateTime(&ownerCreateTime)) {
            pThis->NotifyHandler(
                (HANDLE)(ULONG_PTR)PipeServer::GetCallerProcessId(),
                ownerCreateTime);
        }
        return NULL;
    }

    if (msg->length < sizeof(MSG_HEADER) ||
            msg->length > CAPTURE_MAX_REQUEST_SIZE)
        return SHORT_REPLY(STATUS_INVALID_PARAMETER);

    if (msg->msgid == MSGID_CAPTURE_QUERY_CAPS)
        return pThis->QueryCapsHandler(msg);
    if (msg->msgid == MSGID_CAPTURE_START)
        return pThis->StartHandler(msg);
    if (msg->msgid == MSGID_CAPTURE_STOP)
        return pThis->StopHandler(msg);
    if (msg->msgid == MSGID_CAPTURE_GET_STATUS)
        return pThis->GetStatusHandler(msg);
    if (msg->msgid == MSGID_CAPTURE_LIST)
        return pThis->ListHandler(msg);
    if (msg->msgid == MSGID_CAPTURE_READ_EVENTS)
        return pThis->ReadEventsHandler(msg);
    if (msg->msgid == MSGID_CAPTURE_SET_EXPORT)
        return pThis->SetExportHandler(msg);
    if (msg->msgid == MSGID_CAPTURE_SET_HAR_EXPORT)
        return pThis->SetHarExportHandler(msg);

    return SHORT_REPLY(STATUS_INVALID_SYSTEM_SERVICE);
}


//---------------------------------------------------------------------------
// QueryCapsHandler
//---------------------------------------------------------------------------


MSG_HEADER *CaptureServer::QueryCapsHandler(MSG_HEADER *msg)
{
    CAPTURE_QUERY_CAPS_REQ *req = (CAPTURE_QUERY_CAPS_REQ *)msg;
    ULONG status = CaptureServer_ValidateVersion(
        &req->v, sizeof(CAPTURE_QUERY_CAPS_REQ));
    if (! NT_SUCCESS(status))
        return SHORT_REPLY(status);

    CAPTURE_QUERY_CAPS_RPL *rpl = (CAPTURE_QUERY_CAPS_RPL *)
        LONG_REPLY(sizeof(CAPTURE_QUERY_CAPS_RPL));
    if (! rpl)
        return SHORT_REPLY(STATUS_INSUFFICIENT_RESOURCES);

    memzero(rpl, sizeof(*rpl));
    rpl->h.length = sizeof(*rpl);
    rpl->h.status = STATUS_SUCCESS;
    rpl->wire_version = CAPTURE_WIRE_VERSION;
    rpl->struct_size = sizeof(*rpl);
    rpl->min_wire_version = CAPTURE_WIRE_VERSION;
    rpl->max_wire_version = CAPTURE_WIRE_VERSION;
    rpl->capabilities = CAPTURE_CAP_CONTROL;
    ULONG driverFlags = 0;
    if (NT_SUCCESS(CaptureServer_QueryDriver(&driverFlags))) {
        rpl->capabilities |= CAPTURE_CAP_CONNECTION_AUDIT;
#if CAPTURE_PACKET_CAPTURE_RELEASE_GATE
        if (driverFlags & CAPTURE_DRIVER_FLAG_INCLUDE_PAYLOAD)
            rpl->capabilities |= CAPTURE_CAP_PACKET_CAPTURE |
                CAPTURE_CAP_PCAPNG_EXPORT;
#endif
    }
    rpl->max_sessions_per_owner = CAPTURE_MAX_SESSIONS_PER_OWNER;
    rpl->max_list_entries = CAPTURE_MAX_LIST_ENTRIES;
    rpl->max_event_entries = CAPTURE_MAX_EVENT_ENTRIES;

    return &rpl->h;
}


//---------------------------------------------------------------------------
// StartHandler
//---------------------------------------------------------------------------


MSG_HEADER *CaptureServer::StartHandler(MSG_HEADER *msg)
{
    CAPTURE_START_REQ *req = (CAPTURE_START_REQ *)msg;
    ULONG status = CaptureServer_ValidateVersion(&req->v,
                                                  CAPTURE_START_REQ_V1_SIZE);
    if (! NT_SUCCESS(status))
        return SHORT_REPLY(status);

    if (req->scope != CAPTURE_SCOPE_BOX &&
            req->scope != CAPTURE_SCOPE_PROCESS)
        return SHORT_REPLY(STATUS_INVALID_PARAMETER);

    if ((req->mode & ~(CAPTURE_MODE_CONNECTIONS | CAPTURE_MODE_PACKETS |
                       CAPTURE_MODE_HTTPS)) != 0 || req->mode == 0)
        return SHORT_REPLY(STATUS_INVALID_PARAMETER);

    if (req->mode != CAPTURE_MODE_CONNECTIONS &&
            req->mode != CAPTURE_MODE_PACKETS)
        return SHORT_REPLY(STATUS_NOT_SUPPORTED);

    if ((req->flags & ~CAPTURE_FLAG_ALL) != 0)
        return SHORT_REPLY(STATUS_INVALID_PARAMETER);

    if (req->v.struct_size > CAPTURE_START_REQ_V1_SIZE &&
            req->v.struct_size < sizeof(CAPTURE_START_REQ))
        return SHORT_REPLY(STATUS_INVALID_PARAMETER);

    if (req->v.struct_size >= sizeof(CAPTURE_START_REQ)) {
        if (req->reserved)
            return SHORT_REPLY(STATUS_INVALID_PARAMETER);
        if (req->snap_length != 0 &&
                (req->snap_length < CAPTURE_SNAP_LENGTH_MIN ||
                 req->snap_length > CAPTURE_SNAP_LENGTH_MAX))
            return SHORT_REPLY(STATUS_INVALID_PARAMETER);
        if (req->max_seconds > CAPTURE_MAX_SECONDS)
            return SHORT_REPLY(STATUS_INVALID_PARAMETER);
        if (req->rotate_count > CAPTURE_MAX_ROTATE_COUNT)
            return SHORT_REPLY(STATUS_INVALID_PARAMETER);
    }

    ULONG snapLength = CAPTURE_DEFAULT_SNAP_LENGTH;
    ULONG maxFileBytes = CAPTURE_DEFAULT_MAX_FILE_BYTES;
    ULONG maxSeconds = CAPTURE_DEFAULT_MAX_SECONDS;
    ULONG rotateCount = 0;
    if (req->v.struct_size >= sizeof(CAPTURE_START_REQ)) {
        snapLength = req->snap_length;
        maxFileBytes = req->max_file_bytes;
        maxSeconds = req->max_seconds;
        rotateCount = req->rotate_count;
    }

    if (! CaptureServer_IsValidBoxName(req->box_name))
        return SHORT_REPLY(STATUS_INVALID_PARAMETER);

    if ((req->scope == CAPTURE_SCOPE_PROCESS && ! req->target_pid) ||
            (req->scope == CAPTURE_SCOPE_BOX && req->target_pid))
        return SHORT_REPLY(STATUS_INVALID_PARAMETER);

    if (req->scope == CAPTURE_SCOPE_PROCESS &&
            (req->flags & CAPTURE_FLAG_INCLUDE_FUTURE_PROCESSES)) {
        return SHORT_REPLY(STATUS_INVALID_PARAMETER);
    }

    if (req->scope == CAPTURE_SCOPE_BOX &&
            !(req->flags & CAPTURE_FLAG_INCLUDE_FUTURE_PROCESSES)) {
        return SHORT_REPLY(STATUS_NOT_SUPPORTED);
    }

    ULONG driverFlags = 0;
    status = CaptureServer_QueryDriver(&driverFlags);
    if (! NT_SUCCESS(status))
        return SHORT_REPLY(status);
    if (req->mode == CAPTURE_MODE_PACKETS) {
#if CAPTURE_PACKET_CAPTURE_RELEASE_GATE
        if (!(driverFlags & CAPTURE_DRIVER_FLAG_INCLUDE_PAYLOAD))
            return SHORT_REPLY(STATUS_NOT_SUPPORTED);
#else
        return SHORT_REPLY(STATUS_NOT_SUPPORTED);
#endif
    }

    ULONG ownerPid;
    ULONG ownerSessionId;
    ULONG64 ownerCreateTime;
    WCHAR ownerSid[96];
    status = CaptureServer_GetCallerIdentity(
        &ownerPid, &ownerSessionId, &ownerCreateTime, ownerSid);
    if (! NT_SUCCESS(status))
        return SHORT_REPLY(status);

    status = SbieApi_Call(API_IS_BOX_ENABLED, 3,
        (ULONG_PTR)req->box_name, (ULONG_PTR)ownerSid,
        (ULONG_PTR)ownerSessionId);
    if (status == STATUS_ACCOUNT_RESTRICTION)
        return SHORT_REPLY(STATUS_ACCESS_DENIED);
    if (! NT_SUCCESS(status))
        return SHORT_REPLY(status);

    ULONG targetPid = 0;
    ULONG targetSessionId = ownerSessionId;
    ULONG64 targetCreateTime = 0;
    WCHAR targetSid[96];
    wcscpy_s(targetSid, ARRAYSIZE(targetSid), ownerSid);

    if (req->scope == CAPTURE_SCOPE_PROCESS) {

        WCHAR targetBox[BOXNAME_COUNT];
        status = SbieApi_QueryProcessEx2(
            (HANDLE)(ULONG_PTR)req->target_pid, 0, targetBox, NULL, targetSid,
            &targetSessionId, &targetCreateTime);
        if (! NT_SUCCESS(status) || ! targetCreateTime)
            return SHORT_REPLY(NT_SUCCESS(status) ? STATUS_INVALID_CID : status);

        ULONG64 processFlags = SbieApi_QueryProcessInfo(
            (HANDLE)(ULONG_PTR)req->target_pid, 0);
        if ((processFlags & SBIE_FLAG_VALID_PROCESS) == 0)
            return SHORT_REPLY(STATUS_INVALID_CID);

        WCHAR confirmBox[BOXNAME_COUNT];
        WCHAR confirmSid[96];
        ULONG confirmSessionId = 0;
        ULONG64 confirmCreateTime = 0;
        status = SbieApi_QueryProcessEx2(
            (HANDLE)(ULONG_PTR)req->target_pid, 0, confirmBox, NULL, confirmSid,
            &confirmSessionId, &confirmCreateTime);
        if (! NT_SUCCESS(status) ||
                confirmCreateTime != targetCreateTime ||
                confirmSessionId != targetSessionId ||
                _wcsicmp(confirmBox, targetBox) != 0 ||
                _wcsicmp(confirmSid, targetSid) != 0) {
            return SHORT_REPLY(STATUS_INVALID_CID);
        }

        if (_wcsicmp(targetBox, req->box_name) != 0)
            return SHORT_REPLY(STATUS_INVALID_PARAMETER);

        if (_wcsicmp(targetSid, ownerSid) != 0)
            return SHORT_REPLY(STATUS_ACCESS_DENIED);

        targetPid = req->target_pid;
    }

    if (targetSessionId != ownerSessionId)
        return SHORT_REPLY(STATUS_ACCESS_DENIED);

    EnterCriticalSection(&m_lock);

    ULONG ownerCount = 0;
    ULONG principalCount = 0;
    ULONG globalActiveCount = 0;
    CAPTURE_SESSION_OBJ *entry = (CAPTURE_SESSION_OBJ *)List_Head(&m_sessions);
    while (entry) {
        if (entry->info.state != CAPTURE_STATE_STOPPED) {
            ++globalActiveCount;
            if (entry->owner_session_id == ownerSessionId &&
                    _wcsicmp(entry->owner_sid, ownerSid) == 0) {
                ++principalCount;
            }
            if (entry->owner_pid == ownerPid &&
                    entry->owner_create_time == ownerCreateTime &&
                    _wcsicmp(entry->owner_sid, ownerSid) == 0) {
                ++ownerCount;
            }
        }
        entry = (CAPTURE_SESSION_OBJ *)List_Next(entry);
    }

    if (ownerCount >= CAPTURE_MAX_SESSIONS_PER_OWNER ||
            principalCount >= CAPTURE_MAX_ACTIVE_PER_PRINCIPAL ||
            globalActiveCount >= CAPTURE_MAX_ACTIVE_GLOBAL) {
        LeaveCriticalSection(&m_lock);
        return SHORT_REPLY(STATUS_LICENSE_QUOTA_EXCEEDED);
    }

    entry = (CAPTURE_SESSION_OBJ *)List_Head(&m_sessions);
    while ((ULONG)List_Count(&m_sessions) >= CAPTURE_MAX_SESSIONS_GLOBAL &&
            entry) {
        CAPTURE_SESSION_OBJ *next =
            (CAPTURE_SESSION_OBJ *)List_Next(entry);
        if (entry->info.state == CAPTURE_STATE_STOPPED)
            DeleteSession(entry);
        entry = next;
    }

    if ((ULONG)List_Count(&m_sessions) >= CAPTURE_MAX_SESSIONS_GLOBAL) {
        LeaveCriticalSection(&m_lock);
        return SHORT_REPLY(STATUS_LICENSE_QUOTA_EXCEEDED);
    }

    CAPTURE_SESSION_OBJ *session = (CAPTURE_SESSION_OBJ *)
        HeapAlloc(m_heap, HEAP_ZERO_MEMORY, sizeof(CAPTURE_SESSION_OBJ));
    if (! session) {
        LeaveCriticalSection(&m_lock);
        return SHORT_REPLY(STATUS_INSUFFICIENT_RESOURCES);
    }

    session->stopped_events = (CAPTURE_CONNECTION_EVENT *)HeapAlloc(
        m_heap, HEAP_ZERO_MEMORY,
        CAPTURE_DRIVER_QUEUE_CAPACITY * sizeof(CAPTURE_CONNECTION_EVENT));
    if (! session->stopped_events) {
        HeapFree(m_heap, 0, session);
        LeaveCriticalSection(&m_lock);
        return SHORT_REPLY(STATUS_INSUFFICIENT_RESOURCES);
    }

    ULONG idAttempts = 0;
    do {
        if (! CaptureServer_GenerateId(&session->info.capture_id))
            break;
        ++idAttempts;
    } while (CaptureServer_IdExists(
                 &m_sessions, &session->info.capture_id) && idAttempts < 4);

    if (! idAttempts || CaptureServer_IdExists(
            &m_sessions, &session->info.capture_id)) {
        HeapFree(m_heap, 0, session->stopped_events);
        HeapFree(m_heap, 0, session);
        LeaveCriticalSection(&m_lock);
        return SHORT_REPLY(STATUS_UNSUCCESSFUL);
    }

    session->owner_pid = ownerPid;
    session->owner_session_id = ownerSessionId;
    session->owner_create_time = ownerCreateTime;
    wcscpy_s(session->owner_sid, ARRAYSIZE(session->owner_sid), ownerSid);

    session->info.state = CAPTURE_STATE_STARTING;
    session->info.scope = req->scope;
    session->info.mode = req->mode;
    session->info.flags = req->flags;
    session->info.target_pid = targetPid;
    session->info.target_session_id = targetSessionId;
    session->info.target_process_create_time = targetCreateTime;
    session->info.started_time = CaptureServer_GetSystemTime();
    session->info.backend_status = STATUS_PENDING;
    session->snap_length = snapLength ?
        snapLength : CAPTURE_DEFAULT_SNAP_LENGTH;
    session->max_file_bytes = maxFileBytes ?
        maxFileBytes : CAPTURE_DEFAULT_MAX_FILE_BYTES;
    session->max_seconds = maxSeconds ?
        maxSeconds : CAPTURE_DEFAULT_MAX_SECONDS;
    session->rotate_count = rotateCount;
    wcscpy_s(session->info.box_name, ARRAYSIZE(session->info.box_name),
             req->box_name);

    CAPTURE_START_RPL *rpl = (CAPTURE_START_RPL *)
        LONG_REPLY(sizeof(CAPTURE_START_RPL));
    if (! rpl) {
        HeapFree(m_heap, 0, session->stopped_events);
        HeapFree(m_heap, 0, session);
        LeaveCriticalSection(&m_lock);
        return SHORT_REPLY(STATUS_INSUFFICIENT_RESOURCES);
    }

    status = CaptureServer_StartDriver(session, targetSid);
    if (! NT_SUCCESS(status)) {
        PipeServer::GetPipeServer()->FreeMsg(&rpl->h);
        HeapFree(m_heap, 0, session->stopped_events);
        HeapFree(m_heap, 0, session);
        LeaveCriticalSection(&m_lock);
        return SHORT_REPLY(status);
    }

    if (session->info.mode == CAPTURE_MODE_PACKETS) {
        status = CaptureServer_MapDriver(session);
        if (! NT_SUCCESS(status)) {
            CaptureServer_StopDriver(&session->info.capture_id);
            PipeServer::GetPipeServer()->FreeMsg(&rpl->h);
            if (session->section_handle)
                CloseHandle(session->section_handle);
            HeapFree(m_heap, 0, session->stopped_events);
            HeapFree(m_heap, 0, session);
            LeaveCriticalSection(&m_lock);
            return SHORT_REPLY(status);
        }
        session->info.state = CAPTURE_STATE_WAITING_FOR_BACKEND;
        session->waiting_deadline = session->info.started_time + 50000000ull;
    }

    session->backend_active = TRUE;
    if (session->info.mode != CAPTURE_MODE_PACKETS) {
        session->info.state = CAPTURE_STATE_RUNNING;
        session->info.backend_status = STATUS_SUCCESS;
    }
    List_Insert_After(&m_sessions, NULL, session);

    memzero(rpl, sizeof(*rpl));
    rpl->h.length = sizeof(*rpl);
    rpl->h.status = STATUS_SUCCESS;
    rpl->wire_version = CAPTURE_WIRE_VERSION;
    rpl->struct_size = sizeof(*rpl);
    memcpy(&rpl->session, &session->info, sizeof(rpl->session));

    LeaveCriticalSection(&m_lock);
    return &rpl->h;
}


//---------------------------------------------------------------------------
// StopHandler
//---------------------------------------------------------------------------


MSG_HEADER *CaptureServer::StopHandler(MSG_HEADER *msg)
{
    CAPTURE_SESSION_REQ *req = (CAPTURE_SESSION_REQ *)msg;
    ULONG status = CaptureServer_ValidateVersion(&req->v,
                                                  sizeof(CAPTURE_SESSION_REQ));
    if (! NT_SUCCESS(status))
        return SHORT_REPLY(status);

    ULONG ownerPid;
    ULONG ownerSessionId;
    ULONG64 ownerCreateTime;
    WCHAR ownerSid[96];
    status = CaptureServer_GetCallerIdentity(
        &ownerPid, &ownerSessionId, &ownerCreateTime, ownerSid);
    if (! NT_SUCCESS(status))
        return SHORT_REPLY(status);

    EnterCriticalSection(&m_lock);

    CAPTURE_SESSION_OBJ *session = FindSession(
        &req->capture_id, ownerPid, ownerCreateTime, ownerSid);
    if (! session) {
        LeaveCriticalSection(&m_lock);
        return SHORT_REPLY(STATUS_OBJECT_NAME_NOT_FOUND);
    }

    if (session->owner_session_id != ownerSessionId) {
        LeaveCriticalSection(&m_lock);
        return SHORT_REPLY(STATUS_ACCESS_DENIED);
    }

    CAPTURE_STATUS_RPL *rpl = (CAPTURE_STATUS_RPL *)
        LONG_REPLY(sizeof(CAPTURE_STATUS_RPL));
    if (! rpl) {
        LeaveCriticalSection(&m_lock);
        return SHORT_REPLY(STATUS_INSUFFICIENT_RESOURCES);
    }

    if (session->info.state != CAPTURE_STATE_STOPPED) {
        status = StopBackend(session, TRUE);
        if (session->backend_active) {
            PipeServer::GetPipeServer()->FreeMsg(&rpl->h);
            LeaveCriticalSection(&m_lock);
            return SHORT_REPLY(status);
        }

        session->info.state = CAPTURE_STATE_STOPPED;
        session->info.stopped_time = CaptureServer_GetSystemTime();
        session->info.backend_status = status;
    }

    memzero(rpl, sizeof(*rpl));
    rpl->h.length = sizeof(*rpl);
    rpl->h.status = STATUS_SUCCESS;
    rpl->wire_version = CAPTURE_WIRE_VERSION;
    rpl->struct_size = sizeof(*rpl);
    memcpy(&rpl->session, &session->info, sizeof(rpl->session));

    TrimStoppedSessions(ownerPid, ownerCreateTime, ownerSid);

    LeaveCriticalSection(&m_lock);
    return &rpl->h;
}


//---------------------------------------------------------------------------
// GetStatusHandler
//---------------------------------------------------------------------------


MSG_HEADER *CaptureServer::GetStatusHandler(MSG_HEADER *msg)
{
    CAPTURE_SESSION_REQ *req = (CAPTURE_SESSION_REQ *)msg;
    ULONG status = CaptureServer_ValidateVersion(&req->v,
                                                  sizeof(CAPTURE_SESSION_REQ));
    if (! NT_SUCCESS(status))
        return SHORT_REPLY(status);

    ULONG ownerPid;
    ULONG ownerSessionId;
    ULONG64 ownerCreateTime;
    WCHAR ownerSid[96];
    status = CaptureServer_GetCallerIdentity(
        &ownerPid, &ownerSessionId, &ownerCreateTime, ownerSid);
    if (! NT_SUCCESS(status))
        return SHORT_REPLY(status);

    EnterCriticalSection(&m_lock);

    CAPTURE_SESSION_OBJ *session = FindSession(
        &req->capture_id, ownerPid, ownerCreateTime, ownerSid);
    if (! session) {
        LeaveCriticalSection(&m_lock);
        return SHORT_REPLY(STATUS_OBJECT_NAME_NOT_FOUND);
    }

    if (session->owner_session_id != ownerSessionId) {
        LeaveCriticalSection(&m_lock);
        return SHORT_REPLY(STATUS_ACCESS_DENIED);
    }

    if (session->info.state == CAPTURE_STATE_WAITING_FOR_BACKEND &&
            session->waiting_deadline &&
            CaptureServer_GetSystemTime() >= session->waiting_deadline) {
        ULONG teardownStatus = StopBackend(session, FALSE);
        session->info.state = CAPTURE_STATE_FAILED;
        session->info.backend_status = NT_SUCCESS(teardownStatus) ?
            STATUS_TIMEOUT : teardownStatus;
    }

    CaptureServer_PollBroker(session);
    CaptureServer_UpdateBrokerCounters(session);

    CAPTURE_STATUS_RPL *rpl = (CAPTURE_STATUS_RPL *)
        LONG_REPLY(sizeof(CAPTURE_STATUS_RPL));
    if (! rpl) {
        LeaveCriticalSection(&m_lock);
        return SHORT_REPLY(STATUS_INSUFFICIENT_RESOURCES);
    }

    memzero(rpl, sizeof(*rpl));
    rpl->h.length = sizeof(*rpl);
    rpl->h.status = STATUS_SUCCESS;
    rpl->wire_version = CAPTURE_WIRE_VERSION;
    rpl->struct_size = sizeof(*rpl);
    memcpy(&rpl->session, &session->info, sizeof(rpl->session));

    LeaveCriticalSection(&m_lock);
    return &rpl->h;
}


//---------------------------------------------------------------------------
// ListHandler
//---------------------------------------------------------------------------


MSG_HEADER *CaptureServer::ListHandler(MSG_HEADER *msg)
{
    CAPTURE_LIST_REQ *req = (CAPTURE_LIST_REQ *)msg;
    ULONG status = CaptureServer_ValidateVersion(&req->v,
                                                  sizeof(CAPTURE_LIST_REQ));
    if (! NT_SUCCESS(status))
        return SHORT_REPLY(status);

    ULONG ownerPid;
    ULONG ownerSessionId;
    ULONG64 ownerCreateTime;
    WCHAR ownerSid[96];
    status = CaptureServer_GetCallerIdentity(
        &ownerPid, &ownerSessionId, &ownerCreateTime, ownerSid);
    if (! NT_SUCCESS(status))
        return SHORT_REPLY(status);

    ULONG maxEntries = req->max_entries;
    if (maxEntries == 0 || maxEntries > CAPTURE_MAX_LIST_ENTRIES)
        maxEntries = CAPTURE_MAX_LIST_ENTRIES;

    EnterCriticalSection(&m_lock);

    ULONG totalCount = 0;
    CAPTURE_SESSION_OBJ *entry = (CAPTURE_SESSION_OBJ *)List_Head(&m_sessions);
    while (entry) {
        if (entry->owner_pid == ownerPid &&
                entry->owner_create_time == ownerCreateTime &&
                entry->owner_session_id == ownerSessionId &&
                _wcsicmp(entry->owner_sid, ownerSid) == 0)
            ++totalCount;
        entry = (CAPTURE_SESSION_OBJ *)List_Next(entry);
    }

    ULONG returnedCount = 0;
    if (req->start_index < totalCount) {
        ULONG remaining = totalCount - req->start_index;
        returnedCount = remaining < maxEntries ? remaining : maxEntries;
    }

    SIZE_T replySize = FIELD_OFFSET(CAPTURE_LIST_RPL, sessions) +
                       returnedCount * sizeof(CAPTURE_SESSION_INFO);
    CAPTURE_LIST_RPL *rpl = (CAPTURE_LIST_RPL *)LONG_REPLY((ULONG)replySize);
    if (! rpl) {
        LeaveCriticalSection(&m_lock);
        return SHORT_REPLY(STATUS_INSUFFICIENT_RESOURCES);
    }

    memzero(rpl, (ULONG)replySize);
    rpl->h.length = (ULONG)replySize;
    rpl->h.status = STATUS_SUCCESS;
    rpl->wire_version = CAPTURE_WIRE_VERSION;
    rpl->struct_size = FIELD_OFFSET(CAPTURE_LIST_RPL, sessions);
    rpl->total_count = totalCount;
    rpl->returned_count = returnedCount;
    rpl->next_index = req->start_index + returnedCount;
    if (rpl->next_index >= totalCount)
        rpl->next_index = 0;

    ULONG ownerIndex = 0;
    ULONG outputIndex = 0;
    entry = (CAPTURE_SESSION_OBJ *)List_Head(&m_sessions);
    while (entry && outputIndex < returnedCount) {

        if (entry->owner_pid == ownerPid &&
                entry->owner_create_time == ownerCreateTime &&
                entry->owner_session_id == ownerSessionId &&
                _wcsicmp(entry->owner_sid, ownerSid) == 0) {

            if (ownerIndex >= req->start_index) {
                memcpy(&rpl->sessions[outputIndex], &entry->info,
                       sizeof(CAPTURE_SESSION_INFO));
                ++outputIndex;
            }
            ++ownerIndex;
        }

        entry = (CAPTURE_SESSION_OBJ *)List_Next(entry);
    }

    LeaveCriticalSection(&m_lock);
    return &rpl->h;
}


//---------------------------------------------------------------------------
// ReadEventsHandler
//---------------------------------------------------------------------------


MSG_HEADER *CaptureServer::ReadEventsHandler(MSG_HEADER *msg)
{
    CAPTURE_READ_EVENTS_REQ *req = (CAPTURE_READ_EVENTS_REQ *)msg;
    ULONG status = CaptureServer_ValidateVersion(
        &req->v, sizeof(CAPTURE_READ_EVENTS_REQ));
    if (! NT_SUCCESS(status))
        return SHORT_REPLY(status);
    if (req->v.struct_size != sizeof(*req) ||
            req->v.h.length != sizeof(*req) || req->reserved) {
        return SHORT_REPLY(STATUS_INVALID_PARAMETER);
    }

    ULONG maxEvents = req->max_events;
    if (! maxEvents)
        maxEvents = CAPTURE_MAX_EVENT_ENTRIES;
    if (maxEvents > CAPTURE_MAX_EVENT_ENTRIES)
        return SHORT_REPLY(STATUS_INVALID_PARAMETER);

    ULONG ownerPid;
    ULONG ownerSessionId;
    ULONG64 ownerCreateTime;
    WCHAR ownerSid[96];
    status = CaptureServer_GetCallerIdentity(
        &ownerPid, &ownerSessionId, &ownerCreateTime, ownerSid);
    if (! NT_SUCCESS(status))
        return SHORT_REPLY(status);

    ULONG replySize = FIELD_OFFSET(CAPTURE_READ_EVENTS_RPL, events) +
        maxEvents * sizeof(CAPTURE_CONNECTION_EVENT);
    CAPTURE_READ_EVENTS_RPL *rpl =
        (CAPTURE_READ_EVENTS_RPL *)LONG_REPLY(replySize);
    if (! rpl)
        return SHORT_REPLY(STATUS_INSUFFICIENT_RESOURCES);

    memzero(rpl, replySize);
    rpl->h.length = replySize;

    EnterCriticalSection(&m_lock);

    CAPTURE_SESSION_OBJ *session = FindSession(
        &req->capture_id, ownerPid, ownerCreateTime, ownerSid);
    if (! session) {
        LeaveCriticalSection(&m_lock);
        PipeServer::GetPipeServer()->FreeMsg(&rpl->h);
        return SHORT_REPLY(STATUS_OBJECT_NAME_NOT_FOUND);
    }

    if (session->owner_session_id != ownerSessionId) {
        LeaveCriticalSection(&m_lock);
        PipeServer::GetPipeServer()->FreeMsg(&rpl->h);
        return SHORT_REPLY(STATUS_ACCESS_DENIED);
    }

    CaptureServer_PollBroker(session);

    ULONG returnedEvents = 0;
    ULONG remainingEvents = 0;
    ULONG64 nextSequence = 0;
    ULONG64 oldestSequence = 0;
    ULONG64 newestSequence = 0;
    ULONG64 droppedCount = session->info.dropped_count;

    if (session->backend_active) {
        status = CaptureServer_ReadDriverEvents(
            session,
            rpl->events,
            maxEvents,
            &returnedEvents,
            &remainingEvents,
            &nextSequence,
            &oldestSequence,
            &newestSequence,
            &droppedCount);
        if (NT_SUCCESS(status)) {
            session->info.event_count += returnedEvents;
            if (session->info.mode != CAPTURE_MODE_PACKETS)
                session->info.dropped_count = droppedCount;
        }
        else if (status == STATUS_NOT_FOUND) {
            session->backend_active = FALSE;
            session->info.state = CAPTURE_STATE_FAILED;
            session->info.backend_status = status;
        }
    }
    else {
        ULONG availableEvents = session->stopped_event_count;
        returnedEvents = availableEvents < maxEvents ?
            availableEvents : maxEvents;

        if (availableEvents) {
            oldestSequence = session->stopped_events[
                session->stopped_event_head].sequence;
            newestSequence = session->stopped_events[
                session->stopped_event_head + availableEvents - 1].sequence;
        }

        if (returnedEvents) {
            memcpy(
                rpl->events,
                &session->stopped_events[session->stopped_event_head],
                returnedEvents * sizeof(CAPTURE_CONNECTION_EVENT));
            nextSequence = rpl->events[returnedEvents - 1].sequence;
            session->stopped_event_head += returnedEvents;
            session->stopped_event_count -= returnedEvents;
        }
        remainingEvents = session->stopped_event_count;
        status = STATUS_SUCCESS;
    }

    if (! NT_SUCCESS(status)) {
        LeaveCriticalSection(&m_lock);
        PipeServer::GetPipeServer()->FreeMsg(&rpl->h);
        return SHORT_REPLY(status);
    }

    rpl->h.length = replySize;
    rpl->h.status = STATUS_SUCCESS;
    rpl->wire_version = CAPTURE_WIRE_VERSION;
    rpl->struct_size = FIELD_OFFSET(CAPTURE_READ_EVENTS_RPL, events);
    rpl->capture_id = req->capture_id;
    rpl->next_sequence = nextSequence;
    rpl->oldest_sequence = oldestSequence;
    rpl->newest_sequence = newestSequence;
    rpl->dropped_count = droppedCount;
    rpl->returned_events = returnedEvents;
    rpl->remaining_events = remainingEvents;

    LeaveCriticalSection(&m_lock);
    return &rpl->h;
}


#if 0
MSG_HEADER *CaptureServer::ReadPayloadHandler(MSG_HEADER *msg, BOOLEAN stream)
{
    UNREFERENCED_PARAMETER(msg);
    UNREFERENCED_PARAMETER(stream);
    return SHORT_REPLY(STATUS_NOT_SUPPORTED);
#if 0
    const ULONG requestSize = stream ?
        sizeof(CAPTURE_READ_STREAMS_REQ) : sizeof(CAPTURE_READ_PACKETS_REQ);
    CAPTURE_VERSIONED_REQUEST *versioned =
        (CAPTURE_VERSIONED_REQUEST *)msg;
    ULONG status = CaptureServer_ValidateVersion(versioned, requestSize);
    if (! NT_SUCCESS(status))
        return SHORT_REPLY(status);

    CAPTURE_SESSION_ID captureId;
    ULONG maxRecords;
    ULONG reserved;
    if (stream) {
        CAPTURE_READ_STREAMS_REQ *req =
            (CAPTURE_READ_STREAMS_REQ *)msg;
        if (req->v.struct_size != sizeof(*req) ||
                req->v.h.length != sizeof(*req)) {
            return SHORT_REPLY(STATUS_INVALID_PARAMETER);
        }
        captureId = req->capture_id;
        maxRecords = req->max_records;
        reserved = req->reserved;
    }
    else {
        CAPTURE_READ_PACKETS_REQ *req =
            (CAPTURE_READ_PACKETS_REQ *)msg;
        if (req->v.struct_size != sizeof(*req) ||
                req->v.h.length != sizeof(*req)) {
            return SHORT_REPLY(STATUS_INVALID_PARAMETER);
        }
        captureId = req->capture_id;
        maxRecords = req->max_records;
        reserved = req->reserved;
    }

    if (reserved)
        return SHORT_REPLY(STATUS_INVALID_PARAMETER);

    const ULONG maximumRecords = stream ?
        CAPTURE_MAX_STREAM_ENTRIES : CAPTURE_MAX_PACKET_ENTRIES;
    if (! maxRecords)
        maxRecords = maximumRecords;
    if (maxRecords > maximumRecords)
        return SHORT_REPLY(STATUS_INVALID_PARAMETER);

    ULONG replySize = FIELD_OFFSET(CAPTURE_READ_PACKETS_RPL, records) +
        maxRecords * sizeof(CAPTURE_PACKET_EVENT);
    CAPTURE_READ_PACKETS_RPL *rpl =
        (CAPTURE_READ_PACKETS_RPL *)LONG_REPLY(replySize);
    if (! rpl)
        return SHORT_REPLY(STATUS_INSUFFICIENT_RESOURCES);

    memzero(rpl, replySize);
    rpl->h.length = replySize;

    ULONG ownerPid;
    ULONG ownerSessionId;
    ULONG64 ownerCreateTime;
    WCHAR ownerSid[96];
    status = CaptureServer_GetCallerIdentity(
        &ownerPid, &ownerSessionId, &ownerCreateTime, ownerSid);
    if (! NT_SUCCESS(status)) {
        PipeServer::GetPipeServer()->FreeMsg(&rpl->h);
        return SHORT_REPLY(status);
    }

    EnterCriticalSection(&m_lock);

    CAPTURE_SESSION_OBJ *session = FindSession(
        &captureId, ownerPid, ownerCreateTime, ownerSid);
    if (! session) {
        LeaveCriticalSection(&m_lock);
        PipeServer::GetPipeServer()->FreeMsg(&rpl->h);
        return SHORT_REPLY(STATUS_OBJECT_NAME_NOT_FOUND);
    }

    if (session->owner_session_id != ownerSessionId) {
        LeaveCriticalSection(&m_lock);
        PipeServer::GetPipeServer()->FreeMsg(&rpl->h);
        return SHORT_REPLY(STATUS_ACCESS_DENIED);
    }

    if (session->info.mode != CAPTURE_MODE_PACKETS) {
        LeaveCriticalSection(&m_lock);
        PipeServer::GetPipeServer()->FreeMsg(&rpl->h);
        return SHORT_REPLY(STATUS_NOT_SUPPORTED);
    }

    CaptureServer_PollBroker(session);

    ULONG returnedRecords = 0;
    ULONG remainingRecords = 0;
    ULONG64 nextSequence = 0;
    ULONG64 oldestSequence = 0;
    ULONG64 newestSequence = 0;
    ULONG64 droppedCount = session->info.dropped_count;

    if (session->backend_active) {
        status = CaptureServer_ReadDriverPayload(
            session,
            stream,
            rpl->records,
            maxRecords,
            &returnedRecords,
            &remainingRecords,
            &nextSequence,
            &oldestSequence,
            &newestSequence,
            &droppedCount);
        if (status == STATUS_NOT_FOUND ||
                status == STATUS_INVALID_NETWORK_RESPONSE) {
            session->backend_active = FALSE;
            session->info.state = CAPTURE_STATE_FAILED;
            session->info.backend_status = status;
        }
    }
    else {
        status = STATUS_SUCCESS;
    }

    if (! NT_SUCCESS(status)) {
        LeaveCriticalSection(&m_lock);
        PipeServer::GetPipeServer()->FreeMsg(&rpl->h);
        return SHORT_REPLY(status);
    }

    rpl->h.length = replySize;
    rpl->h.status = STATUS_SUCCESS;
    rpl->wire_version = CAPTURE_WIRE_VERSION;
    rpl->struct_size = FIELD_OFFSET(CAPTURE_READ_PACKETS_RPL, records);
    rpl->capture_id = captureId;
    rpl->next_sequence = nextSequence;
    rpl->oldest_sequence = oldestSequence;
    rpl->newest_sequence = newestSequence;
    rpl->dropped_count = droppedCount;
    rpl->returned_records = returnedRecords;
    rpl->remaining_records = remainingRecords;

    LeaveCriticalSection(&m_lock);
    return &rpl->h;
#endif
}


MSG_HEADER *CaptureServer::ReadPacketsHandler(MSG_HEADER *msg)
{
    return ReadPayloadHandler(msg, FALSE);
}


MSG_HEADER *CaptureServer::ReadStreamsHandler(MSG_HEADER *msg)
{
    return ReadPayloadHandler(msg, TRUE);
}
#endif


//---------------------------------------------------------------------------
// SetExportHandler
//---------------------------------------------------------------------------


MSG_HEADER *CaptureServer::SetExportHandler(MSG_HEADER *msg)
{
    CAPTURE_SET_EXPORT_REQ *req = (CAPTURE_SET_EXPORT_REQ *)msg;
    ULONG status = CaptureServer_ValidateVersion(
        &req->v, sizeof(CAPTURE_SET_EXPORT_REQ));
    if (! NT_SUCCESS(status))
        return SHORT_REPLY(status);

    if ((req->capture_id.high == 0 && req->capture_id.low == 0) ||
            req->file_handle == 0 || req->reserved || req->reserved2)
        return SHORT_REPLY(STATUS_INVALID_PARAMETER);

    ULONG ownerPid;
    ULONG ownerSessionId;
    ULONG64 ownerCreateTime;
    WCHAR ownerSid[96];
    status = CaptureServer_GetCallerIdentity(
        &ownerPid, &ownerSessionId, &ownerCreateTime, ownerSid);
    if (! NT_SUCCESS(status))
        return SHORT_REPLY(status);

    HANDLE duplicateFile = NULL;
    status = CaptureServer_DuplicateWritableFile(
        ownerPid, ownerCreateTime, req->file_handle, &duplicateFile);
    if (! NT_SUCCESS(status))
        return SHORT_REPLY(status);

    EnterCriticalSection(&m_lock);

    CAPTURE_SESSION_OBJ *session = FindSession(
        &req->capture_id, ownerPid, ownerCreateTime, ownerSid);
    if (! session) {
        LeaveCriticalSection(&m_lock);
        CloseHandle(duplicateFile);
        return SHORT_REPLY(STATUS_OBJECT_NAME_NOT_FOUND);
    }

    if (session->owner_session_id != ownerSessionId) {
        LeaveCriticalSection(&m_lock);
        CloseHandle(duplicateFile);
        return SHORT_REPLY(STATUS_ACCESS_DENIED);
    }

    if (! CaptureServer_IsPacketMode(session)) {
        LeaveCriticalSection(&m_lock);
        CloseHandle(duplicateFile);
        return SHORT_REPLY(STATUS_NOT_SUPPORTED);
    }

    if (! CaptureServer_IsWaitingForBackend(session) ||
            session->export_file) {
        LeaveCriticalSection(&m_lock);
        CloseHandle(duplicateFile);
        return SHORT_REPLY(STATUS_INVALID_DEVICE_STATE);
    }

    CAPTURE_SET_EXPORT_RPL *rpl = (CAPTURE_SET_EXPORT_RPL *)
        LONG_REPLY(sizeof(CAPTURE_SET_EXPORT_RPL));
    if (! rpl) {
        LeaveCriticalSection(&m_lock);
        CloseHandle(duplicateFile);
        return SHORT_REPLY(STATUS_INSUFFICIENT_RESOURCES);
    }

    session->export_file = duplicateFile;
    duplicateFile = NULL;
    session->info.backend_status = STATUS_PENDING;

    if (session->section_handle) {
        status = CaptureServer_StartBroker(session);
        if (! NT_SUCCESS(status)) {
            ULONG teardownStatus = StopBackend(session, FALSE);
            if (NT_SUCCESS(teardownStatus) && !NT_SUCCESS(status))
                teardownStatus = status;
            session->info.state = CAPTURE_STATE_FAILED;
            session->info.backend_status = teardownStatus;
            PipeServer::GetPipeServer()->FreeMsg(&rpl->h);
            LeaveCriticalSection(&m_lock);
            return SHORT_REPLY(teardownStatus);
        }
    }

    memzero(rpl, sizeof(*rpl));
    rpl->h.length = sizeof(*rpl);
    rpl->h.status = STATUS_SUCCESS;
    rpl->wire_version = CAPTURE_WIRE_VERSION;
    rpl->struct_size = sizeof(*rpl);
    memcpy(&rpl->session, &session->info, sizeof(rpl->session));

    LeaveCriticalSection(&m_lock);
    return &rpl->h;
}


//---------------------------------------------------------------------------
// SetHarExportHandler
//---------------------------------------------------------------------------


MSG_HEADER *CaptureServer::SetHarExportHandler(MSG_HEADER *msg)
{
    CAPTURE_SET_HAR_EXPORT_REQ *req = (CAPTURE_SET_HAR_EXPORT_REQ *)msg;
    ULONG status = CaptureServer_ValidateVersion(
        &req->v, sizeof(CAPTURE_SET_HAR_EXPORT_REQ));
    if (! NT_SUCCESS(status))
        return SHORT_REPLY(status);

    if ((req->capture_id.high == 0 && req->capture_id.low == 0) ||
            req->file_handle == 0 || req->reserved || req->reserved2)
        return SHORT_REPLY(STATUS_INVALID_PARAMETER);

    return SHORT_REPLY(STATUS_NOT_SUPPORTED);
}


static BOOLEAN CaptureServer_DuplicateInheritable(
    HANDLE source, HANDLE *duplicate)
{
    return DuplicateHandle(
        GetCurrentProcess(),
        source,
        GetCurrentProcess(),
        duplicate,
        0,
        TRUE,
        DUPLICATE_SAME_ACCESS) != FALSE;
}


static ULONG CaptureServer_WaitBrokerReady(
    HANDLE sectionHandle,
    const CAPTURE_SESSION_ID *captureId)
{
    if (! sectionHandle || ! captureId ||
            (captureId->high == 0 && captureId->low == 0)) {
        return STATUS_INVALID_PARAMETER;
    }

    CAPTURE_BROKER_SECTION *section =
        (CAPTURE_BROKER_SECTION *)MapViewOfFile(
            sectionHandle, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
    if (! section)
        return STATUS_INVALID_HANDLE;

    const ULONG64 generation = CaptureBroker_CalculateGeneration(
        captureId->high, captureId->low);
    const DWORD startTick = GetTickCount();
    ULONG status = STATUS_TIMEOUT;

    for (;;) {
        MemoryBarrier();
        if (section->magic != CAPTURE_BROKER_SECTION_MAGIC ||
                section->version != CAPTURE_BROKER_SECTION_VERSION ||
                section->capture_id_high != captureId->high ||
                section->capture_id_low != captureId->low ||
                section->generation != generation) {
            status = STATUS_INVALID_NETWORK_RESPONSE;
            break;
        }

        const LONG brokerState = section->broker_status;
        if (brokerState == CAPTURE_BROKER_STATE_RUNNING) {
            status = STATUS_SUCCESS;
            break;
        }
        if (brokerState == CAPTURE_BROKER_STATE_FAILED ||
                brokerState == CAPTURE_BROKER_STATE_STOPPED) {
            status = STATUS_DEVICE_NOT_READY;
            break;
        }
        if (GetTickCount() - startTick >= 5000)
            break;
        Sleep(10);
    }

    UnmapViewOfFile(section);
    return status;
}


static void CaptureServer_UpdateBrokerCounters(CAPTURE_SESSION_OBJ *session)
{
    if (! session || ! session->section_handle)
        return;

    CAPTURE_BROKER_SECTION *section =
        (CAPTURE_BROKER_SECTION *)MapViewOfFile(
            session->section_handle,
            FILE_MAP_READ,
            0,
            0,
            0);
    if (! section)
        return;

    const ULONG64 generation = CaptureBroker_CalculateGeneration(
        session->info.capture_id.high,
        session->info.capture_id.low);
    MemoryBarrier();
    if (section->magic == CAPTURE_BROKER_SECTION_MAGIC &&
            section->version == CAPTURE_BROKER_SECTION_VERSION &&
            section->size == CAPTURE_BROKER_SECTION_SIZE(
                CAPTURE_BROKER_MAX_RECORD_CAPACITY) &&
            section->record_capacity == CAPTURE_BROKER_MAX_RECORD_CAPACITY &&
            section->capture_id_high == session->info.capture_id.high &&
            section->capture_id_low == session->info.capture_id.low &&
            section->generation == generation) {
        session->info.packet_count = section->packet_count;
        session->info.byte_count = section->byte_count;
        session->info.dropped_count = section->dropped_count;
    }

    UnmapViewOfFile(section);
}


static ULONG CaptureServer_StartBroker(CAPTURE_SESSION_OBJ *session)
{
    if (! session || ! session->section_handle || ! session->export_file)
        return STATUS_DEVICE_NOT_READY;
    if (session->broker_process || session->broker_job)
        return STATUS_OBJECT_NAME_COLLISION;

    HANDLE ownerProcess = NULL;
    HANDLE ownerToken = NULL;
    HANDLE primaryToken = NULL;
    HANDLE stopEvent = NULL;
    HANDLE job = NULL;
    HANDLE childSection = NULL;
    HANDLE childFile = NULL;
    HANDLE childStopEvent = NULL;
    HANDLE inheritedHandles[3] = { 0 };
    SBIE_STARTUPINFOEXW startup = { 0 };
    PROCESS_INFORMATION processInfo = { 0 };
    PVOID attributes = NULL;
    SIZE_T attributesSize = 0;
    BOOL attributesInitialized = FALSE;
    SBIE_INITIALIZE_ATTRIBUTE_LIST initializeAttributes = NULL;
    SBIE_UPDATE_ATTRIBUTE updateAttribute = NULL;
    SBIE_DELETE_ATTRIBUTE_LIST deleteAttributes = NULL;
    HMODULE kernel32 = NULL;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = { 0 };
    DWORD exitCode = STILL_ACTIVE;
    WCHAR homePath[512];
    WCHAR executablePath[512];
    WCHAR commandLine[1024];
    ULONG status = STATUS_UNSUCCESSFUL;
    BOOL processCreated = FALSE;

    ownerProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION, FALSE, session->owner_pid);
    if (! ownerProcess)
        goto cleanup;
    ULONG64 liveOwnerCreateTime = 0;
    if (! NT_SUCCESS(CaptureServer_GetProcessCreateTime(
            ownerProcess, &liveOwnerCreateTime)) ||
            liveOwnerCreateTime != session->owner_create_time) {
        goto cleanup;
    }
    if (! OpenProcessToken(
            ownerProcess,
            TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY,
            &ownerToken)) {
        goto cleanup;
    }
    if (! CaptureServer_TokenMatchesOwner(
            ownerToken, session->owner_session_id, session->owner_sid)) {
        goto cleanup;
    }
    if (! DuplicateTokenEx(
            ownerToken,
            TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY,
            NULL,
            SecurityImpersonation,
            TokenPrimary,
            &primaryToken)) {
        goto cleanup;
    }

    stopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    job = CreateJobObjectW(NULL, NULL);
    if (! stopEvent || ! job)
        goto cleanup;

    limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (! SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &limits,
            sizeof(limits))) {
        goto cleanup;
    }

    if (! CaptureServer_DuplicateInheritable(
            session->section_handle, &childSection) ||
            ! CaptureServer_DuplicateInheritable(
                session->export_file, &childFile) ||
            ! CaptureServer_DuplicateInheritable(
                stopEvent, &childStopEvent)) {
        goto cleanup;
    }

    inheritedHandles[0] = childSection;
    inheritedHandles[1] = childFile;
    inheritedHandles[2] = childStopEvent;

    if (SbieApi_GetHomePath(NULL, 0, homePath, ARRAYSIZE(homePath)) != 0)
        goto cleanup;
    if (wcscpy_s(executablePath, ARRAYSIZE(executablePath), homePath) != 0 ||
            wcscat_s(executablePath, ARRAYSIZE(executablePath),
                     L"\\SbieCapture.exe") != 0) {
        goto cleanup;
    }

    if (swprintf_s(
            commandLine,
            ARRAYSIZE(commandLine),
            L"\"%s\" --section %p --file %p --stop-event %p "
            L"--capture-high %I64X --capture-low %I64X "
            L"--generation %I64X --snaplen %lu --max-file-bytes %lu "
            L"--max-seconds %lu --rotate-count %lu",
            executablePath,
            childSection,
            childFile,
            childStopEvent,
            session->info.capture_id.high,
            session->info.capture_id.low,
            CaptureBroker_CalculateGeneration(
                session->info.capture_id.high,
                session->info.capture_id.low),
            session->snap_length,
            session->max_file_bytes,
            session->max_seconds,
            session->rotate_count) < 0) {
        goto cleanup;
    }

    kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (! kernel32)
        goto cleanup;
    initializeAttributes = (SBIE_INITIALIZE_ATTRIBUTE_LIST)
        GetProcAddress(kernel32, "InitializeProcThreadAttributeList");
    updateAttribute = (SBIE_UPDATE_ATTRIBUTE)
        GetProcAddress(kernel32, "UpdateProcThreadAttribute");
    deleteAttributes = (SBIE_DELETE_ATTRIBUTE_LIST)
        GetProcAddress(kernel32, "DeleteProcThreadAttributeList");
    if (! initializeAttributes || ! updateAttribute || ! deleteAttributes)
        goto cleanup;

    initializeAttributes(NULL, 1, 0, &attributesSize);
    attributes = HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, attributesSize);
    if (! attributes || ! initializeAttributes(attributes, 1, 0, &attributesSize)) {
        goto cleanup;
    }
    attributesInitialized = TRUE;
    if (! updateAttribute(
            attributes,
            0,
            SBIE_PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            inheritedHandles,
            sizeof(inheritedHandles),
            NULL,
            NULL)) {
        goto cleanup;
    }

    startup.StartupInfo.cb = sizeof(startup);
    startup.attribute_list = attributes;
    if (! CreateProcessAsUserW(
            primaryToken,
            NULL,
            commandLine,
            NULL,
            NULL,
            TRUE,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
            NULL,
            NULL,
            &startup.StartupInfo,
            &processInfo)) {
        goto cleanup;
    }
    processCreated = TRUE;

    if (! AssignProcessToJobObject(job, processInfo.hProcess))
        goto cleanup;
    if (ResumeThread(processInfo.hThread) == (DWORD)-1)
        goto cleanup;

    exitCode = STILL_ACTIVE;
    if (! GetExitCodeProcess(processInfo.hProcess, &exitCode) ||
            exitCode != STILL_ACTIVE) {
        goto cleanup;
    }

    status = CaptureServer_WaitBrokerReady(
        session->section_handle, &session->info.capture_id);
    if (! NT_SUCCESS(status))
        goto cleanup;

    session->broker_job = job;
    job = NULL;
    session->broker_process = processInfo.hProcess;
    processInfo.hProcess = NULL;
    session->broker_thread = processInfo.hThread;
    processInfo.hThread = NULL;
    session->broker_stop_event = stopEvent;
    stopEvent = NULL;
    session->info.state = CAPTURE_STATE_RUNNING;
    session->info.backend_status = STATUS_SUCCESS;
    status = STATUS_SUCCESS;

cleanup:
    if (attributesInitialized)
        deleteAttributes(attributes);
    if (attributes)
        HeapFree(GetProcessHeap(), 0, attributes);
    if (processCreated && status != STATUS_SUCCESS) {
        TerminateProcess(processInfo.hProcess, ERROR_PROCESS_ABORTED);
        WaitForSingleObject(processInfo.hProcess, 5000);
    }
    if (processInfo.hThread)
        CloseHandle(processInfo.hThread);
    if (processInfo.hProcess)
        CloseHandle(processInfo.hProcess);
    if (childSection)
        CloseHandle(childSection);
    if (childFile)
        CloseHandle(childFile);
    if (childStopEvent)
        CloseHandle(childStopEvent);
    if (job)
        CloseHandle(job);
    if (stopEvent)
        CloseHandle(stopEvent);
    if (primaryToken)
        CloseHandle(primaryToken);
    if (ownerToken)
        CloseHandle(ownerToken);
    if (ownerProcess)
        CloseHandle(ownerProcess);
    return status;
}


static ULONG CaptureServer_StopBroker(CAPTURE_SESSION_OBJ *session)
{
    if (! session)
        return STATUS_INVALID_PARAMETER;
    if (! session->broker_process && ! session->broker_job) {
        if (session->broker_stop_event)
            CloseHandle(session->broker_stop_event);
        session->broker_stop_event = NULL;
        return STATUS_SUCCESS;
    }

    ULONG status = STATUS_SUCCESS;
    if (session->broker_stop_event)
        SetEvent(session->broker_stop_event);

    if (session->broker_process &&
            WaitForSingleObject(session->broker_process, 5000) !=
                WAIT_OBJECT_0) {
        status = STATUS_TIMEOUT;
        if (session->broker_job)
            TerminateJobObject(session->broker_job, ERROR_PROCESS_ABORTED);
        else
            TerminateProcess(
                session->broker_process, ERROR_PROCESS_ABORTED);
        WaitForSingleObject(session->broker_process, 5000);
    }

    if (session->broker_thread)
        CloseHandle(session->broker_thread);
    if (session->broker_process)
        CloseHandle(session->broker_process);
    if (session->broker_stop_event)
        CloseHandle(session->broker_stop_event);
    if (session->broker_job)
        CloseHandle(session->broker_job);

    session->broker_thread = NULL;
    session->broker_process = NULL;
    session->broker_stop_event = NULL;
    session->broker_job = NULL;
    return status;
}


static void CaptureServer_PollBroker(CAPTURE_SESSION_OBJ *session)
{
    if (! session || ! session->broker_process)
        return;

    DWORD exitCode = STILL_ACTIVE;
    if (! GetExitCodeProcess(session->broker_process, &exitCode) ||
            exitCode == STILL_ACTIVE) {
        return;
    }

    CaptureServer_UpdateBrokerCounters(session);
    ULONG brokerStatus = CaptureServer_StopBroker(session);
    ULONG driverStatus = STATUS_SUCCESS;
    if (session->backend_active) {
        driverStatus = CaptureServer_StopDriver(&session->info.capture_id);
        if (NT_SUCCESS(driverStatus) || driverStatus == STATUS_NOT_FOUND)
            session->backend_active = FALSE;
    }
    if (session->export_file) {
        CloseHandle(session->export_file);
        session->export_file = NULL;
    }
    if (session->section_handle) {
        CloseHandle(session->section_handle);
        session->section_handle = NULL;
    }

    ULONG stopStatus = NT_SUCCESS(driverStatus) ? brokerStatus : driverStatus;
    if (exitCode == ERROR_SUCCESS && NT_SUCCESS(stopStatus)) {
        session->info.state = CAPTURE_STATE_STOPPED;
        session->info.backend_status = STATUS_SUCCESS;
    }
    else {
        session->info.state = CAPTURE_STATE_FAILED;
        session->info.backend_status = NT_SUCCESS(stopStatus) ?
            STATUS_UNSUCCESSFUL : stopStatus;
    }
}


//---------------------------------------------------------------------------
// NotifyHandler
//---------------------------------------------------------------------------


void CaptureServer::NotifyHandler(HANDLE idProcess, ULONG64 ownerCreateTime)
{
    ULONG ownerPid = (ULONG)(ULONG_PTR)idProcess;

    EnterCriticalSection(&m_lock);

    CAPTURE_SESSION_OBJ *entry = (CAPTURE_SESSION_OBJ *)List_Head(&m_sessions);
    while (entry) {
        CAPTURE_SESSION_OBJ *next = (CAPTURE_SESSION_OBJ *)List_Next(entry);
        if (entry->owner_pid == ownerPid &&
                entry->owner_create_time == ownerCreateTime)
            DeleteSession(entry);
        entry = next;
    }

    LeaveCriticalSection(&m_lock);
}


//---------------------------------------------------------------------------
// FindSession and DeleteSession
//---------------------------------------------------------------------------


CAPTURE_SESSION_OBJ *CaptureServer::FindSession(
    const CAPTURE_SESSION_ID *captureId, ULONG ownerPid,
    ULONG64 ownerCreateTime, const WCHAR *ownerSid)
{
    CAPTURE_SESSION_OBJ *entry = (CAPTURE_SESSION_OBJ *)List_Head(&m_sessions);
    while (entry) {
        if (entry->owner_pid == ownerPid &&
                entry->owner_create_time == ownerCreateTime &&
                _wcsicmp(entry->owner_sid, ownerSid) == 0 &&
                CaptureServer_IdEquals(&entry->info.capture_id, captureId))
            return entry;
        entry = (CAPTURE_SESSION_OBJ *)List_Next(entry);
    }

    return NULL;
}


ULONG CaptureServer::StopBackend(
    CAPTURE_SESSION_OBJ *session, BOOLEAN preserveEvents)
{
    if (! session)
        return STATUS_INVALID_PARAMETER;

    ULONG brokerStatus = CaptureServer_StopBroker(session);
    CaptureServer_UpdateBrokerCounters(session);
    if (! session->backend_active) {
        if (session->export_file) {
            CloseHandle(session->export_file);
            session->export_file = NULL;
        }
        if (session->section_handle) {
            CloseHandle(session->section_handle);
            session->section_handle = NULL;
        }
        return brokerStatus;
    }

    ULONG readStatus = STATUS_SUCCESS;

    if (preserveEvents) {
        while (session->stopped_event_count <
                CAPTURE_DRIVER_QUEUE_CAPACITY) {

            ULONG maxEvents = CAPTURE_DRIVER_QUEUE_CAPACITY -
                session->stopped_event_count;
            if (maxEvents > CAPTURE_MAX_EVENT_ENTRIES)
                maxEvents = CAPTURE_MAX_EVENT_ENTRIES;

            ULONG returnedEvents = 0;
            ULONG remainingEvents = 0;
            ULONG64 nextSequence = 0;
            ULONG64 oldestSequence = 0;
            ULONG64 newestSequence = 0;
            ULONG64 droppedCount = 0;

            readStatus = CaptureServer_ReadDriverEvents(
                session,
                &session->stopped_events[session->stopped_event_count],
                maxEvents,
                &returnedEvents,
                &remainingEvents,
                &nextSequence,
                &oldestSequence,
                &newestSequence,
                &droppedCount);
            if (! NT_SUCCESS(readStatus))
                break;

            session->stopped_event_count += returnedEvents;
            session->info.event_count += returnedEvents;
            if (session->info.mode != CAPTURE_MODE_PACKETS)
                session->info.dropped_count = droppedCount;

            if (! remainingEvents || ! returnedEvents)
                break;
        }
    }

    ULONG stopStatus = CaptureServer_StopDriver(&session->info.capture_id);
    if (NT_SUCCESS(stopStatus) || stopStatus == STATUS_NOT_FOUND)
        session->backend_active = FALSE;

    if (! session->backend_active && session->export_file) {
        CloseHandle(session->export_file);
        session->export_file = NULL;
    }
    if (! session->backend_active && session->section_handle) {
        CloseHandle(session->section_handle);
        session->section_handle = NULL;
    }

    if (! NT_SUCCESS(stopStatus))
        return stopStatus;
    if (! NT_SUCCESS(readStatus))
        return readStatus;
    return brokerStatus;
}


void CaptureServer::TrimStoppedSessions(
    ULONG ownerPid, ULONG64 ownerCreateTime, const WCHAR *ownerSid)
{
    ULONG stoppedCount = 0;
    CAPTURE_SESSION_OBJ *entry = (CAPTURE_SESSION_OBJ *)List_Tail(&m_sessions);

    while (entry) {
        CAPTURE_SESSION_OBJ *previous =
            (CAPTURE_SESSION_OBJ *)List_Prev(entry);

        if (entry->owner_pid == ownerPid &&
                entry->owner_create_time == ownerCreateTime &&
                _wcsicmp(entry->owner_sid, ownerSid) == 0 &&
                entry->info.state == CAPTURE_STATE_STOPPED) {

            ++stoppedCount;
            if (stoppedCount > CAPTURE_MAX_STOPPED_PER_OWNER)
                DeleteSession(entry);
        }

        entry = previous;
    }
}


void CaptureServer::DeleteSession(CAPTURE_SESSION_OBJ *session)
{
    if (session->backend_active || session->broker_process ||
            session->broker_job || session->export_file ||
            session->section_handle)
        StopBackend(session, FALSE);
    List_Remove(&m_sessions, session);
    if (session->export_file)
        CloseHandle(session->export_file);
    if (session->section_handle)
        CloseHandle(session->section_handle);
    if (session->stopped_events)
        HeapFree(m_heap, 0, session->stopped_events);
    HeapFree(m_heap, 0, session);
}
