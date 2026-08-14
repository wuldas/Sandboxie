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


typedef struct _CAPTURE_SESSION_OBJ {

    LIST_ELEM list_elem;
    ULONG owner_pid;
    ULONG owner_session_id;
    ULONG64 owner_create_time;
    WCHAR owner_sid[96];
    BOOLEAN backend_active;
    ULONG stopped_event_head;
    ULONG stopped_event_count;
    CAPTURE_CONNECTION_EVENT *stopped_events;
    CAPTURE_SESSION_INFO info;

} CAPTURE_SESSION_OBJ;


static_assert(sizeof(CAPTURE_DRIVER_SESSION_ID) == sizeof(CAPTURE_SESSION_ID),
              "driver and service capture identifiers differ");
static_assert(sizeof(CAPTURE_DRIVER_EVENT) == sizeof(CAPTURE_CONNECTION_EVENT),
              "driver and service capture events differ");
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


static ULONG CaptureServer_QueryDriver(void)
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
    if (NT_SUCCESS(CaptureServer_QueryDriver()))
        rpl->capabilities |= CAPTURE_CAP_CONNECTION_AUDIT;
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

    if ((req->mode & ~CAPTURE_MODE_CONNECTIONS) != 0)
        return SHORT_REPLY(STATUS_NOT_SUPPORTED);

    if ((req->flags & ~(CAPTURE_FLAG_INCLUDE_FUTURE_PROCESSES |
                        CAPTURE_FLAG_INCLUDE_LOOPBACK)) != 0)
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

    status = CaptureServer_QueryDriver();
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

    session->backend_active = TRUE;
    session->info.state = CAPTURE_STATE_RUNNING;
    session->info.backend_status = STATUS_SUCCESS;
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

    return SHORT_REPLY(STATUS_NOT_SUPPORTED);
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
    if (! session->backend_active)
        return STATUS_SUCCESS;

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
            session->info.dropped_count = droppedCount;

            if (! remainingEvents || ! returnedEvents)
                break;
        }
    }

    ULONG stopStatus = CaptureServer_StopDriver(&session->info.capture_id);
    if (NT_SUCCESS(stopStatus) || stopStatus == STATUS_NOT_FOUND)
        session->backend_active = FALSE;

    if (! NT_SUCCESS(stopStatus))
        return stopStatus;
    return readStatus;
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
    if (session->backend_active)
        StopBackend(session, FALSE);
    List_Remove(&m_sessions, session);
    if (session->stopped_events)
        HeapFree(m_heap, 0, session->stopped_events);
    HeapFree(m_heap, 0, session);
}
