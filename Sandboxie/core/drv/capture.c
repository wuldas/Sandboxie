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
// Capture Connection Audit
//---------------------------------------------------------------------------

#include "driver.h"
#include "capture.h"

#include "api.h"
#include "box.h"
#include "wfp.h"
#include "capture_https.h"
#include "../svc/capturebrokerwire.h"

NTSTATUS NTAPI FwpsFlowRemoveContext0(
    UINT64 flowId, UINT16 layerId, UINT32 calloutId);


#define CAPTURE_MAX_FLOW_CONTEXTS 4096


//---------------------------------------------------------------------------
// Structures and Types
//---------------------------------------------------------------------------


typedef struct _CAPTURE_SESSION {

    LIST_ENTRY link;
    CAPTURE_DRIVER_SESSION_ID capture_id;
    CAPTURE_FILTER_TARGET target;
    CAPTURE_QUEUE *queue;
    CAPTURE_PACKET_QUEUE *packet_queue;
    CAPTURE_STREAM_QUEUE *stream_queue;
    BOOLEAN payload_enabled;
    BOOLEAN https_redirect_enabled;
    HANDLE section_kernel_handle;
    PVOID section_object;
    CAPTURE_BROKER_SECTION *section_system_address;
    PMDL section_mdl;
    SIZE_T section_view_size;
    ULONG shared_write_index;
    ULONG64 shared_sequence;
    CAPTURE_FILTER_PROCESS_KEY initial_processes[1];

} CAPTURE_SESSION;


typedef struct _CAPTURE_FLOW_CONTEXT {

    LIST_ENTRY link;
    LIST_ENTRY retire_link;
    UINT64 flow_id;
    UINT16 layer_id;
    UINT32 callout_id;
    BOOLEAN retiring;
    CAPTURE_DRIVER_SESSION_ID capture_id;
    CAPTURE_FILTER_IDENTITY identity;
    LONG retire_refs;
    BOOLEAN wfp_deleted;
    CAPTURE_PACKET_RECORD template_record;

} CAPTURE_FLOW_CONTEXT;


//---------------------------------------------------------------------------
// Variables
//---------------------------------------------------------------------------


static BOOLEAN Capture_Initialized = FALSE;
static BOOLEAN Capture_Unloading = FALSE;
static KSPIN_LOCK Capture_Lock;
static LIST_ENTRY Capture_Sessions;
static ULONG Capture_SessionCount = 0;
static LIST_ENTRY Capture_Flows;
static ULONG Capture_FlowCount = 0;


static void Capture_RetireFlowsForSession(
    const CAPTURE_DRIVER_SESSION_ID *captureId, BOOLEAN all);


//---------------------------------------------------------------------------
// Compile-time invariants
//---------------------------------------------------------------------------


C_ASSERT(CAPTURE_FILTER_SCOPE_BOX == CAPTURE_DRIVER_SCOPE_BOX);
C_ASSERT(CAPTURE_FILTER_SCOPE_PROCESS == CAPTURE_DRIVER_SCOPE_PROCESS);
C_ASSERT(CAPTURE_FILTER_FLAG_INCLUDE_FUTURE == CAPTURE_DRIVER_FLAG_INCLUDE_FUTURE);
C_ASSERT(CAPTURE_FILTER_FLAG_INCLUDE_LOOPBACK == CAPTURE_DRIVER_FLAG_INCLUDE_LOOPBACK);
C_ASSERT(CAPTURE_QUEUE_EVENT_CONNECT == CAPTURE_DRIVER_EVENT_CONNECT);
C_ASSERT(CAPTURE_QUEUE_EVENT_ACCEPT == CAPTURE_DRIVER_EVENT_ACCEPT);
C_ASSERT(CAPTURE_QUEUE_DIRECTION_OUTBOUND == CAPTURE_DRIVER_DIRECTION_OUTBOUND);
C_ASSERT(CAPTURE_QUEUE_DIRECTION_INBOUND == CAPTURE_DRIVER_DIRECTION_INBOUND);
C_ASSERT(sizeof(CAPTURE_FILTER_PROCESS_KEY) == sizeof(CAPTURE_DRIVER_PROCESS_KEY));
C_ASSERT(sizeof(CAPTURE_QUEUE_RECORD) == sizeof(CAPTURE_DRIVER_EVENT));
C_ASSERT(FIELD_OFFSET(CAPTURE_QUEUE_RECORD, sequence) ==
         FIELD_OFFSET(CAPTURE_DRIVER_EVENT, sequence));
C_ASSERT(FIELD_OFFSET(CAPTURE_QUEUE_RECORD, local_address) ==
         FIELD_OFFSET(CAPTURE_DRIVER_EVENT, local_address));
C_ASSERT(FIELD_OFFSET(CAPTURE_QUEUE_RECORD, remote_address) ==
         FIELD_OFFSET(CAPTURE_DRIVER_EVENT, remote_address));


//---------------------------------------------------------------------------
// Local helpers
//---------------------------------------------------------------------------


static void *Capture_Alloc(SIZE_T size)
{
    return ExAllocatePoolWithTag(NonPagedPool, size, tzuk);
}


static void Capture_Free(void *ptr)
{
    ExFreePoolWithTag(ptr, tzuk);
}


static BOOLEAN Capture_IdIsZero(const CAPTURE_DRIVER_SESSION_ID *captureId)
{
    return captureId->high == 0 && captureId->low == 0;
}


static BOOLEAN Capture_IdEquals(
    const CAPTURE_DRIVER_SESSION_ID *left,
    const CAPTURE_DRIVER_SESSION_ID *right)
{
    return left->high == right->high && left->low == right->low;
}


static BOOLEAN Capture_StringIsTerminated(
    const WCHAR *string, ULONG capacity, BOOLEAN allowEmpty)
{
    ULONG index;
    for (index = 0; index < capacity; ++index) {
        if (! string[index])
            return allowEmpty || index != 0;
    }

    return FALSE;
}


static CAPTURE_SESSION *Capture_FindSessionLocked(
    const CAPTURE_DRIVER_SESSION_ID *captureId)
{
    PLIST_ENTRY entry = Capture_Sessions.Flink;
    while (entry != &Capture_Sessions) {
        CAPTURE_SESSION *session = CONTAINING_RECORD(
            entry, CAPTURE_SESSION, link);
        if (Capture_IdEquals(&session->capture_id, captureId))
            return session;
        entry = entry->Flink;
    }

    return NULL;
}


static NTSTATUS Capture_CreateSharedSection(
    CAPTURE_SESSION *session)
{
    if (! session || ! session->payload_enabled)
        return STATUS_NOT_SUPPORTED;
    if (session->section_system_address)
        return STATUS_SUCCESS;

    const ULONG sectionSize = CAPTURE_BROKER_SECTION_SIZE(
        CAPTURE_BROKER_MAX_RECORD_CAPACITY);
    LARGE_INTEGER maximumSize;
    maximumSize.QuadPart = sectionSize;

    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(
        &attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE sectionHandle = NULL;
    NTSTATUS status = ZwCreateSection(
        &sectionHandle,
        SECTION_ALL_ACCESS,
        &attributes,
        &maximumSize,
        PAGE_READWRITE,
        SEC_COMMIT,
        NULL);
    if (! NT_SUCCESS(status))
        return status;

    PVOID sectionObject = NULL;
    status = ObReferenceObjectByHandle(
        sectionHandle,
        SECTION_ALL_ACCESS,
        NULL,
        KernelMode,
        &sectionObject,
        NULL);
    if (! NT_SUCCESS(status)) {
        ZwClose(sectionHandle);
        return status;
    }

    PVOID baseAddress = NULL;
    SIZE_T viewSize = 0;
    status = MmMapViewInSystemSpace(
        sectionObject, &baseAddress, &viewSize);
    if (! NT_SUCCESS(status) || viewSize < sectionSize) {
        if (NT_SUCCESS(status))
            MmUnmapViewInSystemSpace(baseAddress);
        ObDereferenceObject(sectionObject);
        ZwClose(sectionHandle);
        return NT_SUCCESS(status) ? STATUS_INVALID_BUFFER_SIZE : status;
    }

    PMDL sectionMdl = IoAllocateMdl(
        baseAddress, sectionSize, FALSE, FALSE, NULL);
    if (! sectionMdl) {
        MmUnmapViewInSystemSpace(baseAddress);
        ObDereferenceObject(sectionObject);
        ZwClose(sectionHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        MmProbeAndLockPages(sectionMdl, KernelMode, IoModifyAccess);
        status = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    if (! NT_SUCCESS(status)) {
        IoFreeMdl(sectionMdl);
        MmUnmapViewInSystemSpace(baseAddress);
        ObDereferenceObject(sectionObject);
        ZwClose(sectionHandle);
        return status;
    }

    CAPTURE_BROKER_SECTION *shared =
        (CAPTURE_BROKER_SECTION *)baseAddress;
    RtlZeroMemory(shared, viewSize);
    shared->magic = CAPTURE_BROKER_SECTION_MAGIC;
    shared->version = CAPTURE_BROKER_SECTION_VERSION;
    shared->size = sectionSize;
    shared->record_capacity = CAPTURE_BROKER_MAX_RECORD_CAPACITY;
    shared->capture_id_high = session->capture_id.high;
    shared->capture_id_low = session->capture_id.low;
    shared->generation = CaptureBroker_CalculateGeneration(
        session->capture_id.high, session->capture_id.low);
    RtlCopyMemory(
        shared->box_name,
        session->target.box_name,
        sizeof(shared->box_name));
    RtlCopyMemory(
        shared->sid_string,
        session->target.sid_string,
        sizeof(shared->sid_string));

    session->section_kernel_handle = sectionHandle;
    session->section_object = sectionObject;
    session->section_system_address = shared;
    session->section_mdl = sectionMdl;
    session->section_view_size = viewSize;
    session->shared_write_index = 0;
    session->shared_sequence = 0;
    return STATUS_SUCCESS;
}


static void Capture_DestroySharedSection(CAPTURE_SESSION *session)
{
    if (! session)
        return;
    if (session->section_mdl) {
        MmUnlockPages(session->section_mdl);
        IoFreeMdl(session->section_mdl);
        session->section_mdl = NULL;
    }
    if (session->section_system_address) {
        MmUnmapViewInSystemSpace(session->section_system_address);
        session->section_system_address = NULL;
    }
    if (session->section_object) {
        ObDereferenceObject(session->section_object);
        session->section_object = NULL;
    }
    if (session->section_kernel_handle) {
        ZwClose(session->section_kernel_handle);
        session->section_kernel_handle = NULL;
    }
    session->section_view_size = 0;
}


static void Capture_FreeSession(CAPTURE_SESSION *session)
{
    Capture_DestroySharedSection(session);
    if (session->queue)
        CaptureQueue_Destroy(session->queue, Capture_Free);
    if (session->packet_queue)
        CapturePacketQueue_Destroy(session->packet_queue, Capture_Free);
    if (session->stream_queue)
        CaptureStreamQueue_Destroy(session->stream_queue, Capture_Free);
    Capture_Free(session);
}


static void Capture_FreeFlow(CAPTURE_FLOW_CONTEXT *flow)
{
    Capture_Free(flow);
}


static void Capture_ReleaseAll(BOOLEAN unloading)
{
    LIST_ENTRY staleSessions;
    LIST_ENTRY staleFlows;
    InitializeListHead(&staleSessions);
    InitializeListHead(&staleFlows);

    if (! Capture_Initialized)
        return;

    KIRQL irql;
    KeAcquireSpinLock(&Capture_Lock, &irql);

    if (unloading)
        Capture_Unloading = TRUE;

    while (! IsListEmpty(&Capture_Sessions)) {
        PLIST_ENTRY entry = RemoveHeadList(&Capture_Sessions);
        InsertTailList(&staleSessions, entry);
    }
    Capture_SessionCount = 0;

    if (unloading) {
        while (! IsListEmpty(&Capture_Flows)) {
            PLIST_ENTRY entry = RemoveHeadList(&Capture_Flows);
            InsertTailList(&staleFlows, entry);
        }
        Capture_FlowCount = 0;
    }

    if (unloading)
        Capture_Initialized = FALSE;

    KeReleaseSpinLock(&Capture_Lock, irql);

    while (! IsListEmpty(&staleSessions)) {
        PLIST_ENTRY entry = RemoveHeadList(&staleSessions);
        Capture_FreeSession(CONTAINING_RECORD(entry, CAPTURE_SESSION, link));
    }

    while (! IsListEmpty(&staleFlows)) {
        PLIST_ENTRY entry = RemoveHeadList(&staleFlows);
        Capture_FreeFlow(CONTAINING_RECORD(
            entry, CAPTURE_FLOW_CONTEXT, link));
    }
}


static NTSTATUS Capture_ValidateStartControl(
    const CAPTURE_DRIVER_CONTROL *control)
{
    const ULONG knownFlags =
        CAPTURE_DRIVER_FLAG_INCLUDE_FUTURE |
        CAPTURE_DRIVER_FLAG_INCLUDE_LOOPBACK |
        CAPTURE_DRIVER_FLAG_INCLUDE_PAYLOAD;

    if (Capture_IdIsZero(&control->capture_id) ||
            control->reserved ||
            (control->flags & ~knownFlags) ||
            (control->queue_capacity != 0 &&
             control->queue_capacity != CAPTURE_DRIVER_QUEUE_CAPACITY) ||
            ! Box_IsValidName(control->box_name) ||
            ! Capture_StringIsTerminated(control->sid_string, 96, FALSE) ||
            control->initial_process_count >
                CAPTURE_DRIVER_MAX_INITIAL_PROCESSES) {
        return STATUS_INVALID_PARAMETER;
    }

    ULONG expectedSize = CAPTURE_DRIVER_CONTROL_BASE_SIZE +
        control->initial_process_count * sizeof(CAPTURE_DRIVER_PROCESS_KEY);
    if (control->size != expectedSize)
        return STATUS_INFO_LENGTH_MISMATCH;

    if (control->scope == CAPTURE_DRIVER_SCOPE_PROCESS) {
        if (! control->target_pid ||
                ! control->target_process_create_time ||
                control->initial_process_count ||
                (control->flags & CAPTURE_DRIVER_FLAG_INCLUDE_FUTURE)) {
            return STATUS_INVALID_PARAMETER;
        }
    }
    else if (control->scope == CAPTURE_DRIVER_SCOPE_BOX) {
        if (control->target_pid || control->target_process_create_time)
            return STATUS_INVALID_PARAMETER;
        if ((control->flags & CAPTURE_DRIVER_FLAG_INCLUDE_FUTURE) &&
                control->initial_process_count) {
            return STATUS_INVALID_PARAMETER;
        }
    }
    else {
        return STATUS_INVALID_PARAMETER;
    }

    for (ULONG index = 0;
            index < control->initial_process_count;
            ++index) {
        const CAPTURE_DRIVER_PROCESS_KEY *key =
            &control->initial_processes[index];
        if (! key->process_id || ! key->process_create_time || key->reserved)
            return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}


static NTSTATUS Capture_Start(const CAPTURE_DRIVER_CONTROL *control)
{
    NTSTATUS status = Capture_ValidateStartControl(control);
    if (! NT_SUCCESS(status))
        return status;

    if (control->flags & CAPTURE_DRIVER_FLAG_INCLUDE_PAYLOAD) {
#if CAPTURE_PACKET_CAPTURE_RELEASE_GATE
        if (! WFP_IsPayloadInspectionEnabled())
            return STATUS_NOT_SUPPORTED;
#else
        return STATUS_NOT_SUPPORTED;
#endif
    }

    if (! WFP_IsReady())
        return STATUS_DEVICE_NOT_READY;

    SIZE_T sessionSize = FIELD_OFFSET(CAPTURE_SESSION, initial_processes) +
        (SIZE_T)control->initial_process_count *
            sizeof(CAPTURE_FILTER_PROCESS_KEY);
    CAPTURE_SESSION *session =
        (CAPTURE_SESSION *)Capture_Alloc(sessionSize);
    if (! session)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(session, sessionSize);
    session->capture_id = control->capture_id;
    session->target.scope = control->scope;
    session->target.flags = control->flags;
    session->target.process_id = control->target_pid;
    session->target.session_id = control->target_session_id;
    session->target.process_create_time =
        control->target_process_create_time;
    RtlCopyMemory(
        session->target.box_name,
        control->box_name,
        sizeof(session->target.box_name));
    RtlCopyMemory(
        session->target.sid_string,
        control->sid_string,
        sizeof(session->target.sid_string));
    session->target.initial_process_count = control->initial_process_count;
    session->target.initial_processes = session->initial_processes;
    session->payload_enabled =
        (control->flags & CAPTURE_DRIVER_FLAG_INCLUDE_PAYLOAD) != 0;

    for (ULONG index = 0;
            index < control->initial_process_count;
            ++index) {
        session->initial_processes[index].process_id =
            control->initial_processes[index].process_id;
        session->initial_processes[index].reserved = 0;
        session->initial_processes[index].process_create_time =
            control->initial_processes[index].process_create_time;
    }

    session->queue = CaptureQueue_Create(
        CAPTURE_DRIVER_QUEUE_CAPACITY, Capture_Alloc);
    if (! session->queue) {
        Capture_Free(session);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (session->payload_enabled) {
        session->packet_queue = CapturePacketQueue_Create(
            CAPTURE_DRIVER_QUEUE_CAPACITY, Capture_Alloc);
        session->stream_queue = CaptureStreamQueue_Create(
            CAPTURE_DRIVER_QUEUE_CAPACITY, Capture_Alloc);
        if (! session->packet_queue || ! session->stream_queue) {
            Capture_FreeSession(session);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    KIRQL irql;
    KeAcquireSpinLock(&Capture_Lock, &irql);

    if (! Capture_Initialized || Capture_Unloading) {
        status = STATUS_DELETE_PENDING;
    }
    else if (Capture_FindSessionLocked(&control->capture_id)) {
        status = STATUS_OBJECT_NAME_COLLISION;
    }
    else if (Capture_SessionCount >= CAPTURE_DRIVER_MAX_SESSIONS) {
        status = STATUS_QUOTA_EXCEEDED;
    }
    else {
        InsertTailList(&Capture_Sessions, &session->link);
        ++Capture_SessionCount;
        session = NULL;
        status = STATUS_SUCCESS;
    }

    KeReleaseSpinLock(&Capture_Lock, irql);

    if (session)
        Capture_FreeSession(session);

    return status;
}


static NTSTATUS Capture_Stop(
    const CAPTURE_DRIVER_SESSION_ID *captureId)
{
    CAPTURE_SESSION *session = NULL;

    KIRQL irql;
    KeAcquireSpinLock(&Capture_Lock, &irql);

    session = Capture_FindSessionLocked(captureId);
    if (session) {
        RemoveEntryList(&session->link);
        --Capture_SessionCount;
    }

    KeReleaseSpinLock(&Capture_Lock, irql);

    if (! session)
        return STATUS_NOT_FOUND;

    Capture_RetireFlowsForSession(captureId, FALSE);
    Capture_FreeSession(session);
    return STATUS_SUCCESS;
}


static NTSTATUS Capture_EnableHttps(
    const CAPTURE_DRIVER_SESSION_ID *captureId)
{
    KIRQL irql;
    CAPTURE_SESSION *session;
    NTSTATUS status = STATUS_NOT_FOUND;

    KeAcquireSpinLock(&Capture_Lock, &irql);
    session = Capture_FindSessionLocked(captureId);
    if (session) {
        session->https_redirect_enabled = TRUE;
        status = STATUS_SUCCESS;
    }
    KeReleaseSpinLock(&Capture_Lock, irql);
    return status;
}


//---------------------------------------------------------------------------
// Driver API
//---------------------------------------------------------------------------


static NTSTATUS Capture_Api_Control(PROCESS *proc, ULONG64 *parms)
{
    API_CAPTURE_CONTROL_ARGS *args =
        (API_CAPTURE_CONTROL_ARGS *)parms;

    if (proc || PsGetCurrentProcessId() != Api_ServiceProcessId)
        return STATUS_ACCESS_DENIED;

    CAPTURE_DRIVER_CONTROL *userControl = args->control.val;
    if (! userControl)
        return STATUS_INVALID_PARAMETER;

    ULONG controlSize = 0;
    ULONG version = 0;
    __try {
        ProbeForRead(userControl, sizeof(ULONG) * 2, sizeof(ULONG));
        version = userControl->version;
        controlSize = userControl->size;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    if (version != CAPTURE_DRIVER_VERSION)
        return STATUS_REVISION_MISMATCH;

    ULONG maxControlSize = CAPTURE_DRIVER_CONTROL_BASE_SIZE +
        CAPTURE_DRIVER_MAX_INITIAL_PROCESSES *
            sizeof(CAPTURE_DRIVER_PROCESS_KEY);
    if (controlSize < CAPTURE_DRIVER_CONTROL_BASE_SIZE ||
            controlSize > maxControlSize) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    CAPTURE_DRIVER_CONTROL *control =
        (CAPTURE_DRIVER_CONTROL *)ExAllocatePoolWithTag(
            PagedPool, controlSize, tzuk);
    if (! control)
        return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS status = STATUS_SUCCESS;
    __try {
        ProbeForRead(userControl, controlSize, sizeof(ULONG));
        RtlCopyMemory(control, userControl, controlSize);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (! NT_SUCCESS(status)) {
        ExFreePoolWithTag(control, tzuk);
        return status;
    }

    if (control->version != version || control->size != controlSize) {
        ExFreePoolWithTag(control, tzuk);
        return STATUS_INVALID_PARAMETER;
    }

    if (control->operation == CAPTURE_DRIVER_CONTROL_QUERY) {
        if (controlSize != CAPTURE_DRIVER_CONTROL_BASE_SIZE) {
            status = STATUS_INFO_LENGTH_MISMATCH;
        }
        else if (! WFP_IsReady()) {
            status = STATUS_DEVICE_NOT_READY;
        }
        else {
            control->flags =
                CAPTURE_DRIVER_FLAG_INCLUDE_FUTURE |
                CAPTURE_DRIVER_FLAG_INCLUDE_LOOPBACK;
            if (WFP_IsPayloadInspectionEnabled())
                control->flags |= CAPTURE_DRIVER_FLAG_INCLUDE_PAYLOAD;
            if (WFP_IsHttpsRedirectAvailable())
                control->flags |= CAPTURE_DRIVER_FLAG_HTTPS_REDIRECT;
            control->queue_capacity = CAPTURE_DRIVER_QUEUE_CAPACITY;
            control->initial_process_count = 0;
            control->reserved = 0;

            __try {
                ProbeForWrite(userControl, controlSize, sizeof(ULONG));
                RtlCopyMemory(userControl, control, controlSize);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                status = GetExceptionCode();
            }
        }
    }
    else if (control->operation == CAPTURE_DRIVER_CONTROL_START) {
        status = Capture_Start(control);
    }
    else if (control->operation == CAPTURE_DRIVER_CONTROL_STOP) {
        if (controlSize != CAPTURE_DRIVER_CONTROL_BASE_SIZE ||
                Capture_IdIsZero(&control->capture_id)) {
            status = STATUS_INVALID_PARAMETER;
        }
        else {
            status = Capture_Stop(&control->capture_id);
        }
    }
    else if (control->operation == CAPTURE_DRIVER_CONTROL_ENABLE_HTTPS) {
        if (controlSize != CAPTURE_DRIVER_CONTROL_BASE_SIZE ||
                Capture_IdIsZero(&control->capture_id)) {
            status = STATUS_INVALID_PARAMETER;
        }
        else if (! WFP_IsHttpsRedirectAvailable()) {
            status = STATUS_NOT_SUPPORTED;
        }
        else {
            status = Capture_EnableHttps(&control->capture_id);
        }
    }
    else {
        status = STATUS_INVALID_PARAMETER;
    }

    ExFreePoolWithTag(control, tzuk);
    return status;
}


static NTSTATUS Capture_OpenSharedSectionObjectHandle(
    PVOID sectionObject, HANDLE *userHandle)
{
    if (! sectionObject || ! userHandle)
        return STATUS_INVALID_PARAMETER;

    *userHandle = NULL;
    const ACCESS_MASK desiredAccess =
        SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_QUERY;
    HANDLE sectionKernelHandle = NULL;
    NTSTATUS status = ObOpenObjectByPointer(
        sectionObject,
        OBJ_KERNEL_HANDLE,
        NULL,
        desiredAccess,
        *MmSectionObjectType,
        KernelMode,
        &sectionKernelHandle);
    if (! NT_SUCCESS(status))
        return status;

    HANDLE systemProcessHandle = NULL;
    status = ObOpenObjectByPointer(
        PsInitialSystemProcess,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_DUP_HANDLE,
        *PsProcessType,
        KernelMode,
        &systemProcessHandle);
    if (NT_SUCCESS(status)) {
        status = ZwDuplicateObject(
            systemProcessHandle,
            sectionKernelHandle,
            ZwCurrentProcess(),
            userHandle,
            desiredAccess,
            0,
            0);
        ZwClose(systemProcessHandle);
    }

    ZwClose(sectionKernelHandle);
    return status;
}


static NTSTATUS Capture_Api_Map(PROCESS *proc, ULONG64 *parms)
{
    API_CAPTURE_MAP_ARGS *args = (API_CAPTURE_MAP_ARGS *)parms;
    if (proc || PsGetCurrentProcessId() != Api_ServiceProcessId)
        return STATUS_ACCESS_DENIED;

    CAPTURE_DRIVER_MAP *userMap = args->map.val;
    if (! userMap)
        return STATUS_INVALID_PARAMETER;

    CAPTURE_DRIVER_MAP request;
    RtlZeroMemory(&request, sizeof(request));
    __try {
        ProbeForRead(userMap, sizeof(request), sizeof(ULONG));
        RtlCopyMemory(&request, userMap, sizeof(request));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    if (request.version != CAPTURE_DRIVER_VERSION ||
            request.size != sizeof(request) ||
            Capture_IdIsZero(&request.capture_id) ||
            request.record_capacity || request.section_size ||
            request.section_handle || request.reserved) {
        return STATUS_INVALID_PARAMETER;
    }

    CAPTURE_SESSION temporary;
    RtlZeroMemory(&temporary, sizeof(temporary));
    CAPTURE_SESSION *session = NULL;
    PVOID referencedObject = NULL;
    BOOLEAN temporaryCreated = FALSE;

    KIRQL irql;
    KeAcquireSpinLock(&Capture_Lock, &irql);
    session = Capture_FindSessionLocked(&request.capture_id);
    if (! session) {
        KeReleaseSpinLock(&Capture_Lock, irql);
        return STATUS_NOT_FOUND;
    }
    if (! session->payload_enabled) {
        KeReleaseSpinLock(&Capture_Lock, irql);
        return STATUS_NOT_SUPPORTED;
    }
    if (session->section_object) {
        referencedObject = session->section_object;
        ObReferenceObject(referencedObject);
    }
    else {
        temporary.capture_id = request.capture_id;
        temporary.target.scope = CAPTURE_DRIVER_SCOPE_BOX;
        temporary.target.flags = CAPTURE_DRIVER_FLAG_INCLUDE_PAYLOAD;
        temporary.target.session_id = 0;
        RtlCopyMemory(
            temporary.target.box_name,
            session->target.box_name,
            sizeof(temporary.target.box_name));
        RtlCopyMemory(
            temporary.target.sid_string,
            session->target.sid_string,
            sizeof(temporary.target.sid_string));
        temporary.payload_enabled = TRUE;
    }
    KeReleaseSpinLock(&Capture_Lock, irql);

    if (! referencedObject) {
        NTSTATUS createStatus = Capture_CreateSharedSection(&temporary);
        if (! NT_SUCCESS(createStatus))
            return createStatus;
        temporaryCreated = TRUE;

        KeAcquireSpinLock(&Capture_Lock, &irql);
        session = Capture_FindSessionLocked(&request.capture_id);
        if (! session || ! session->payload_enabled) {
            KeReleaseSpinLock(&Capture_Lock, irql);
            Capture_DestroySharedSection(&temporary);
            return ! session ? STATUS_NOT_FOUND : STATUS_NOT_SUPPORTED;
        }
        if (! session->section_object) {
            session->section_kernel_handle = temporary.section_kernel_handle;
            session->section_object = temporary.section_object;
            session->section_system_address =
                temporary.section_system_address;
            session->section_mdl = temporary.section_mdl;
            session->section_view_size = temporary.section_view_size;
            session->shared_write_index = temporary.shared_write_index;
            session->shared_sequence = temporary.shared_sequence;
            temporary.section_kernel_handle = NULL;
            temporary.section_object = NULL;
            temporary.section_system_address = NULL;
            temporary.section_mdl = NULL;
            temporary.section_view_size = 0;
        }
        referencedObject = session->section_object;
        ObReferenceObject(referencedObject);
        KeReleaseSpinLock(&Capture_Lock, irql);
    }

    if (temporaryCreated)
        Capture_DestroySharedSection(&temporary);

    HANDLE userHandle = NULL;
    NTSTATUS status = Capture_OpenSharedSectionObjectHandle(
        referencedObject, &userHandle);
    ObDereferenceObject(referencedObject);
    if (! NT_SUCCESS(status))
        return status;

    CAPTURE_DRIVER_MAP output = request;
    output.record_capacity = CAPTURE_BROKER_MAX_RECORD_CAPACITY;
    output.section_size = CAPTURE_BROKER_SECTION_SIZE(
        CAPTURE_BROKER_MAX_RECORD_CAPACITY);
    output.section_handle = (ULONG64)(ULONG_PTR)userHandle;

    __try {
        ProbeForWrite(userMap, sizeof(output), sizeof(ULONG));
        RtlCopyMemory(userMap, &output, sizeof(output));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ZwClose(userHandle);
        return GetExceptionCode();
    }

    return STATUS_SUCCESS;
}


static NTSTATUS Capture_Api_Read(PROCESS *proc, ULONG64 *parms)
{
    API_CAPTURE_READ_ARGS *args = (API_CAPTURE_READ_ARGS *)parms;

    if (proc || PsGetCurrentProcessId() != Api_ServiceProcessId)
        return STATUS_ACCESS_DENIED;

    CAPTURE_DRIVER_READ *userRead = args->read.val;
    ULONG readSize = args->read_size.val;
    const ULONG maxReadSize = CAPTURE_DRIVER_READ_BASE_SIZE +
        CAPTURE_DRIVER_MAX_READ_EVENTS * sizeof(CAPTURE_DRIVER_EVENT);

    if (! userRead || readSize < CAPTURE_DRIVER_READ_BASE_SIZE ||
            readSize > maxReadSize) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    CAPTURE_DRIVER_READ request;
    RtlZeroMemory(&request, sizeof(request));

    __try {
        ProbeForRead(userRead, CAPTURE_DRIVER_READ_BASE_SIZE, sizeof(ULONG));
        RtlCopyMemory(&request, userRead, CAPTURE_DRIVER_READ_BASE_SIZE);
        ProbeForWrite(userRead, readSize, sizeof(ULONG));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    if (request.version != CAPTURE_DRIVER_VERSION)
        return STATUS_REVISION_MISMATCH;
    if (request.size != readSize || request.reserved ||
            Capture_IdIsZero(&request.capture_id) ||
            ! request.max_events ||
            request.max_events > CAPTURE_DRIVER_MAX_READ_EVENTS ||
            readSize != CAPTURE_DRIVER_READ_BASE_SIZE +
                request.max_events * sizeof(CAPTURE_DRIVER_EVENT)) {
        return STATUS_INVALID_PARAMETER;
    }

    SIZE_T eventBytes =
        (SIZE_T)request.max_events * sizeof(CAPTURE_QUEUE_RECORD);
    CAPTURE_QUEUE_RECORD *events =
        (CAPTURE_QUEUE_RECORD *)Capture_Alloc(eventBytes);
    if (! events)
        return STATUS_INSUFFICIENT_RESOURCES;

    ULONG64 nextSequence = 0;
    ULONG64 oldestSequence = 0;
    ULONG64 newestSequence = 0;
    ULONG64 droppedCount = 0;
    ULONG remainingEvents = 0;
    ULONG returnedEvents = 0;
    NTSTATUS status = STATUS_SUCCESS;

    KIRQL irql;
    KeAcquireSpinLock(&Capture_Lock, &irql);

    CAPTURE_SESSION *session =
        Capture_FindSessionLocked(&request.capture_id);
    if (! session) {
        status = STATUS_NOT_FOUND;
    }
    else {
        returnedEvents = CaptureQueue_Drain(
            session->queue,
            events,
            request.max_events,
            &nextSequence,
            &oldestSequence,
            &newestSequence,
            &droppedCount,
            &remainingEvents);
    }

    KeReleaseSpinLock(&Capture_Lock, irql);

    if (NT_SUCCESS(status)) {
        CAPTURE_DRIVER_READ output;
        RtlZeroMemory(&output, sizeof(output));
        output.version = CAPTURE_DRIVER_VERSION;
        output.size = readSize;
        output.capture_id = request.capture_id;
        output.next_sequence = nextSequence;
        output.oldest_sequence = oldestSequence;
        output.newest_sequence = newestSequence;
        output.dropped_count = droppedCount;
        output.max_events = request.max_events;
        output.returned_events = returnedEvents;
        output.remaining_events = remainingEvents;

        __try {
            RtlCopyMemory(userRead, &output, CAPTURE_DRIVER_READ_BASE_SIZE);
            if (returnedEvents) {
                RtlCopyMemory(
                    userRead->events,
                    events,
                    returnedEvents * sizeof(CAPTURE_DRIVER_EVENT));
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
        }
    }

    Capture_Free(events);
    return status;
}


#if 0
static NTSTATUS Capture_Api_ReadPayload(
    PROCESS *proc, ULONG64 *parms, BOOLEAN stream)
{
    void *userRead = NULL;
    ULONG readSize = 0;
    if (stream) {
        API_CAPTURE_STREAM_READ_ARGS *args =
            (API_CAPTURE_STREAM_READ_ARGS *)parms;
        userRead = args->read.val;
        readSize = args->read_size.val;
    }
    else {
        API_CAPTURE_PACKET_READ_ARGS *args =
            (API_CAPTURE_PACKET_READ_ARGS *)parms;
        userRead = args->read.val;
        readSize = args->read_size.val;
    }

    if (proc || PsGetCurrentProcessId() != Api_ServiceProcessId)
        return STATUS_ACCESS_DENIED;

    const ULONG maxRecords = stream ?
        CAPTURE_DRIVER_MAX_READ_STREAMS : CAPTURE_DRIVER_MAX_READ_PACKETS;
    const ULONG maxReadSize = CAPTURE_DRIVER_PACKET_READ_BASE_SIZE +
        maxRecords * sizeof(CAPTURE_PACKET_RECORD);
    if (! userRead || readSize < CAPTURE_DRIVER_PACKET_READ_BASE_SIZE ||
            readSize > maxReadSize) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    CAPTURE_DRIVER_PACKET_READ request;
    RtlZeroMemory(&request, sizeof(request));
    __try {
        ProbeForRead(
            userRead, CAPTURE_DRIVER_PACKET_READ_BASE_SIZE, sizeof(ULONG));
        RtlCopyMemory(
            &request, userRead, CAPTURE_DRIVER_PACKET_READ_BASE_SIZE);
        ProbeForWrite(userRead, readSize, sizeof(ULONG));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    if (request.version != CAPTURE_DRIVER_VERSION)
        return STATUS_REVISION_MISMATCH;
    if (request.size != readSize || request.reserved ||
            Capture_IdIsZero(&request.capture_id) ||
            ! request.max_records || request.max_records > maxRecords ||
            readSize != CAPTURE_DRIVER_PACKET_READ_BASE_SIZE +
                request.max_records * sizeof(CAPTURE_PACKET_RECORD)) {
        return STATUS_INVALID_PARAMETER;
    }

    SIZE_T recordBytes = (SIZE_T)request.max_records *
        sizeof(CAPTURE_PACKET_RECORD);
    CAPTURE_PACKET_RECORD *records =
        (CAPTURE_PACKET_RECORD *)Capture_Alloc(recordBytes);
    if (! records)
        return STATUS_INSUFFICIENT_RESOURCES;

    ULONG64 nextSequence = 0;
    ULONG64 oldestSequence = 0;
    ULONG64 newestSequence = 0;
    ULONG64 droppedCount = 0;
    ULONG remainingRecords = 0;
    ULONG returnedRecords = 0;
    NTSTATUS status = STATUS_SUCCESS;

    KIRQL irql;
    KeAcquireSpinLock(&Capture_Lock, &irql);
    CAPTURE_SESSION *session =
        Capture_FindSessionLocked(&request.capture_id);
    if (! session) {
        status = STATUS_NOT_FOUND;
    }
    else if (! session->payload_enabled) {
        status = STATUS_NOT_SUPPORTED;
    }
    else if (stream) {
        returnedRecords = CaptureStreamQueue_Drain(
            session->stream_queue,
            (CAPTURE_STREAM_RECORD *)records,
            request.max_records,
            &nextSequence,
            &oldestSequence,
            &newestSequence,
            &droppedCount,
            &remainingRecords);
    }
    else {
        returnedRecords = CapturePacketQueue_Drain(
            session->packet_queue,
            records,
            request.max_records,
            &nextSequence,
            &oldestSequence,
            &newestSequence,
            &droppedCount,
            &remainingRecords);
    }
    KeReleaseSpinLock(&Capture_Lock, irql);

    if (NT_SUCCESS(status)) {
        CAPTURE_DRIVER_PACKET_READ output;
        RtlZeroMemory(&output, sizeof(output));
        output.version = CAPTURE_DRIVER_VERSION;
        output.size = readSize;
        output.capture_id = request.capture_id;
        output.next_sequence = nextSequence;
        output.oldest_sequence = oldestSequence;
        output.newest_sequence = newestSequence;
        output.dropped_count = droppedCount;
        output.max_records = request.max_records;
        output.returned_records = returnedRecords;
        output.remaining_records = remainingRecords;

        __try {
            RtlCopyMemory(
                userRead, &output, CAPTURE_DRIVER_PACKET_READ_BASE_SIZE);
            if (returnedRecords) {
                RtlCopyMemory(
                    (UCHAR *)userRead + CAPTURE_DRIVER_PACKET_READ_BASE_SIZE,
                    records,
                    returnedRecords * sizeof(CAPTURE_PACKET_RECORD));
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
        }
    }

    Capture_Free(records);
    return status;
}


static NTSTATUS Capture_Api_ReadPackets(PROCESS *proc, ULONG64 *parms)
{
    return Capture_Api_ReadPayload(proc, parms, FALSE);
}


static NTSTATUS Capture_Api_ReadStreams(PROCESS *proc, ULONG64 *parms)
{
    return Capture_Api_ReadPayload(proc, parms, TRUE);
}
#endif


//---------------------------------------------------------------------------
// Public functions
//---------------------------------------------------------------------------


BOOLEAN Capture_Init(void)
{
    KeInitializeSpinLock(&Capture_Lock);
    InitializeListHead(&Capture_Sessions);
    Capture_SessionCount = 0;
    InitializeListHead(&Capture_Flows);
    Capture_FlowCount = 0;
    Capture_Unloading = FALSE;
    Capture_Initialized = TRUE;

    Api_SetFunction(API_CAPTURE_CONTROL, Capture_Api_Control);
    Api_SetFunction(API_CAPTURE_READ, Capture_Api_Read);
    Api_SetFunction(API_CAPTURE_MAP, Capture_Api_Map);
    return TRUE;
}


void Capture_Unload(void)
{
    Capture_ReleaseAll(TRUE);
}


void Capture_Reset(void)
{
    Capture_RetireFlowsForSession(NULL, TRUE);
    Capture_ReleaseAll(FALSE);
}


void Capture_RecordEvent(
    const CAPTURE_FILTER_IDENTITY *identity,
    const CAPTURE_QUEUE_RECORD *record)
{
    if (! identity || ! record || ! Capture_Initialized)
        return;

    KIRQL irql;
    KeAcquireSpinLock(&Capture_Lock, &irql);

    if (! Capture_Unloading) {
        PLIST_ENTRY entry = Capture_Sessions.Flink;
        while (entry != &Capture_Sessions) {
            CAPTURE_SESSION *session = CONTAINING_RECORD(
                entry, CAPTURE_SESSION, link);
            if (CaptureFilter_Matches(&session->target, identity))
                CaptureQueue_Push(session->queue, record);
            entry = entry->Flink;
        }
    }

    KeReleaseSpinLock(&Capture_Lock, irql);
}


BOOLEAN Capture_LookupHttpsRedirect(
    const CAPTURE_FILTER_IDENTITY *identity,
    USHORT *listenPort,
    ULONG64 *captureIdHigh,
    ULONG64 *captureIdLow,
    ULONG64 *generation)
{
    BOOLEAN found = FALSE;

    if (! identity || ! listenPort || ! captureIdHigh ||
            ! captureIdLow || ! generation || ! Capture_Initialized) {
        return FALSE;
    }

    KIRQL irql;
    KeAcquireSpinLock(&Capture_Lock, &irql);

    if (! Capture_Unloading) {
        PLIST_ENTRY entry = Capture_Sessions.Flink;
        while (entry != &Capture_Sessions) {
            CAPTURE_SESSION *session = CONTAINING_RECORD(
                entry, CAPTURE_SESSION, link);
            ULONG port = 0;
            if (session->section_system_address)
                port = session->section_system_address->https_listen_port;
            if (session->https_redirect_enabled &&
                    port != 0 && port <= 0xFFFFul &&
                    CaptureFilter_Matches(&session->target, identity)) {
                *listenPort = (USHORT)port;
                *captureIdHigh = session->capture_id.high;
                *captureIdLow = session->capture_id.low;
                *generation = CaptureBroker_CalculateGeneration(
                    session->capture_id.high, session->capture_id.low);
                found = TRUE;
                break;
            }
            entry = entry->Flink;
        }
    }

    KeReleaseSpinLock(&Capture_Lock, irql);
    return found;
}


static CAPTURE_FLOW_CONTEXT *Capture_FindFlowLocked(UINT64 flowContext)
{
    PLIST_ENTRY entry = Capture_Flows.Flink;
    while (entry != &Capture_Flows) {
        CAPTURE_FLOW_CONTEXT *flow = CONTAINING_RECORD(
            entry, CAPTURE_FLOW_CONTEXT, link);
        if ((UINT64)(ULONG_PTR)flow == flowContext)
            return flow;
        entry = entry->Flink;
    }
    return NULL;
}


static CAPTURE_SESSION *Capture_FindPayloadSessionLocked(
    const CAPTURE_FILTER_IDENTITY *identity)
{
    PLIST_ENTRY entry = Capture_Sessions.Flink;
    while (entry != &Capture_Sessions) {
        CAPTURE_SESSION *session = CONTAINING_RECORD(
            entry, CAPTURE_SESSION, link);
        if (session->payload_enabled &&
                CaptureFilter_Matches(&session->target, identity)) {
            return session;
        }
        entry = entry->Flink;
    }
    return NULL;
}


UINT64 Capture_CreateFlowContext(
    const CAPTURE_FILTER_IDENTITY *identity,
    const CAPTURE_PACKET_RECORD *templateRecord,
    UINT64 flowId,
    UINT16 layerId,
    UINT32 calloutId)
{
    if (! identity || ! templateRecord || ! flowId ||
            ! Capture_Initialized)
        return 0;

    CAPTURE_DRIVER_SESSION_ID captureId;
    RtlZeroMemory(&captureId, sizeof(captureId));
    KIRQL irql;
    KeAcquireSpinLock(&Capture_Lock, &irql);
    CAPTURE_SESSION *session = Capture_FindPayloadSessionLocked(identity);
    if (Capture_Unloading || ! session ||
            Capture_FlowCount >= CAPTURE_MAX_FLOW_CONTEXTS) {
        if (session && session->section_system_address &&
                Capture_FlowCount >= CAPTURE_MAX_FLOW_CONTEXTS &&
                session->section_system_address->dropped_count < (ULONG64)-1) {
            ++session->section_system_address->dropped_count;
        }
        KeReleaseSpinLock(&Capture_Lock, irql);
        return 0;
    }
    captureId = session->capture_id;
    KeReleaseSpinLock(&Capture_Lock, irql);

    CAPTURE_FLOW_CONTEXT *flow =
        (CAPTURE_FLOW_CONTEXT *)Capture_Alloc(sizeof(*flow));
    if (! flow)
        return 0;

    RtlZeroMemory(flow, sizeof(*flow));
    flow->flow_id = flowId;
    flow->layer_id = layerId;
    flow->callout_id = calloutId;
    flow->capture_id = captureId;
    flow->identity = *identity;
    flow->template_record = *templateRecord;

    BOOLEAN keep = FALSE;
    KeAcquireSpinLock(&Capture_Lock, &irql);
    session = Capture_FindPayloadSessionLocked(identity);
    if (! Capture_Unloading && session &&
            Capture_FlowCount < CAPTURE_MAX_FLOW_CONTEXTS &&
            Capture_IdEquals(&session->capture_id, &flow->capture_id)) {
        InsertTailList(&Capture_Flows, &flow->link);
        ++Capture_FlowCount;
        keep = TRUE;
    }
    else if (session && session->section_system_address &&
            Capture_FlowCount >= CAPTURE_MAX_FLOW_CONTEXTS &&
            session->section_system_address->dropped_count < (ULONG64)-1) {
        ++session->section_system_address->dropped_count;
    }
    KeReleaseSpinLock(&Capture_Lock, irql);

    if (! keep) {
        Capture_FreeFlow(flow);
        return 0;
    }

    return (UINT64)(ULONG_PTR)flow;
}


void Capture_DeleteFlowContext(UINT64 flowContext)
{
    if (! flowContext || ! Capture_Initialized)
        return;

    CAPTURE_FLOW_CONTEXT *flow = NULL;
    BOOLEAN freeFlow = FALSE;
    KIRQL irql;
    KeAcquireSpinLock(&Capture_Lock, &irql);

    flow = Capture_FindFlowLocked(flowContext);
    if (flow) {
        RemoveEntryList(&flow->link);
        --Capture_FlowCount;
        flow->wfp_deleted = TRUE;
        freeFlow = flow->retire_refs == 0;
    }

    KeReleaseSpinLock(&Capture_Lock, irql);

    if (freeFlow)
        Capture_FreeFlow(flow);
}


UINT64 Capture_LookupFlowContext(
    UINT64 flowId,
    UINT16 layerId,
    UINT32 calloutId)
{
    UINT64 context = 0;
    KIRQL irql;

    if (! flowId || ! calloutId || ! Capture_Initialized)
        return 0;

    KeAcquireSpinLock(&Capture_Lock, &irql);
    {
        PLIST_ENTRY entry = Capture_Flows.Flink;
        while (entry != &Capture_Flows) {
            CAPTURE_FLOW_CONTEXT *flow = CONTAINING_RECORD(
                entry, CAPTURE_FLOW_CONTEXT, link);
            if (! flow->retiring &&
                    flow->flow_id == flowId &&
                    flow->layer_id == layerId &&
                    flow->callout_id == calloutId) {
                context = (UINT64)(ULONG_PTR)flow;
                break;
            }
            entry = entry->Flink;
        }
    }
    KeReleaseSpinLock(&Capture_Lock, irql);
    return context;
}


void Capture_CountDroppedIdentity(const CAPTURE_FILTER_IDENTITY *identity)
{
    if (! identity || ! Capture_Initialized)
        return;

    KIRQL irql;
    KeAcquireSpinLock(&Capture_Lock, &irql);
    {
        PLIST_ENTRY entry = Capture_Sessions.Flink;
        while (entry != &Capture_Sessions) {
            CAPTURE_SESSION *session = CONTAINING_RECORD(
                entry, CAPTURE_SESSION, link);
            if (session->payload_enabled &&
                    session->section_system_address &&
                    CaptureFilter_Matches(&session->target, identity) &&
                    session->section_system_address->dropped_count <
                        (ULONG64)-1) {
                ++session->section_system_address->dropped_count;
            }
            entry = entry->Flink;
        }
    }
    KeReleaseSpinLock(&Capture_Lock, irql);
}


static void Capture_ReleaseRetireRef(CAPTURE_FLOW_CONTEXT *flow)
{
    BOOLEAN freeFlow = FALSE;
    KIRQL irql;
    KeAcquireSpinLock(&Capture_Lock, &irql);
    if (flow->retire_refs > 0)
        --flow->retire_refs;
    freeFlow = flow->wfp_deleted && flow->retire_refs == 0;
    KeReleaseSpinLock(&Capture_Lock, irql);

    if (freeFlow)
        Capture_FreeFlow(flow);
}


static void Capture_RetireFlowsForSession(
    const CAPTURE_DRIVER_SESSION_ID *captureId, BOOLEAN all)
{
    LIST_ENTRY retiring;
    InitializeListHead(&retiring);

    KIRQL irql;
    KeAcquireSpinLock(&Capture_Lock, &irql);
    PLIST_ENTRY entry = Capture_Flows.Flink;
    while (entry != &Capture_Flows) {
        CAPTURE_FLOW_CONTEXT *flow = CONTAINING_RECORD(
            entry, CAPTURE_FLOW_CONTEXT, link);
        if (! flow->retiring &&
                (all || (captureId && Capture_IdEquals(
                    &flow->capture_id, captureId)))) {
            flow->retiring = TRUE;
            ++flow->retire_refs;
            InitializeListHead(&flow->retire_link);
            InsertTailList(&retiring, &flow->retire_link);
        }
        entry = entry->Flink;
    }
    KeReleaseSpinLock(&Capture_Lock, irql);

    while (! IsListEmpty(&retiring)) {
        PLIST_ENTRY link = RemoveHeadList(&retiring);
        CAPTURE_FLOW_CONTEXT *flow = CONTAINING_RECORD(
            link, CAPTURE_FLOW_CONTEXT, retire_link);
        NTSTATUS status = FwpsFlowRemoveContext0(
            flow->flow_id, flow->layer_id, flow->callout_id);
        if (status == STATUS_NOT_FOUND)
            Capture_DeleteFlowContext((UINT64)(ULONG_PTR)flow);
        Capture_ReleaseRetireRef(flow);
    }
}


static BOOLEAN Capture_SharedContractValidLocked(
    const CAPTURE_SESSION *session,
    const CAPTURE_BROKER_SECTION *shared)
{
    if (! session || ! shared ||
            session->section_view_size <
                CAPTURE_BROKER_SECTION_SIZE(
                    CAPTURE_BROKER_MAX_RECORD_CAPACITY)) {
        return FALSE;
    }

    return shared->magic == CAPTURE_BROKER_SECTION_MAGIC &&
        shared->version == CAPTURE_BROKER_SECTION_VERSION &&
        shared->size == CAPTURE_BROKER_SECTION_SIZE(
            CAPTURE_BROKER_MAX_RECORD_CAPACITY) &&
        shared->record_capacity == CAPTURE_BROKER_MAX_RECORD_CAPACITY &&
        shared->capture_id_high == session->capture_id.high &&
        shared->capture_id_low == session->capture_id.low &&
        shared->generation == CaptureBroker_CalculateGeneration(
            session->capture_id.high, session->capture_id.low);
}


static void Capture_SharedPushLocked(
    CAPTURE_SESSION *session,
    const CAPTURE_PACKET_RECORD *record)
{
    CAPTURE_BROKER_SECTION *shared =
        session ? session->section_system_address : NULL;
    if (! Capture_SharedContractValidLocked(session, shared) || ! record)
        return;

    const ULONG writeIndex = session->shared_write_index;
    const ULONG readIndex = shared->read_index;
    if (writeIndex - readIndex >= CAPTURE_BROKER_MAX_RECORD_CAPACITY &&
            shared->dropped_count < (ULONG64)-1) {
        ++shared->dropped_count;
    }
    const ULONG64 sequence = ++session->shared_sequence;
    CAPTURE_PACKET_RECORD *slot =
        &shared->records[writeIndex % CAPTURE_BROKER_MAX_RECORD_CAPACITY];
    CAPTURE_PACKET_RECORD copy = *record;
    copy.sequence = 0;

    slot->sequence = 0;
    KeMemoryBarrier();
    RtlCopyMemory(
        (UCHAR *)slot + sizeof(slot->sequence),
        (const UCHAR *)&copy + sizeof(copy.sequence),
        sizeof(copy) - sizeof(copy.sequence));
    KeMemoryBarrier();
    slot->sequence = sequence;
    KeMemoryBarrier();

    session->shared_write_index = writeIndex + 1;
    shared->write_index = session->shared_write_index;
}


static void Capture_RecordPayloadByFlowInternal(
    UINT64 flowContext,
    const UCHAR *data,
    ULONG dataLength,
    ULONG originalLength,
    UCHAR layer)
{
    if (! flowContext || ! Capture_Initialized)
        return;

    KIRQL irql;
    KeAcquireSpinLock(&Capture_Lock, &irql);

    if (! Capture_Unloading) {
        CAPTURE_FLOW_CONTEXT *flow =
            Capture_FindFlowLocked(flowContext);
        if (flow && ! flow->retiring) {
            CAPTURE_PACKET_RECORD record = flow->template_record;
            record.timestamp = 0;
            record.layer = layer;
            record.original_length = originalLength;
            record.captured_length = dataLength >
                CAPTURE_PACKET_SNAPLEN_MAX ?
                CAPTURE_PACKET_SNAPLEN_MAX : dataLength;
            if (record.captured_length && data)
                RtlCopyMemory(
                    record.data, data, record.captured_length);

            LARGE_INTEGER timestamp;
            KeQuerySystemTime(&timestamp);
            record.timestamp = timestamp.QuadPart;

            PLIST_ENTRY entry = Capture_Sessions.Flink;
            while (entry != &Capture_Sessions) {
                CAPTURE_SESSION *session = CONTAINING_RECORD(
                    entry, CAPTURE_SESSION, link);
                if (session->payload_enabled &&
                        Capture_IdEquals(
                            &session->capture_id, &flow->capture_id) &&
                        CaptureFilter_Matches(
                            &session->target, &flow->identity)) {
                    if (layer == CAPTURE_PACKET_LAYER_STREAM &&
                            session->stream_queue) {
                        CaptureStreamQueue_Push(
                            session->stream_queue,
                            (const CAPTURE_STREAM_RECORD *)&record);
                    }
                    else if (layer != CAPTURE_PACKET_LAYER_STREAM) {
                        if (layer == CAPTURE_PACKET_LAYER_TRANSPORT &&
                                session->section_system_address) {
                            Capture_SharedPushLocked(session, &record);
                        }
                        if (session->packet_queue) {
                            CapturePacketQueue_Push(
                                session->packet_queue, &record);
                        }
                    }
                }
                entry = entry->Flink;
            }
        }
    }

    KeReleaseSpinLock(&Capture_Lock, irql);
}


void Capture_RecordPayloadByFlow(
    UINT64 flowContext,
    const UCHAR *data,
    ULONG dataLength,
    ULONG originalLength,
    UCHAR layer)
{
    Capture_RecordPayloadByFlowInternal(
        flowContext, data, dataLength, originalLength, layer);
}
