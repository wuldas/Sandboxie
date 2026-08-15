/*
 * Copyright 2021-2024 David Xanatos, xanasoft.com
 *
 * This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//---------------------------------------------------------------------------
// Windows Filtering Platform
//---------------------------------------------------------------------------


#include "wfp.h"
#include "process.h"
#include "conf.h"
#include "session.h"
#include "api_flags.h"
#include "common/map.h"
#include "common/netfw.h"
#include "common/my_version.h"
#define NO_IP_DEFS
#include "common/my_wsa.h"
#include "util.h"
#include "capture.h"
#include "capture_network.h"
#include "capture_https.h"


extern DEVICE_OBJECT *Api_DeviceObject;

#ifdef _M_ARM64
#define NDIS630 1 // windows 8.1
#else
#define NDIS61 1 // windows 7
#endif


#include "Ntifs.h"
#include <ntddk.h>				// Windows Driver Development Kit
#include <ntimage.h>

#pragma warning(push)
#pragma warning(disable: 4201)	// Disable "Nameless struct/union" compiler warning for fwpsk.h only!
#include <fwpsk.h>				// Functions and enumerated types used to implement callouts in kernel mode
#pragma warning(pop)			// Re-enable "Nameless struct/union" compiler warning

#include <guiddef.h>			// Used to define GUID's
#include <initguid.h>			// Used to define GUID's
#include <fwpmk.h>				// Functions used for managing IKE and AuthIP main mode (MM) policy and security associations
#include <fwpvi.h>				// Mappings of OS specific function versions (i.e. fn's that end in 0 or 1)
#include "../svc/capturebrokerwire.h"
#include "devguid.h"


//---------------------------------------------------------------------------
// Defines
//---------------------------------------------------------------------------

#define WFP_SUBLAYER_NAME L"SbieSublayer"
#define WFP_SUBLAYER_DESCRIPTION L"A sublayer used by sandboxie to implement internet restrictions"

DEFINE_GUID(WFP_SUBLAYER_GUID,	// e1d364e9-cd84-4a48-aba4-608ce83e31ee
	0xe1d364e9, 0xcd84, 0x4a48, 0xab, 0xa4, 0x60, 0x8c, 0xe8, 0x3e, 0x31, 0xee);
DEFINE_GUID(WFP_PROVIDER_GUID,	// e1d364e9-cd84-4a48-aba4-608ce83e31ef
	0xe1d364e9, 0xcd84, 0x4a48, 0xab, 0xa4, 0x60, 0x8c, 0xe8, 0x3e, 0x31, 0xef);

#define WFP_CALLOUT_NAME		L"SbieCallout"
#define WFP_CALLOUT_DESCRIPTION	L"A callout used by sandboxie to implement internet restrictions"

//DEFINE_GUID(WPF_CALLOUT_GUID_V4,	// 0bf56435-71e4-4de7-bd0b-1af0b4cbb8f4
//	0x0bf56435, 0x71e4, 0x4de7, 0xbd, 0x0b, 0x1a, 0xf0, 0xb4, 0xcb, 0xb8, 0xf4);
//DEFINE_GUID(WPF_CALLOUT_GUID_V6,	// 0bf56435-71e4-4de7-bd0b-1af0b4cbb9f5
//	0x0bf56435, 0x71e4, 0x4de7, 0xbd, 0x0b, 0x1a, 0xf0, 0xb4, 0xcb, 0xb9, 0xf5);
DEFINE_GUID(WPF_SEND_CALLOUT_GUID_V4,	// 0bf56435-71e4-4de7-bd0b-1af0b4cbb8f6
	0x0bf56435, 0x71e4, 0x4de7, 0xbd, 0x0b, 0x1a, 0xf0, 0xb4, 0xcb, 0xb8, 0xf6);
DEFINE_GUID(WPF_SEND_CALLOUT_GUID_V6,	// 0bf56435-71e4-4de7-bd0b-1af0b4cbb9f7
	0x0bf56435, 0x71e4, 0x4de7, 0xbd, 0x0b, 0x1a, 0xf0, 0xb4, 0xcb, 0xb9, 0xf7);
DEFINE_GUID(WPF_RECV_CALLOUT_GUID_V4,	// 0bf56435-71e4-4de7-bd0b-1af0b4cbb8f8
	0x0bf56435, 0x71e4, 0x4de7, 0xbd, 0x0b, 0x1a, 0xf0, 0xb4, 0xcb, 0xb8, 0xf8);
DEFINE_GUID(WPF_RECV_CALLOUT_GUID_V6,	// 0bf56435-71e4-4de7-bd0b-1af0b4cbb9f9
	0x0bf56435, 0x71e4, 0x4de7, 0xbd, 0x0b, 0x1a, 0xf0, 0xb4, 0xcb, 0xb9, 0xf9);
DEFINE_GUID(WFP_FLOW_CALLOUT_GUID_V4,
    0x4e0d6435, 0x91a2, 0x4d7e, 0x8b, 0x01, 0x1a, 0xf0, 0xb4, 0xcb, 0x10, 0x01);
DEFINE_GUID(WFP_FLOW_CALLOUT_GUID_V6,
    0x4e0d6435, 0x91a2, 0x4d7e, 0x8b, 0x01, 0x1a, 0xf0, 0xb4, 0xcb, 0x10, 0x02);
DEFINE_GUID(WFP_TRANSPORT_OUT_CALLOUT_GUID_V4,
    0x4e0d6435, 0x91a2, 0x4d7e, 0x8b, 0x01, 0x1a, 0xf0, 0xb4, 0xcb, 0x10, 0x03);
DEFINE_GUID(WFP_TRANSPORT_OUT_CALLOUT_GUID_V6,
    0x4e0d6435, 0x91a2, 0x4d7e, 0x8b, 0x01, 0x1a, 0xf0, 0xb4, 0xcb, 0x10, 0x04);
DEFINE_GUID(WFP_TRANSPORT_IN_CALLOUT_GUID_V4,
    0x4e0d6435, 0x91a2, 0x4d7e, 0x8b, 0x01, 0x1a, 0xf0, 0xb4, 0xcb, 0x10, 0x05);
DEFINE_GUID(WFP_TRANSPORT_IN_CALLOUT_GUID_V6,
    0x4e0d6435, 0x91a2, 0x4d7e, 0x8b, 0x01, 0x1a, 0xf0, 0xb4, 0xcb, 0x10, 0x06);
DEFINE_GUID(WFP_STREAM_CALLOUT_GUID_V4,
    0x4e0d6435, 0x91a2, 0x4d7e, 0x8b, 0x01, 0x1a, 0xf0, 0xb4, 0xcb, 0x10, 0x07);
DEFINE_GUID(WFP_STREAM_CALLOUT_GUID_V6,
    0x4e0d6435, 0x91a2, 0x4d7e, 0x8b, 0x01, 0x1a, 0xf0, 0xb4, 0xcb, 0x10, 0x08);
DEFINE_GUID(WFP_DATAGRAM_CALLOUT_GUID_V4,
    0x4e0d6435, 0x91a2, 0x4d7e, 0x8b, 0x01, 0x1a, 0xf0, 0xb4, 0xcb, 0x10, 0x09);
DEFINE_GUID(WFP_DATAGRAM_CALLOUT_GUID_V6,
    0x4e0d6435, 0x91a2, 0x4d7e, 0x8b, 0x01, 0x1a, 0xf0, 0xb4, 0xcb, 0x10, 0x0a);
DEFINE_GUID(WFP_REDIRECT_CALLOUT_GUID_V4,	// 0bf56435-71e4-4de7-bd0b-1af0b4cbb8fa
	0x0bf56435, 0x71e4, 0x4de7, 0xbd, 0x0b, 0x1a, 0xf0, 0xb4, 0xcb, 0xb8, 0xfa);
DEFINE_GUID(WFP_REDIRECT_CALLOUT_GUID_V6,	// 0bf56435-71e4-4de7-bd0b-1af0b4cbb9fb
	0x0bf56435, 0x71e4, 0x4de7, 0xbd, 0x0b, 0x1a, 0xf0, 0xb4, 0xcb, 0xb9, 0xfb);

#define WFP_FILTER_NAME L"SbieFilter"
#define WFP_FILTER_DESCRIPTION L"A filter that uses by sandboxie to implement internet restrictions"


//---------------------------------------------------------------------------
// Structures and Types
//---------------------------------------------------------------------------


typedef struct _WFP_PROCESS {

	HANDLE ProcessId;
	BOOLEAN LogTraffic;
	BOOLEAN BlockInternet;
	BOOLEAN BlockLoopback;
	BOOLEAN CaptureEligible;
	ULONG SessionId;
	ULONG64 ProcessCreateTime;
	WCHAR BoxName[BOXNAME_COUNT];
	WCHAR SidString[96];
	LIST NetFwRules;

} WFP_PROCESS;


//---------------------------------------------------------------------------
// Functions
//---------------------------------------------------------------------------

BOOLEAN WFP_Install_Callbacks(void);

void WFP_Uninstall_Callbacks(void);

NTSTATUS WFP_RegisterSubLayer();

NTSTATUS WFP_RegisterCallout(const GUID* calloutKey, const GUID* applicableLayer, UINT32* callout_id, UINT64* filter_id);

static NTSTATUS WFP_RegisterCalloutEx(
    const GUID *calloutKey,
    const GUID *applicableLayer,
    UINT32 *calloutId,
    UINT64 *filterId,
    FWPS_CALLOUT_CLASSIFY_FN1 classifyFn,
    FWP_ACTION_TYPE actionType);

static void NTAPI WFP_flow_classify(
    const FWPS_INCOMING_VALUES *inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
    void *layerData,
    const void *classifyContext,
    const FWPS_FILTER1 *filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT *classifyOut);

static void NTAPI WFP_transport_classify(
    const FWPS_INCOMING_VALUES *inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
    void *layerData,
    const void *classifyContext,
    const FWPS_FILTER1 *filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT *classifyOut);

static void NTAPI WFP_stream_classify(
    const FWPS_INCOMING_VALUES *inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
    void *layerData,
    const void *classifyContext,
    const FWPS_FILTER1 *filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT *classifyOut);

static void NTAPI WFP_datagram_classify(
    const FWPS_INCOMING_VALUES *inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
    void *layerData,
    const void *classifyContext,
    const FWPS_FILTER1 *filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT *classifyOut);

static void NTAPI WFP_https_redirect_classify(
    const FWPS_INCOMING_VALUES *inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
    void *layerData,
    const void *classifyContext,
    const FWPS_FILTER1 *filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT *classifyOut);

const WCHAR* Process_MatchImageAndGetValue(BOX* box, const WCHAR* value, const WCHAR* ImageName, ULONG* pLevel);

ULONG Process_GetTraceFlag(PROCESS *proc, const WCHAR *setting);

void WFP_FreeRules(LIST* NetFwRules);

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, WFP_Init)
#endif // ALLOC_PRAGMA

void WFP_state_changed(
	_Inout_ void* context,
	_In_ FWPM_SERVICE_STATE newState);

/*	The "classifyFn" callout function for this Callout.
For more information about a Callout's classifyFn, see:
http://msdn.microsoft.com/en-us/library/windows/hardware/ff544893(v=vs.85).aspx
*/
void WFP_classify(
	const FWPS_INCOMING_VALUES * inFixedValues,
	const FWPS_INCOMING_METADATA_VALUES * inMetaValues,
	void * layerData,
	const void * classifyContext,
	const FWPS_FILTER1 * filter, // FWPS_FILTER1 is the latest supported by windows 7
	UINT64 flowContext,
	FWPS_CLASSIFY_OUT * classifyOut);

/*	The "notifyFn" callout function for this Callout.
This function manages setting up global resources and a worker thread
managed by this Callout. For more information about a Callout's notifyFn, see:
http://msdn.microsoft.com/en-us/library/windows/hardware/ff568804(v=vs.85).aspx
*/
NTSTATUS WFP_notify(
	FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	const GUID * filterKey,
	const FWPS_FILTER1* filter); // FWPS_FILTER1 is the latest supported by windows 7

/*	The "flowDeleteFn" callout function for this Callout.
This function doesn't do anything.
http://msdn.microsoft.com/en-us/library/windows/hardware/ff550025(v=vs.85).aspx
*/
NTSTATUS WFP_flow_delete(
	UINT16 layerId,
	UINT32 calloutId,
	UINT64 flowContext);

void GetNetwork5TupleIndexesForLayer(
	_In_ UINT16 layerId,
	_Out_ UINT* localAddressIndex,
	_Out_ UINT* remoteAddressIndex,
	_Out_ UINT* localPortIndex,
	_Out_ UINT* remotePortIndex,
	_Out_ UINT* protocolIndex,
	_Out_ UINT* flagsIndex);


//---------------------------------------------------------------------------
// Variables
//---------------------------------------------------------------------------


BOOLEAN WFP_Enabled = FALSE;
static BOOLEAN WFP_PayloadRegistered = FALSE;
static PERESOURCE WFP_InitLock = NULL;

static HANDLE WFP_state_handle = NULL;

// Global handle to the WFP Base Filter Engine
static HANDLE WFP_engine_handle = NULL;

//static UINT32 WFP_callout_id_v4 = 0;
//static UINT32 WFP_callout_id_v6 = 0;
static UINT32 WFP_send_callout_id_v4 = 0;
static UINT32 WFP_send_callout_id_v6 = 0;
static UINT32 WFP_recv_callout_id_v4 = 0;
static UINT32 WFP_recv_callout_id_v6 = 0;
static UINT32 WFP_flow_callout_id_v4 = 0;
static UINT32 WFP_flow_callout_id_v6 = 0;
static UINT32 WFP_transport_out_callout_id_v4 = 0;
static UINT32 WFP_transport_out_callout_id_v6 = 0;
static UINT32 WFP_transport_in_callout_id_v4 = 0;
static UINT32 WFP_transport_in_callout_id_v6 = 0;
static UINT32 WFP_stream_callout_id_v4 = 0;
static UINT32 WFP_stream_callout_id_v6 = 0;
static UINT32 WFP_datagram_callout_id_v4 = 0;
static UINT32 WFP_datagram_callout_id_v6 = 0;
static UINT32 WFP_redirect_callout_id_v4 = 0;
static UINT32 WFP_redirect_callout_id_v6 = 0;

//static UINT64 WFP_filter_id_v4 = 0;
//static UINT64 WFP_filter_id_v6 = 0;
static UINT64 WFP_send_filter_id_v4 = 0;
static UINT64 WFP_send_filter_id_v6 = 0;
static UINT64 WFP_recv_filter_id_v4 = 0;
static UINT64 WFP_recv_filter_id_v6 = 0;
static UINT64 WFP_flow_filter_id_v4 = 0;
static UINT64 WFP_flow_filter_id_v6 = 0;
static UINT64 WFP_transport_out_filter_id_v4 = 0;
static UINT64 WFP_transport_out_filter_id_v6 = 0;
static UINT64 WFP_transport_in_filter_id_v4 = 0;
static UINT64 WFP_transport_in_filter_id_v6 = 0;
static UINT64 WFP_stream_filter_id_v4 = 0;
static UINT64 WFP_stream_filter_id_v6 = 0;
static UINT64 WFP_datagram_filter_id_v4 = 0;
static UINT64 WFP_datagram_filter_id_v6 = 0;
static UINT64 WFP_redirect_filter_id_v4 = 0;
static UINT64 WFP_redirect_filter_id_v6 = 0;

static BOOLEAN WPF_MapInitialized = FALSE;
static map_base_t WFP_Processes;
static KSPIN_LOCK WFP_MapLock;


static void WFP_UnregisterCalloutId(UINT32 *calloutId)
{
    if (calloutId && *calloutId) {
        FwpsCalloutUnregisterById(*calloutId);
        *calloutId = 0;
    }
}


static BOOLEAN WFP_PayloadConfigEnabled(void)
{
#if CAPTURE_PACKET_CAPTURE_RELEASE_GATE
    return Conf_Get_Boolean(NULL, L"NetworkEnablePacketCapture", 0, FALSE);
#else
    return FALSE;
#endif
}


BOOLEAN WFP_IsPayloadInspectionEnabled(void)
{
    return WFP_PayloadRegistered;
}


typedef NTSTATUS (NTAPI *WFP_PFN_REDIRECT_HANDLE_CREATE)(
    const GUID *providerGuid, UINT32 flags, HANDLE *redirectHandle);
typedef void (NTAPI *WFP_PFN_REDIRECT_HANDLE_DESTROY)(HANDLE redirectHandle);
typedef FWPS_CONNECTION_REDIRECT_STATE (NTAPI *WFP_PFN_QUERY_REDIRECT_STATE)(
    HANDLE redirectRecords, HANDLE redirectHandle, void **redirectContext);

static WFP_PFN_REDIRECT_HANDLE_CREATE WFP_pRedirectHandleCreate = NULL;
static WFP_PFN_REDIRECT_HANDLE_DESTROY WFP_pRedirectHandleDestroy = NULL;
static WFP_PFN_QUERY_REDIRECT_STATE WFP_pQueryRedirectState = NULL;
static HANDLE WFP_redirect_handle = NULL;
static BOOLEAN WFP_RedirectRegistered = FALSE;


BOOLEAN WFP_IsHttpsRedirectAvailable(void)
{
    return WFP_RedirectRegistered && WFP_redirect_handle != NULL;
}


static BOOLEAN WFP_NameEquals(const char *left, const char *right)
{
    if (! left || ! right)
        return FALSE;
    while (*left || *right) {
        char a = *left++;
        char b = *right++;
        if (a >= 'A' && a <= 'Z')
            a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z')
            b = (char)(b - 'A' + 'a');
        if (a != b)
            return FALSE;
    }
    return TRUE;
}


static PVOID WFP_FindExport(PVOID imageBase, const char *name)
{
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_DATA_DIRECTORY *dir;
    IMAGE_EXPORT_DIRECTORY *exports;
    ULONG *names;
    ULONG *funcs;
    USHORT *ords;
    ULONG index;

    if (! imageBase || ! name)
        return NULL;
    dos = (IMAGE_DOS_HEADER *)imageBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;
    nt = (IMAGE_NT_HEADERS *)((UCHAR *)imageBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return NULL;
    dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (! dir->VirtualAddress || ! dir->Size)
        return NULL;
    exports = (IMAGE_EXPORT_DIRECTORY *)((UCHAR *)imageBase + dir->VirtualAddress);
    names = (ULONG *)((UCHAR *)imageBase + exports->AddressOfNames);
    funcs = (ULONG *)((UCHAR *)imageBase + exports->AddressOfFunctions);
    ords = (USHORT *)((UCHAR *)imageBase + exports->AddressOfNameOrdinals);
    for (index = 0; index < exports->NumberOfNames; ++index) {
        const char *exportName = (const char *)imageBase + names[index];
        if (WFP_NameEquals(exportName, name))
            return (UCHAR *)imageBase + funcs[ords[index]];
    }
    return NULL;
}


static PVOID WFP_FindFwpkclntBase(void)
{
    ULONG needed = 0;
    ULONG allocSize;
    SYSTEM_MODULE_INFORMATION *info;
    ULONG index;
    PVOID base = NULL;

    ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &needed);
    if (needed < PAGE_SIZE)
        needed = PAGE_SIZE;
    allocSize = needed + PAGE_SIZE;
    info = (SYSTEM_MODULE_INFORMATION *)ExAllocatePoolWithTag(
        PagedPool, allocSize, tzuk);
    if (! info)
        return NULL;
    if (NT_SUCCESS(ZwQuerySystemInformation(
            SystemModuleInformation, info, allocSize, &needed))) {
        for (index = 0; index < info->ModuleCount; ++index) {
            const char *path = (const char *)info->ModuleInfo[index].Path;
            const char *name = path + info->ModuleInfo[index].NameOffset;
            if (WFP_NameEquals(name, "fwpkclnt.sys")) {
                base = (PVOID)info->ModuleInfo[index].ImageBaseAddress;
                break;
            }
        }
    }
    ExFreePoolWithTag(info, tzuk);
    return base;
}


static PVOID WFP_ResolveRedirectRoutine(const WCHAR *wideName, const char *ansiName)
{
    UNICODE_STRING uni;
    PVOID routine;

    RtlInitUnicodeString(&uni, wideName);
    routine = MmGetSystemRoutineAddress(&uni);
    if (routine)
        return routine;
    return WFP_FindExport(WFP_FindFwpkclntBase(), ansiName);
}


static BOOLEAN WFP_ResolveRedirectApis(void)
{
    if (WFP_pRedirectHandleCreate &&
            WFP_pRedirectHandleDestroy &&
            WFP_pQueryRedirectState) {
        return TRUE;
    }

    WFP_pRedirectHandleCreate = (WFP_PFN_REDIRECT_HANDLE_CREATE)
        WFP_ResolveRedirectRoutine(
            L"FwpsRedirectHandleCreate0", "FwpsRedirectHandleCreate0");
    WFP_pRedirectHandleDestroy = (WFP_PFN_REDIRECT_HANDLE_DESTROY)
        WFP_ResolveRedirectRoutine(
            L"FwpsRedirectHandleDestroy0", "FwpsRedirectHandleDestroy0");
    WFP_pQueryRedirectState = (WFP_PFN_QUERY_REDIRECT_STATE)
        WFP_ResolveRedirectRoutine(
            L"FwpsQueryConnectionRedirectState0",
            "FwpsQueryConnectionRedirectState0");
    return WFP_pRedirectHandleCreate &&
        WFP_pRedirectHandleDestroy &&
        WFP_pQueryRedirectState;
}


//---------------------------------------------------------------------------
// WFP_Alloc
//---------------------------------------------------------------------------


_FX VOID* WFP_Alloc(void* pool, size_t size)
{
	return ExAllocatePoolWithTag(NonPagedPool, size, tzuk);
}


//---------------------------------------------------------------------------
// WFP_Free
//---------------------------------------------------------------------------


_FX VOID WFP_Free(void* pool, void* ptr)
{
	ExFreePoolWithTag(ptr, tzuk);
}


//---------------------------------------------------------------------------
// WFP_Init
//---------------------------------------------------------------------------


_FX BOOLEAN WFP_Init(void)
{
	map_init(&WFP_Processes, NULL);
	WFP_Processes.func_malloc = &WFP_Alloc;
	WFP_Processes.func_free = &WFP_Free;

	KeInitializeSpinLock(&WFP_MapLock);

	WPF_MapInitialized = TRUE;

	if (!Conf_Get_Boolean(NULL, L"NetworkEnableWFP", 0, FALSE))
		return TRUE;

	return WFP_Load();
}


//---------------------------------------------------------------------------
// WFP_Load
//---------------------------------------------------------------------------


_FX BOOLEAN WFP_Load(void)
{
	if (WFP_Enabled)
		return TRUE;

	WFP_Enabled = TRUE;

	map_resize(&WFP_Processes, 128); // prepare some buckets for better performance

	DbgPrint("Sbie WFP enabled\r\n");

	if (!Mem_GetLockResource(&WFP_InitLock, TRUE))
		return FALSE;

	NTSTATUS status = FwpmBfeStateSubscribeChanges((void*)Api_DeviceObject, WFP_state_changed, NULL, &WFP_state_handle);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Sbie WFP failed to install state change callback\r\n");
		Mem_FreeLockResource(&WFP_InitLock);
		WFP_InitLock = NULL;
		return FALSE;
	}

	if (FwpmBfeStateGet() == FWPM_SERVICE_RUNNING) {

		KeEnterCriticalRegion();

		ExAcquireResourceSharedLite(WFP_InitLock, TRUE);

		WFP_Install_Callbacks();

		ExReleaseResourceLite(WFP_InitLock);

		KeLeaveCriticalRegion();
	}
	else
		DbgPrint("Sbie WFP is not ready\r\n");

	return TRUE;
}


//---------------------------------------------------------------------------
// WFP_IsReady
//---------------------------------------------------------------------------


_FX BOOLEAN WFP_IsReady(void)
{
	return WFP_Enabled && WFP_engine_handle != NULL;
}


//---------------------------------------------------------------------------
// WFP_Unload
//---------------------------------------------------------------------------


_FX void WFP_Unload(void)
{
	WFP_Enabled = FALSE;

	if (WFP_state_handle != NULL) {

		FwpmBfeStateUnsubscribeChanges(WFP_state_handle);
		WFP_state_handle = NULL;
	}

	if (WFP_InitLock) {

		KeEnterCriticalRegion();

		ExAcquireResourceSharedLite(WFP_InitLock, TRUE);

		WFP_Uninstall_Callbacks();

		ExReleaseResourceLite(WFP_InitLock);

		KeLeaveCriticalRegion();

		Mem_FreeLockResource(&WFP_InitLock);
		WFP_InitLock = NULL;
	}

	if (WPF_MapInitialized) {

		KIRQL irql; 

#ifdef _WIN64
		irql = KeAcquireSpinLockRaiseToDpc(&WFP_MapLock);
#else
		KeAcquireSpinLock(&WFP_MapLock, &irql);
#endif

		map_iter_t iter = map_iter();
		while (map_next(&WFP_Processes, &iter)) {
			WFP_PROCESS* wfp_proc = iter.value;
			
			WFP_FreeRules(&wfp_proc->NetFwRules);
			WFP_Free(NULL, wfp_proc);
		}

		map_clear(&WFP_Processes);

		KeReleaseSpinLock(&WFP_MapLock, irql);
	}
}


//---------------------------------------------------------------------------
// WFP_state_changed
//---------------------------------------------------------------------------


_FX void WFP_state_changed(_Inout_ void* context, _In_ FWPM_SERVICE_STATE newState)
{
	KeEnterCriticalRegion();

	ExAcquireResourceSharedLite(WFP_InitLock, TRUE);

	if (newState == FWPM_SERVICE_STOP_PENDING)
		WFP_Uninstall_Callbacks();
	else if (newState == FWPM_SERVICE_RUNNING)
		WFP_Install_Callbacks();

	ExReleaseResourceLite(WFP_InitLock);

	KeLeaveCriticalRegion();
}


//---------------------------------------------------------------------------
// WFP_Install_Callbacks
//---------------------------------------------------------------------------


_FX BOOLEAN WFP_Install_Callbacks(void)
{
	if (WFP_engine_handle != NULL)
		return TRUE; // already initialized

    WFP_PayloadRegistered = FALSE;
    WFP_RedirectRegistered = FALSE;

	NTSTATUS status = STATUS_SUCCESS;
	DWORD stage = 0;

	FWPM_SESSION wdf_session = { 0 };
	BOOLEAN in_transaction = FALSE;
	BOOLEAN callout_registered = FALSE;


	// Begin a transaction to the FilterEngine. You must register objects (filter, callouts, sublayers)
	//to the filter engine in the context of a 'transaction'
	wdf_session.flags = FWPM_SESSION_FLAG_DYNAMIC;	// <-- Automatically destroys all filters and removes all callouts after this wdf_session ends
	status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &wdf_session, &WFP_engine_handle);
	stage = 0x10; if (!NT_SUCCESS(status)) goto Exit;
	status = FwpmTransactionBegin(WFP_engine_handle, 0);
	stage = 0x20; if (!NT_SUCCESS(status)) goto Exit;
	in_transaction = TRUE;

	// Register a new sublayer to the filter engine
	status = WFP_RegisterSubLayer();
	stage = 0x30; if (!NT_SUCCESS(status)) goto Exit;

	//status = WFP_RegisterCallout(&WPF_CALLOUT_GUID_V4, &FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4, &WFP_callout_id_v4, &WFP_filter_id_v4);
	//if (!NT_SUCCESS(status)) goto Exit;
	//status = WFP_RegisterCallout(&WPF_CALLOUT_GUID_V6, &FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6, &WFP_callout_id_v6, &WFP_filter_id_v6);
	//if (!NT_SUCCESS(status)) goto Exit;
	status = WFP_RegisterCallout(&WPF_SEND_CALLOUT_GUID_V4, &FWPM_LAYER_ALE_AUTH_CONNECT_V4, &WFP_send_callout_id_v4, &WFP_send_filter_id_v4);
	stage = 0x41; if (!NT_SUCCESS(status)) goto Exit;
	callout_registered = TRUE;
	status = WFP_RegisterCallout(&WPF_SEND_CALLOUT_GUID_V6, &FWPM_LAYER_ALE_AUTH_CONNECT_V6, &WFP_send_callout_id_v6, &WFP_send_filter_id_v6);
	stage = 0x42; if (!NT_SUCCESS(status)) goto Exit;
	status = WFP_RegisterCallout(&WPF_RECV_CALLOUT_GUID_V4, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, &WFP_recv_callout_id_v4, &WFP_recv_filter_id_v4);
	stage = 0x43; if (!NT_SUCCESS(status)) goto Exit;
	status = WFP_RegisterCallout(&WPF_RECV_CALLOUT_GUID_V6, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, &WFP_recv_callout_id_v6, &WFP_recv_filter_id_v6);
	stage = 0x44; if (!NT_SUCCESS(status)) goto Exit;
	if (WFP_PayloadConfigEnabled()) {
	status = WFP_RegisterCalloutEx(
		&WFP_FLOW_CALLOUT_GUID_V4,
		&FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
		&WFP_flow_callout_id_v4,
		&WFP_flow_filter_id_v4,
		WFP_flow_classify,
		FWP_ACTION_CALLOUT_INSPECTION);
	stage = 0x51; if (!NT_SUCCESS(status)) goto Exit;
	status = WFP_RegisterCalloutEx(
		&WFP_FLOW_CALLOUT_GUID_V6,
		&FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,
		&WFP_flow_callout_id_v6,
		&WFP_flow_filter_id_v6,
		WFP_flow_classify,
		FWP_ACTION_CALLOUT_INSPECTION);
	stage = 0x52; if (!NT_SUCCESS(status)) goto Exit;
	status = WFP_RegisterCalloutEx(
		&WFP_TRANSPORT_OUT_CALLOUT_GUID_V4,
		&FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
		&WFP_transport_out_callout_id_v4,
		&WFP_transport_out_filter_id_v4,
		WFP_transport_classify,
		FWP_ACTION_CALLOUT_INSPECTION);
	stage = 0x53; if (!NT_SUCCESS(status)) goto Exit;
	status = WFP_RegisterCalloutEx(
		&WFP_TRANSPORT_OUT_CALLOUT_GUID_V6,
		&FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
		&WFP_transport_out_callout_id_v6,
		&WFP_transport_out_filter_id_v6,
		WFP_transport_classify,
		FWP_ACTION_CALLOUT_INSPECTION);
	stage = 0x54; if (!NT_SUCCESS(status)) goto Exit;
	status = WFP_RegisterCalloutEx(
		&WFP_TRANSPORT_IN_CALLOUT_GUID_V4,
		&FWPM_LAYER_INBOUND_TRANSPORT_V4,
		&WFP_transport_in_callout_id_v4,
		&WFP_transport_in_filter_id_v4,
		WFP_transport_classify,
		FWP_ACTION_CALLOUT_INSPECTION);
	stage = 0x55; if (!NT_SUCCESS(status)) goto Exit;
	status = WFP_RegisterCalloutEx(
		&WFP_TRANSPORT_IN_CALLOUT_GUID_V6,
		&FWPM_LAYER_INBOUND_TRANSPORT_V6,
		&WFP_transport_in_callout_id_v6,
		&WFP_transport_in_filter_id_v6,
		WFP_transport_classify,
		FWP_ACTION_CALLOUT_INSPECTION);
	stage = 0x56; if (!NT_SUCCESS(status)) goto Exit;
	status = WFP_RegisterCalloutEx(
		&WFP_STREAM_CALLOUT_GUID_V4,
		&FWPM_LAYER_STREAM_V4,
		&WFP_stream_callout_id_v4,
		&WFP_stream_filter_id_v4,
		WFP_stream_classify,
		FWP_ACTION_CALLOUT_INSPECTION);
	stage = 0x57; if (!NT_SUCCESS(status)) goto Exit;
	status = WFP_RegisterCalloutEx(
		&WFP_STREAM_CALLOUT_GUID_V6,
		&FWPM_LAYER_STREAM_V6,
		&WFP_stream_callout_id_v6,
		&WFP_stream_filter_id_v6,
		WFP_stream_classify,
		FWP_ACTION_CALLOUT_INSPECTION);
	stage = 0x58; if (!NT_SUCCESS(status)) goto Exit;
	status = WFP_RegisterCalloutEx(
		&WFP_DATAGRAM_CALLOUT_GUID_V4,
		&FWPM_LAYER_DATAGRAM_DATA_V4,
		&WFP_datagram_callout_id_v4,
		&WFP_datagram_filter_id_v4,
		WFP_datagram_classify,
		FWP_ACTION_CALLOUT_INSPECTION);
	stage = 0x59; if (!NT_SUCCESS(status)) goto Exit;
	status = WFP_RegisterCalloutEx(
		&WFP_DATAGRAM_CALLOUT_GUID_V6,
		&FWPM_LAYER_DATAGRAM_DATA_V6,
		&WFP_datagram_callout_id_v6,
		&WFP_datagram_filter_id_v6,
		WFP_datagram_classify,
		FWP_ACTION_CALLOUT_INSPECTION);
	stage = 0x5a; if (!NT_SUCCESS(status)) goto Exit;
	}

	if (WFP_ResolveRedirectApis()) {
		status = WFP_pRedirectHandleCreate(
			&WFP_PROVIDER_GUID, 0, &WFP_redirect_handle);
		stage = 0x61; if (!NT_SUCCESS(status) || ! WFP_redirect_handle) goto Exit;
		status = WFP_RegisterCalloutEx(
			&WFP_REDIRECT_CALLOUT_GUID_V4,
			&FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
			&WFP_redirect_callout_id_v4,
			&WFP_redirect_filter_id_v4,
			WFP_https_redirect_classify,
			FWP_ACTION_CALLOUT_TERMINATING);
		stage = 0x62; if (!NT_SUCCESS(status)) goto Exit;
		status = WFP_RegisterCalloutEx(
			&WFP_REDIRECT_CALLOUT_GUID_V6,
			&FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
			&WFP_redirect_callout_id_v6,
			&WFP_redirect_filter_id_v6,
			WFP_https_redirect_classify,
			FWP_ACTION_CALLOUT_TERMINATING);
		stage = 0x63; if (!NT_SUCCESS(status)) goto Exit;
		WFP_RedirectRegistered = TRUE;
	}

	// note: we could also setup FWPM_LAYER_ALE_AUTH_LISTEN_V4 but since we block all accepts we don't have to


	// Commit transaction to the Filter Engine
	status = FwpmTransactionCommit(WFP_engine_handle);
	stage = 0x50; if (!NT_SUCCESS(status)) goto Exit;
	in_transaction = FALSE;
    WFP_PayloadRegistered = WFP_PayloadConfigEnabled();

	// Cleanup and handle any errors
Exit:
	if (!NT_SUCCESS(status)) {
		DbgPrint("Sbie WFP initialization failed, stage %02x, status 0x%08x\r\n", stage, status);

		if (in_transaction == TRUE) {
			FwpmTransactionAbort(WFP_engine_handle);
			_Analysis_assume_lock_not_held_(WFP_engine_handle); // Potential leak if "FwpmTransactionAbort" fails
		}
		if (callout_registered) {
			WFP_UnregisterCalloutId(&WFP_send_callout_id_v4);
			WFP_UnregisterCalloutId(&WFP_send_callout_id_v6);
			WFP_UnregisterCalloutId(&WFP_recv_callout_id_v4);
			WFP_UnregisterCalloutId(&WFP_recv_callout_id_v6);
			WFP_UnregisterCalloutId(&WFP_flow_callout_id_v4);
			WFP_UnregisterCalloutId(&WFP_flow_callout_id_v6);
			WFP_UnregisterCalloutId(&WFP_transport_out_callout_id_v4);
			WFP_UnregisterCalloutId(&WFP_transport_out_callout_id_v6);
			WFP_UnregisterCalloutId(&WFP_transport_in_callout_id_v4);
			WFP_UnregisterCalloutId(&WFP_transport_in_callout_id_v6);
			WFP_UnregisterCalloutId(&WFP_stream_callout_id_v4);
			WFP_UnregisterCalloutId(&WFP_stream_callout_id_v6);
			WFP_UnregisterCalloutId(&WFP_datagram_callout_id_v4);
			WFP_UnregisterCalloutId(&WFP_datagram_callout_id_v6);
			WFP_UnregisterCalloutId(&WFP_redirect_callout_id_v4);
			WFP_UnregisterCalloutId(&WFP_redirect_callout_id_v6);
		}
		if (WFP_engine_handle) {
			FwpmEngineClose(WFP_engine_handle);
			WFP_engine_handle = NULL;
		}
        WFP_PayloadRegistered = FALSE;
        WFP_RedirectRegistered = FALSE;
        if (WFP_redirect_handle && WFP_pRedirectHandleDestroy) {
            WFP_pRedirectHandleDestroy(WFP_redirect_handle);
            WFP_redirect_handle = NULL;
        }

		return FALSE;
	}

	DbgPrint("Sbie WFP initialized successfully\r\n");
	return TRUE;
}


//---------------------------------------------------------------------------
// WFP_Uninstall_Callbacks
//---------------------------------------------------------------------------


_FX void WFP_Uninstall_Callbacks(void)
{
    WFP_PayloadRegistered = FALSE;
    WFP_RedirectRegistered = FALSE;
	if (WFP_engine_handle == NULL)
		return; // not initialized

	WFP_UnregisterCalloutId(&WFP_send_callout_id_v4);
	//if (!NT_SUCCESS(status)) DbgPrint("Failed to unregister callout, status: 0x%08x\r\n", status);
	WFP_UnregisterCalloutId(&WFP_send_callout_id_v6);
	//if (!NT_SUCCESS(status)) DbgPrint("Failed to unregister callout, status: 0x%08x\r\n", status);
	WFP_UnregisterCalloutId(&WFP_recv_callout_id_v4);
	//if (!NT_SUCCESS(status)) DbgPrint("Failed to unregister callout, status: 0x%08x\r\n", status);
	WFP_UnregisterCalloutId(&WFP_recv_callout_id_v6);
	WFP_UnregisterCalloutId(&WFP_flow_callout_id_v4);
	WFP_UnregisterCalloutId(&WFP_flow_callout_id_v6);
	WFP_UnregisterCalloutId(&WFP_transport_out_callout_id_v4);
	WFP_UnregisterCalloutId(&WFP_transport_out_callout_id_v6);
	WFP_UnregisterCalloutId(&WFP_transport_in_callout_id_v4);
	WFP_UnregisterCalloutId(&WFP_transport_in_callout_id_v6);
	WFP_UnregisterCalloutId(&WFP_stream_callout_id_v4);
	WFP_UnregisterCalloutId(&WFP_stream_callout_id_v6);
	WFP_UnregisterCalloutId(&WFP_datagram_callout_id_v4);
	WFP_UnregisterCalloutId(&WFP_datagram_callout_id_v6);
	WFP_UnregisterCalloutId(&WFP_redirect_callout_id_v4);
	WFP_UnregisterCalloutId(&WFP_redirect_callout_id_v6);

	if (WFP_redirect_handle && WFP_pRedirectHandleDestroy) {
		WFP_pRedirectHandleDestroy(WFP_redirect_handle);
		WFP_redirect_handle = NULL;
	}

	// Close handle to the WFP Filter Engine
	if (WFP_engine_handle) {
		FwpmEngineClose(WFP_engine_handle);
		WFP_engine_handle = NULL;
	}

	DbgPrint("Sbie WFP uninitialized\r\n");
}


//---------------------------------------------------------------------------
// WFP_RegisterSubLayer
//---------------------------------------------------------------------------


NTSTATUS WFP_RegisterSubLayer()
{
	NTSTATUS status = STATUS_SUCCESS;
	FWPM_PROVIDER provider = { 0 };

	provider.providerKey = WFP_PROVIDER_GUID;
	provider.displayData.name = L"SbieProvider";
	provider.displayData.description = L"Sandboxie WFP provider";
	status = FwpmProviderAdd(WFP_engine_handle, &provider, NULL);
	if (status == STATUS_FWP_ALREADY_EXISTS)
		status = STATUS_SUCCESS;
	if (!NT_SUCCESS(status))
		return status;

	FWPM_SUBLAYER sublayer = { 0 };
	sublayer.subLayerKey = WFP_SUBLAYER_GUID;
	sublayer.displayData.name = WFP_SUBLAYER_NAME;
	sublayer.displayData.description = WFP_SUBLAYER_DESCRIPTION;
	sublayer.flags = 0;
	sublayer.weight = 0x0f;
	status = FwpmSubLayerAdd(WFP_engine_handle, &sublayer, NULL);
	if (!NT_SUCCESS(status)){
		//DbgPrint("Failed to register Sbie sublayer, status 0x%08x\r\n", status);
		goto Exit;
	}

Exit:
	return status;
}


//---------------------------------------------------------------------------
// WFP_RegisterCallout
//---------------------------------------------------------------------------


static NTSTATUS WFP_RegisterCalloutEx(
    const GUID* calloutKey,
    const GUID* applicableLayer,
    UINT32* callout_id,
    UINT64* filter_id,
    FWPS_CALLOUT_CLASSIFY_FN1 classifyFn,
    FWP_ACTION_TYPE actionType)
{
	NTSTATUS status = STATUS_SUCCESS;
	BOOLEAN fwpsRegistered = FALSE;
	
	if (WFP_engine_handle == NULL || ! classifyFn ||
			! callout_id || ! filter_id)
		return STATUS_INVALID_PARAMETER;

	// Register a new Callout with the Filter Engine using the provided callout functions
	FWPS_CALLOUT1 s_callout = { 0 }; // FWPS_CALLOUT1 is the latest supported by windows 7
	s_callout.calloutKey = *calloutKey;
	s_callout.classifyFn = classifyFn;
	s_callout.notifyFn = WFP_notify;
	s_callout.flowDeleteFn = WFP_flow_delete;
	status = FwpsCalloutRegister1((void *)Api_DeviceObject, &s_callout, callout_id); // FwpsCalloutRegister1 is the latest supported by windows 7
	if (!NT_SUCCESS(status))
		goto Exit;
	fwpsRegistered = TRUE;

	// Setup a FWPM_CALLOUT structure to store/track the state associated with the FWPS_CALLOUT
	FWPM_CALLOUT m_callout = { 0 };
	m_callout.displayData.name = WFP_CALLOUT_NAME;
	m_callout.displayData.description = WFP_CALLOUT_DESCRIPTION;
	m_callout.calloutKey = *calloutKey;
	m_callout.applicableLayer = *applicableLayer;
	m_callout.flags = 0;
	status = FwpmCalloutAdd(WFP_engine_handle, &m_callout, NULL, NULL);
	if (!NT_SUCCESS(status)){
		//DbgPrint("Failed to register sbie callout, status 0x%08x\r\n", status);
		goto Exit;
	}

	// Setup a FWPM_FILTER structure
	FWPM_FILTER filter = { 0 };
	filter.displayData.name = WFP_FILTER_NAME;
	filter.displayData.description = WFP_FILTER_DESCRIPTION;
	filter.action.type = actionType;
	filter.subLayerKey = WFP_SUBLAYER_GUID;
	filter.weight.type = FWP_UINT8;
	filter.weight.uint8 = 0xf;		// The weight of this filter within its sublayer
	filter.numFilterConditions = 0;	// If you specify 0, this filter invokes its callout for all traffic in its layer
	filter.layerKey = *applicableLayer;	// This layer must match the layer that ExampleCallout is registered to
	filter.action.calloutKey = *calloutKey;
	status = FwpmFilterAdd(WFP_engine_handle, &filter, NULL, filter_id);
	if (status != STATUS_SUCCESS){
		//DbgPrint("Failed to register Sbie filter, status 0x%08x\r\n", status);
		goto Exit;
	}

Exit:
	if (! NT_SUCCESS(status) && fwpsRegistered) {
		FwpsCalloutUnregisterById(*callout_id);
		*callout_id = 0;
	}
	return status;
}


NTSTATUS WFP_RegisterCallout(
	const GUID* calloutKey,
	const GUID* applicableLayer,
	UINT32* callout_id,
	UINT64* filter_id)
{
	return WFP_RegisterCalloutEx(
		calloutKey,
		applicableLayer,
		callout_id,
		filter_id,
		WFP_classify,
		FWP_ACTION_CALLOUT_TERMINATING);
}


//---------------------------------------------------------------------------
// WFP_FreeRules
//---------------------------------------------------------------------------


void WFP_FreeRules(LIST* NetFwRules)
{
	// clear Firewall Rules
	while (1) {
		NETFW_RULE* rule = List_Head(NetFwRules);
		if (!rule)
			break;
		List_Remove(NetFwRules, rule);
		NetFw_FreeRule(rule);
	}
}


//---------------------------------------------------------------------------
// WFP_LoadRules
//---------------------------------------------------------------------------


BOOLEAN WFP_LoadRules(LIST* NetFwRules, PROCESS* proc)
{
	List_Init(NetFwRules);

    for (ULONG index = 0; ; ++index) {

        const WCHAR *value = Conf_Get(proc->box->name, L"NetworkAccess", index);
        if (! value)
            break;

        ULONG level = -1;
        const WCHAR *found_value = Process_MatchImageAndGetValue(proc->box, value, proc->image_name, &level);
        if (!found_value)
            continue;

        NETFW_RULE* rule = NetFw_AllocRule(NULL, level);
        if (!rule) {
            Log_Msg_Process(MSG_1201, NULL, NULL, proc->box->session_id, proc->pid);
			return FALSE;
        }

		NetFw_ParseRule(rule, found_value);

		NetFw_AddRule(NetFwRules, rule);
    }

	return TRUE;
}


//---------------------------------------------------------------------------
// WFP_InitProcess
//---------------------------------------------------------------------------


BOOLEAN WFP_InitProcess(PROCESS* proc)
{
	if (!WFP_Enabled)
		return TRUE; // nothing to do

	if (WFP_engine_handle == NULL)
	    return FALSE; // WFP was not ready report failure, cancel process creation

	BOOLEAN ok = TRUE;
	KIRQL irql;

	WFP_PROCESS* wfp_proc = WFP_Alloc(NULL, sizeof(WFP_PROCESS));
	if (wfp_proc == NULL) {
		ok = FALSE;
		goto finish;
	}
	memzero(wfp_proc, sizeof(WFP_PROCESS));

	wfp_proc->ProcessId = proc->pid;
	wfp_proc->ProcessCreateTime = proc->create_time;
	if (! proc->bHostInject && proc->box && proc->box->sid) {
		wfp_proc->CaptureEligible = TRUE;
		wfp_proc->SessionId = proc->box->session_id;
		memcpy(wfp_proc->BoxName, proc->box->name, sizeof(wfp_proc->BoxName));
		ULONG sidLength = proc->box->sid_len;
		if (sidLength > sizeof(wfp_proc->SidString))
			sidLength = sizeof(wfp_proc->SidString);
		memcpy(wfp_proc->SidString, proc->box->sid, sidLength);
		wfp_proc->SidString[RTL_NUMBER_OF(wfp_proc->SidString) - 1] = L'\0';
	}

	List_Init(&wfp_proc->NetFwRules);

#ifdef _WIN64
	irql = KeAcquireSpinLockRaiseToDpc(&WFP_MapLock);
#else
	KeAcquireSpinLock(&WFP_MapLock, &irql);
#endif

	if(map_get(&WFP_Processes, wfp_proc->ProcessId) != NULL)
	    ok = FALSE; // that would be a duplicate, should not happen, but in case
	else if (!map_insert(&WFP_Processes, wfp_proc->ProcessId, wfp_proc, 0))
	    ok = FALSE;

	KeReleaseSpinLock(&WFP_MapLock, irql);

finish:
	if(!ok && wfp_proc)
		WFP_Free(NULL, wfp_proc);
	return ok;
}


//---------------------------------------------------------------------------
// WFP_UpdateProcess
//---------------------------------------------------------------------------


BOOLEAN WFP_UpdateProcess(PROCESS* proc)
{
	if (!WFP_Enabled)
		return TRUE; // nothing to do

	BOOLEAN ok = FALSE;
	KIRQL irql;
	WFP_PROCESS* wfp_proc;
	HANDLE processId = proc->pid;
	BOOLEAN LogTraffic = FALSE;
	BOOLEAN BlockInternet = FALSE;
	BOOLEAN BlockLoopback = FALSE;
	LIST NewNetFwRules, OldNetFwRules;
	
	List_Init(&NewNetFwRules);
	List_Init(&OldNetFwRules);

	LogTraffic = Process_GetTraceFlag(proc, L"NetFwTrace") != 0;

	if (!proc->AllowInternetAccess) { // if the process isn't exempted check the config

		BlockInternet = !Process_GetConf_bool(proc, L"AllowNetworkAccess", TRUE);
	}

	if (!BlockInternet) {

		ok = WFP_LoadRules(&NewNetFwRules, proc);

		if (!ok) {
			memcpy(&OldNetFwRules, &NewNetFwRules, sizeof(LIST));
			BlockInternet = TRUE; // on roule failure we lust block everything
			// todo: log error
		}
		
		BlockLoopback = Process_GetConf_bool(proc, L"BlockLocalLoop", FALSE);
	}

#ifdef _WIN64
	irql = KeAcquireSpinLockRaiseToDpc(&WFP_MapLock);
#else
	KeAcquireSpinLock(&WFP_MapLock, &irql);
#endif

	wfp_proc = map_get(&WFP_Processes, processId);
	if (wfp_proc) {

		wfp_proc->LogTraffic = LogTraffic;
		wfp_proc->BlockInternet = BlockInternet;
		wfp_proc->BlockLoopback = BlockLoopback;

		if (ok) {
			memcpy(&OldNetFwRules, &wfp_proc->NetFwRules, sizeof(LIST));
			memcpy(&wfp_proc->NetFwRules, &NewNetFwRules, sizeof(LIST));
		}
		ok = TRUE;
	}
	else {
		if (ok) {
			memcpy(&OldNetFwRules, &NewNetFwRules, sizeof(LIST));
		}
		ok = FALSE;
	}
    
	KeReleaseSpinLock(&WFP_MapLock, irql);

	WFP_FreeRules(&OldNetFwRules);

	return ok;
}


//---------------------------------------------------------------------------
// WFP_DeleteProcess
//---------------------------------------------------------------------------


void WFP_DeleteProcess(PROCESS* proc)
{
	if (!WFP_Enabled)
		return; // nothing to do

	KIRQL irql; 
	WFP_PROCESS* wfp_proc = NULL;
	HANDLE processId = proc->pid;

#ifdef _WIN64
	irql = KeAcquireSpinLockRaiseToDpc(&WFP_MapLock);
#else
	KeAcquireSpinLock(&WFP_MapLock, &irql);
#endif

	map_take(&WFP_Processes, processId, &wfp_proc, 0);
    
	KeReleaseSpinLock(&WFP_MapLock, irql);

	if (wfp_proc)
	{
		WFP_FreeRules(&wfp_proc->NetFwRules);
		WFP_Free(NULL, wfp_proc);
	}
}

//---------------------------------------------------------------------------
// WFP_isLoopback
//---------------------------------------------------------------------------

BOOLEAN WFP_isLoopback(const IP_ADDRESS* ip)
{
	// Check IPv6 ::1
	int allzero = TRUE;
	for (int i = 0; i < 15; i++) {
		if (ip->Data[i] != 0) {
			allzero = FALSE;
			break;
		}
	}
	if (allzero && ip->Data[15] == 1) {
		return TRUE;
	}

	// Check IPv4-mapped IPv6 ::FFFF:127.0.0.0/8.  The address bytes are
	// stored in network order even on little-endian hosts.
	if (ip->Data[0] == 0 && ip->Data[1] == 0 &&
		ip->Data[2] == 0 && ip->Data[3] == 0 &&
		ip->Data[4] == 0 && ip->Data[5] == 0 &&
		ip->Data[6] == 0 && ip->Data[7] == 0 &&
		ip->Data[8] == 0 && ip->Data[9] == 0 &&
		ip->Data[10] == 0xFF && ip->Data[11] == 0xFF &&
		ip->Data[12] == 0x7F)
	{
		return TRUE;
	}

	return FALSE;
}




//---------------------------------------------------------------------------
// WFP_https_redirect_classify
//---------------------------------------------------------------------------


static BOOLEAN WFP_LookupHttpsIdentity(
	HANDLE processId,
	BOOLEAN loopback,
	CAPTURE_FILTER_IDENTITY *identity)
{
	KIRQL irql;
	WFP_PROCESS *wfp_proc;
	BOOLEAN ok = FALSE;

#ifdef _WIN64
	irql = KeAcquireSpinLockRaiseToDpc(&WFP_MapLock);
#else
	KeAcquireSpinLock(&WFP_MapLock, &irql);
#endif
	wfp_proc = map_get(&WFP_Processes, processId);
	if (wfp_proc && wfp_proc->CaptureEligible) {
		memzero(identity, sizeof(*identity));
		identity->process_id = (ULONG)(ULONG_PTR)wfp_proc->ProcessId;
		identity->session_id = wfp_proc->SessionId;
		identity->process_create_time = wfp_proc->ProcessCreateTime;
		identity->loopback = loopback;
		memcpy(identity->box_name, wfp_proc->BoxName, sizeof(identity->box_name));
		memcpy(identity->sid_string, wfp_proc->SidString, sizeof(identity->sid_string));
		ok = TRUE;
	}
	KeReleaseSpinLock(&WFP_MapLock, irql);
	return ok;
}


static void NTAPI WFP_https_redirect_classify(
	const FWPS_INCOMING_VALUES *inFixedValues,
	const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
	void *layerData,
	const void *classifyContext,
	const FWPS_FILTER1 *filter,
	UINT64 flowContext,
	FWPS_CLASSIFY_OUT *classifyOut)
{
	BOOLEAN canWrite;
	BOOLEAN v6;
	BOOLEAN alreadySelf = FALSE;
	UINT localAddrIndex, remoteAddrIndex, localPortIndex;
	UINT remotePortIndex, protocolIndex, flagsIndex;
	UINT32 connectionFlags;
	UCHAR protocol;
	USHORT remotePort;
	CAPTURE_FILTER_IDENTITY identity;
	CAPTURE_HTTPS_FLOW flow;
	USHORT listenPort = 0;
	ULONG64 captureIdHigh = 0;
	ULONG64 captureIdLow = 0;
	ULONG64 generation = 0;
	UINT64 classifyHandle = 0;
	FWPS_CONNECT_REQUEST *request = NULL;
	HTTPS_REDIRECT_CONTEXT *context = NULL;
	NTSTATUS status;

	UNREFERENCED_PARAMETER(layerData);
	UNREFERENCED_PARAMETER(flowContext);

	canWrite = (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) != 0;
	if (! canWrite || ! WFP_IsHttpsRedirectAvailable() ||
			! inFixedValues || ! inMetaValues || ! filter ||
			! classifyContext) {
		classifyOut->actionType = FWP_ACTION_PERMIT;
		return;
	}

	if (WFP_pQueryRedirectState &&
			FWPS_IS_METADATA_FIELD_PRESENT(
				inMetaValues, FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE) &&
			inMetaValues->redirectRecords) {
		FWPS_CONNECTION_REDIRECT_STATE state = WFP_pQueryRedirectState(
			inMetaValues->redirectRecords, WFP_redirect_handle, NULL);
		alreadySelf =
			state == FWPS_CONNECTION_REDIRECTED_BY_SELF ||
			state == FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_SELF;
	}

	GetNetwork5TupleIndexesForLayer(
		inFixedValues->layerId,
		&localAddrIndex, &remoteAddrIndex, &localPortIndex,
		&remotePortIndex, &protocolIndex, &flagsIndex);
	if (remoteAddrIndex == (UINT)-1 || remotePortIndex == (UINT)-1 ||
			protocolIndex == (UINT)-1) {
		classifyOut->actionType = FWP_ACTION_PERMIT;
		return;
	}

	v6 = (filter->filterId == WFP_redirect_filter_id_v6);
	connectionFlags = flagsIndex != (UINT)-1 ?
		inFixedValues->incomingValue[flagsIndex].value.uint32 : 0;
	protocol = inFixedValues->incomingValue[protocolIndex].value.uint8;
	remotePort = inFixedValues->incomingValue[remotePortIndex].value.uint16;

	memzero(&flow, sizeof(flow));
	flow.protocol = protocol;
	flow.address_family = v6 ? CAPTURE_HTTPS_AF_INET6 : CAPTURE_HTTPS_AF_INET;
	flow.remote_port = remotePort;
	flow.already_redirected_by_self = alreadySelf;
	if (v6) {
		const FWP_BYTE_ARRAY16 *remoteArray =
			inFixedValues->incomingValue[remoteAddrIndex].value.byteArray16;
		if (remoteArray)
			memcpy(flow.remote_address, remoteArray->byteArray16, 16);
	}
	else {
		CaptureNetwork_EncodeIpv4(
			flow.remote_address,
			inFixedValues->incomingValue[remoteAddrIndex].value.uint32);
	}

	if (FWPS_IS_METADATA_FIELD_PRESENT(
			inMetaValues, FWPS_METADATA_FIELD_PROCESS_ID) &&
			WFP_LookupHttpsIdentity(
				(HANDLE)inMetaValues->processId,
				(connectionFlags & FWP_CONDITION_FLAG_IS_LOOPBACK) != 0,
				&identity)) {
		if (Capture_LookupHttpsRedirect(
				&identity, &listenPort, &captureIdHigh, &captureIdLow,
				&generation)) {
			flow.identity = &identity;
			flow.listen_port = listenPort;
		}
	}

	if (CaptureHttps_Decide(&flow) == CAPTURE_HTTPS_DECISION_REDIRECT) {
		context = CaptureHttps_CreateContext(
			captureIdHigh, captureIdLow, generation,
			&identity, flow.address_family, remotePort,
			flow.remote_address);
		if (context) {
		status = FwpsAcquireClassifyHandle0(
			(void *)classifyContext, 0, &classifyHandle);
		if (NT_SUCCESS(status)) {
			status = FwpsAcquireWritableLayerDataPointer0(
				classifyHandle,
				filter->filterId,
				0,
				(PVOID *)&request,
				classifyOut);
			if (NT_SUCCESS(status) && request) {
				if (! v6) {
					SOCKADDR_IN *addr =
						(SOCKADDR_IN *)&request->remoteAddressAndPort;
					memzero(addr, sizeof(*addr));
					addr->sin_family = AF_INET;
					addr->sin_port = RtlUshortByteSwap(listenPort);
					addr->sin_addr.S_un.S_addr =
						RtlUlongByteSwap(0x7f000001ul);
				}
				else {
					SOCKADDR_IN6 *addr =
						(SOCKADDR_IN6 *)&request->remoteAddressAndPort;
					memzero(addr, sizeof(*addr));
					addr->sin6_family = AF_INET6;
					addr->sin6_port = RtlUshortByteSwap(listenPort);
					((UCHAR *)&addr->sin6_addr)[15] = 1;
				}
#if (NTDDI_VERSION >= NTDDI_WIN8)
				request->localRedirectHandle = WFP_redirect_handle;
				request->localRedirectContext = context;
				request->localRedirectContextSize = sizeof(*context);
#endif
				FwpsApplyModifiedLayerData0(
					classifyHandle, request,
					FWPS_CLASSIFY_FLAG_REAUTHORIZE_IF_MODIFIED_BY_OTHERS);
				context = NULL;
				classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
			}
			FwpsReleaseClassifyHandle0(classifyHandle);
		}
		}
		if (context)
			CaptureHttps_ReleaseContext(context);
	}

	classifyOut->actionType = FWP_ACTION_PERMIT;
}


//---------------------------------------------------------------------------
// WFP_classify
//---------------------------------------------------------------------------


void WFP_classify(
	const FWPS_INCOMING_VALUES * inFixedValues,
	const FWPS_INCOMING_METADATA_VALUES * inMetaValues,
	void * layerData,
	const void * classifyContext,
	const FWPS_FILTER1 * filter, // FWPS_FILTER1 is the latest supported by windows 7
	UINT64 flowContext,
	FWPS_CLASSIFY_OUT * classifyOut)
{
	// https://docs.microsoft.com/en-us/windows-hardware/drivers/network/metadata-fields-at-each-filtering-layer

	UNREFERENCED_PARAMETER(layerData);
	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(flowContext);

	//
	// Observation must not depend on being allowed to change the verdict.
	// Only the permit/block write-back below is gated on WRITE rights.
	//
	BOOLEAN canWrite =
		(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) != 0;

	if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_ID))
	{
		UINT localAddrIndex, remoteAddrIndex, localPortIndex;
		UINT remotePortIndex, protocolIndex, flagsIndex;
		GetNetwork5TupleIndexesForLayer(inFixedValues->layerId,
		  &localAddrIndex, &remoteAddrIndex, &localPortIndex,
		  &remotePortIndex, &protocolIndex, &flagsIndex);

		BOOLEAN send =
			(filter->filterId == WFP_send_filter_id_v4) ||
			(filter->filterId == WFP_send_filter_id_v6);
		BOOLEAN v6 =
			(filter->filterId == WFP_send_filter_id_v6) ||
			(filter->filterId == WFP_recv_filter_id_v6);
		UINT32 connectionFlags = flagsIndex != (UINT)-1 ?
			inFixedValues->incomingValue[flagsIndex].value.uint32 : 0;
		UCHAR protocol =
			inFixedValues->incomingValue[protocolIndex].value.uint8;
		USHORT local_port =
			inFixedValues->incomingValue[localPortIndex].value.uint16;
		USHORT remote_port =
			inFixedValues->incomingValue[remotePortIndex].value.uint16;

		CAPTURE_QUEUE_RECORD captureRecord;
		memzero(&captureRecord, sizeof(captureRecord));
		captureRecord.address_family = v6 ? AF_INET6 : AF_INET;
		captureRecord.protocol = protocol;
		captureRecord.event_type = send ?
			CAPTURE_QUEUE_EVENT_CONNECT : CAPTURE_QUEUE_EVENT_ACCEPT;
		captureRecord.direction = send ?
			CAPTURE_QUEUE_DIRECTION_OUTBOUND :
			CAPTURE_QUEUE_DIRECTION_INBOUND;
		captureRecord.local_port = local_port;
		captureRecord.remote_port = remote_port;

		IP_ADDRESS remote_ip;
		memzero(&remote_ip, sizeof(remote_ip));
		BOOLEAN haveAddresses = TRUE;
		if (v6)
		{
			const FWP_BYTE_ARRAY16 *localArray =
				inFixedValues->incomingValue[localAddrIndex].value.byteArray16;
			const FWP_BYTE_ARRAY16 *remoteArray =
				inFixedValues->incomingValue[remoteAddrIndex].value.byteArray16;
			if (! localArray || ! remoteArray)
			{
				haveAddresses = FALSE;
			}
			else
			{
				const UINT8* local_address = localArray->byteArray16;
				const UINT8* remote_address = remoteArray->byteArray16;

				memcpy(captureRecord.local_address, local_address, 16);
				memcpy(captureRecord.remote_address, remote_address, 16);
				memcpy(remote_ip.Data, remote_address, 16);
			}
		}
		else
		{
			UINT32 local_address = inFixedValues->incomingValue[localAddrIndex].value.uint32;
			UINT32 remote_address = inFixedValues->incomingValue[remoteAddrIndex].value.uint32;
			CaptureNetwork_EncodeIpv4(
				captureRecord.local_address, local_address);
			CaptureNetwork_EncodeIpv4(
				captureRecord.remote_address, remote_address);

			// IPv4-mapped IPv6 addresses, eg. ::FFFF:192.168.0.1
			remote_ip.Data[10] = 0xFF;
			remote_ip.Data[11] = 0xFF;
			memcpy(
				remote_ip.Data + 12, captureRecord.remote_address, 4);
		}

		BOOLEAN block = FALSE;
		BOOLEAN noloop = FALSE;
		BOOLEAN isloopback =
			(connectionFlags & FWP_CONDITION_FLAG_IS_LOOPBACK) != 0 ||
			(haveAddresses && WFP_isLoopback(&remote_ip));
		BOOLEAN captureIdentityValid = FALSE;
		CAPTURE_FILTER_IDENTITY captureIdentity;
		memzero(&captureIdentity, sizeof(captureIdentity));


		KIRQL irql; 
		WFP_PROCESS* wfp_proc;
		HANDLE processId = (HANDLE)inMetaValues->processId;

#ifdef _WIN64
		irql = KeAcquireSpinLockRaiseToDpc(&WFP_MapLock);
#else
		KeAcquireSpinLock(&WFP_MapLock, &irql);
#endif

		wfp_proc = map_get(&WFP_Processes, processId);
		if (wfp_proc) {

			block = wfp_proc->BlockInternet;
			noloop = wfp_proc->BlockLoopback;
			if (isloopback && noloop) {
				block = TRUE;
			}

			if (!block && haveAddresses) {

				block = NetFw_BlockTraffic(&wfp_proc->NetFwRules, &remote_ip, remote_port, protocol);
			}

			if (haveAddresses && wfp_proc->CaptureEligible &&
					!(connectionFlags & FWP_CONDITION_FLAG_IS_REAUTHORIZE)) {
				captureIdentityValid = TRUE;
				captureIdentity.process_id =
					(ULONG)(ULONG_PTR)wfp_proc->ProcessId;
				captureIdentity.session_id = wfp_proc->SessionId;
				captureIdentity.process_create_time =
					wfp_proc->ProcessCreateTime;
				captureIdentity.loopback = isloopback;
				memcpy(
					captureIdentity.box_name,
					wfp_proc->BoxName,
					sizeof(captureIdentity.box_name));
				memcpy(
					captureIdentity.sid_string,
					wfp_proc->SidString,
					sizeof(captureIdentity.sid_string));

				captureRecord.process_id = captureIdentity.process_id;
				captureRecord.session_id = captureIdentity.session_id;
				captureRecord.process_create_time =
					captureIdentity.process_create_time;
			}
		}
    
		KeReleaseSpinLock(&WFP_MapLock, irql);

		if (captureIdentityValid) {
			LARGE_INTEGER timestamp;
			KeQuerySystemTime(&timestamp);
			captureRecord.timestamp = timestamp.QuadPart;
			captureRecord.blocked = block;
			captureRecord.loopback = isloopback;
			Capture_RecordEvent(&captureIdentity, &captureRecord);
		}

		// TODO: Fix-Me, no ETW logging for now, we are here at DISPATCH_LEVEL but Session_MonitorPut is using pagable memory,
		// we need either to create a logging proxy using non-paged pool, or change the tracking mechanism to use non-paged pool itself.
        /*if (log){

			BOOLEAN send = (filter->filterId == WFP_send_filter_id_v4) || (filter->filterId == WFP_send_filter_id_v6);
			BOOLEAN v6 = (filter->filterId == WFP_send_filter_id_v6) || (filter->filterId == WFP_recv_filter_id_v6);

			
			//RtlStringCbPrintfW at DISPATCH_LEVEL or higher can cause a BSOD, 
			//the issue is with accessing unicode tables, which may be paged out.

			//The documentation for KdPrint() states it this way:

			//<wdk>
			//Format
			//Specifies a pointer to the format string to print. The Format string
			//supports all the printf-style formatting codes. However, the Unicode format
			//codes (%C, %S, %lc, %ls, %wc, %ws, and %wZ) can only be used with IRQL =
			//PASSIVE_LEVEL.
			//</wdk>

			//RtlStringCbPrintfA is technically also not permitted so a better solution needs to be found
			

			char trace_strA[256];
			if (v6) {
				RtlStringCbPrintfA(trace_strA, sizeof(trace_strA), "%s Network Traffic; Port: %u; Prot: %u; IPv6: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", 
					send ? "Outgoing " : "Incoming ", remote_port, protocol,
					remote_ip.Data[0], remote_ip.Data[1], remote_ip.Data[2], remote_ip.Data[3], remote_ip.Data[4], remote_ip.Data[5], remote_ip.Data[6], remote_ip.Data[7],
					remote_ip.Data[8], remote_ip.Data[9], remote_ip.Data[10], remote_ip.Data[11], remote_ip.Data[12], remote_ip.Data[13], remote_ip.Data[14], remote_ip.Data[15]);
			}
			else {
				RtlStringCbPrintfA(trace_strA, sizeof(trace_strA), "%s Network Traffic; Port: %u; Prot: %u; IPv4: %d.%d.%d.%d", 
					send ? "Outgoing " : "Incoming ", remote_port, protocol,
					remote_ip.Data[12], remote_ip.Data[13], remote_ip.Data[14], remote_ip.Data[15]);
			}

			WCHAR trace_str[256];
			char* cptr = trace_strA;
			WCHAR* wptr = trace_str;
			while (*cptr != '\0')
				*wptr++ = *cptr++;
			*wptr = L'\0';

            Session_MonitorPut(MONITOR_NETFW | (block ? MONITOR_DENY : MONITOR_OPEN), trace_str, PsGetCurrentProcessId());
        }*/

		if (block) {

			if (canWrite) {
				classifyOut->actionType = FWP_ACTION_BLOCK;
				classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
			}
			return;
		}
	}

	if (canWrite)
		classifyOut->actionType = FWP_ACTION_PERMIT;
	return;
}


static BOOLEAN WFP_IsV6Layer(UINT16 layerId)
{
    return layerId == FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6 ||
        layerId == FWPS_LAYER_OUTBOUND_TRANSPORT_V6 ||
        layerId == FWPS_LAYER_INBOUND_TRANSPORT_V6 ||
        layerId == FWPS_LAYER_STREAM_V6 ||
        layerId == FWPS_LAYER_DATAGRAM_DATA_V6 ||
        layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V6;
}


static BOOLEAN WFP_GetCaptureIdentity(
    const FWPS_INCOMING_METADATA_VALUES *metadata,
    CAPTURE_FILTER_IDENTITY *identity)
{
    if (! metadata || ! identity ||
            ! FWPS_IS_METADATA_FIELD_PRESENT(
                metadata, FWPS_METADATA_FIELD_PROCESS_ID)) {
        return FALSE;
    }

    HANDLE processId = (HANDLE)(ULONG_PTR)metadata->processId;
    BOOLEAN valid = FALSE;
    KIRQL irql;
#ifdef _WIN64
    irql = KeAcquireSpinLockRaiseToDpc(&WFP_MapLock);
#else
    KeAcquireSpinLock(&WFP_MapLock, &irql);
#endif

    WFP_PROCESS *wfpProcess = map_get(&WFP_Processes, processId);
    if (wfpProcess && wfpProcess->CaptureEligible) {
        RtlZeroMemory(identity, sizeof(*identity));
        identity->process_id = (ULONG)(ULONG_PTR)wfpProcess->ProcessId;
        identity->session_id = wfpProcess->SessionId;
        identity->process_create_time = wfpProcess->ProcessCreateTime;
        RtlCopyMemory(
            identity->box_name,
            wfpProcess->BoxName,
            sizeof(identity->box_name));
        RtlCopyMemory(
            identity->sid_string,
            wfpProcess->SidString,
            sizeof(identity->sid_string));
        valid = TRUE;
    }

    KeReleaseSpinLock(&WFP_MapLock, irql);
    return valid;
}


static UCHAR WFP_GetFlowDirection(
    const FWPS_INCOMING_VALUES *fixedValues)
{
    UINT directionIndex = WFP_IsV6Layer(fixedValues->layerId) ?
        FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_DIRECTION :
        FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_DIRECTION;
    return fixedValues->incomingValue[directionIndex].value.uint32 ==
            FWP_DIRECTION_INBOUND ?
        CAPTURE_PACKET_DIRECTION_INBOUND :
        CAPTURE_PACKET_DIRECTION_OUTBOUND;
}


static BOOLEAN WFP_BuildPacketRecord(
    const FWPS_INCOMING_VALUES *fixedValues,
    UCHAR direction,
    UCHAR layer,
    CAPTURE_PACKET_RECORD *record)
{
    UINT localAddressIndex;
    UINT remoteAddressIndex;
    UINT localPortIndex;
    UINT remotePortIndex;
    UINT protocolIndex;
    UINT flagsIndex;

    if (! fixedValues || ! record)
        return FALSE;

    GetNetwork5TupleIndexesForLayer(
        fixedValues->layerId,
        &localAddressIndex,
        &remoteAddressIndex,
        &localPortIndex,
        &remotePortIndex,
        &protocolIndex,
        &flagsIndex);
    if (localAddressIndex == (UINT)-1 ||
            remoteAddressIndex == (UINT)-1 ||
            localPortIndex == (UINT)-1 ||
            remotePortIndex == (UINT)-1 ||
            protocolIndex == (UINT)-1) {
        return FALSE;
    }

    BOOLEAN v6 = WFP_IsV6Layer(fixedValues->layerId);
    RtlZeroMemory(record, sizeof(*record));
    record->address_family = v6 ? AF_INET6 : AF_INET;
    record->protocol =
        fixedValues->incomingValue[protocolIndex].value.uint8;
    record->direction = direction;
    record->layer = layer;
    record->local_port =
        fixedValues->incomingValue[localPortIndex].value.uint16;
    record->remote_port =
        fixedValues->incomingValue[remotePortIndex].value.uint16;

    if (v6) {
        const FWP_BYTE_ARRAY16 *localArray =
            fixedValues->incomingValue[localAddressIndex].value.byteArray16;
        const FWP_BYTE_ARRAY16 *remoteArray =
            fixedValues->incomingValue[remoteAddressIndex].value.byteArray16;
        if (! localArray || ! remoteArray)
            return FALSE;
        RtlCopyMemory(record->local_address,
            localArray->byteArray16, sizeof(record->local_address));
        RtlCopyMemory(record->remote_address,
            remoteArray->byteArray16, sizeof(record->remote_address));
    }
    else {
        CaptureNetwork_EncodeIpv4(
            record->local_address,
            fixedValues->incomingValue[localAddressIndex].value.uint32);
        CaptureNetwork_EncodeIpv4(
            record->remote_address,
            fixedValues->incomingValue[remoteAddressIndex].value.uint32);
    }

    if (flagsIndex != (UINT)-1) {
        record->loopback =
            (fixedValues->incomingValue[flagsIndex].value.uint32 &
                FWP_CONDITION_FLAG_IS_LOOPBACK) != 0;
    }
    return TRUE;
}


static BOOLEAN WFP_IsInboundTransportLayer(UINT16 layerId)
{
    return layerId == FWPS_LAYER_INBOUND_TRANSPORT_V4 ||
        layerId == FWPS_LAYER_INBOUND_TRANSPORT_V6;
}


static ULONG WFP_CopyNetBuffer(
    const FWPS_INCOMING_VALUES *fixedValues,
    const FWPS_INCOMING_METADATA_VALUES *metadata,
    NET_BUFFER *netBuffer,
    UCHAR *buffer,
    ULONG capacity,
    ULONG *originalLength)
{
    if (originalLength)
        *originalLength = 0;
    if (! fixedValues || ! netBuffer || ! buffer || ! capacity)
        return 0;

    BOOLEAN retreated = FALSE;
    ULONG retreatSize = 0;
    if (WFP_IsInboundTransportLayer(fixedValues->layerId)) {
        if (! metadata || ! FWPS_IS_METADATA_FIELD_PRESENT(
                metadata, FWPS_METADATA_FIELD_TRANSPORT_HEADER_SIZE) ||
                ! metadata->transportHeaderSize) {
            return 0;
        }
        retreatSize = metadata->transportHeaderSize;
        if (NdisRetreatNetBufferDataStart(
                netBuffer, retreatSize, 0, NULL) != NDIS_STATUS_SUCCESS) {
            return 0;
        }
        retreated = TRUE;
    }

    ULONG capturedLength = 0;
    ULONG available = NET_BUFFER_DATA_LENGTH(netBuffer);
    if (originalLength)
        *originalLength = available;
    ULONG copyLength = available < capacity ? available : capacity;
    if (copyLength) {
        PVOID source = NdisGetDataBuffer(
            netBuffer, copyLength, buffer, 1, 0);
        if (source) {
            if (source != buffer)
                RtlCopyMemory(buffer, source, copyLength);
            capturedLength = copyLength;
        }
    }

    if (retreated)
        NdisAdvanceNetBufferDataStart(netBuffer, retreatSize, FALSE, NULL);
    return capturedLength;
}


static void WFP_RecordNetBufferList(
    const FWPS_INCOMING_VALUES *fixedValues,
    const FWPS_INCOMING_METADATA_VALUES *metadata,
    void *layerData,
    UINT64 flowContext,
    UCHAR layer)
{
    if (! fixedValues || ! layerData || ! flowContext)
        return;

    NET_BUFFER_LIST *list = (NET_BUFFER_LIST *)layerData;
    while (list) {
        NET_BUFFER *netBuffer = NET_BUFFER_LIST_FIRST_NB(list);
        while (netBuffer) {
            UCHAR buffer[CAPTURE_PACKET_SNAPLEN_MAX];
            ULONG originalLength = 0;
            ULONG capturedLength = WFP_CopyNetBuffer(
                fixedValues,
                metadata,
                netBuffer,
                buffer,
                sizeof(buffer),
                &originalLength);
            if (capturedLength) {
                Capture_RecordPayloadByFlow(
                    flowContext,
                    buffer,
                    capturedLength,
                    originalLength,
                    layer);
            }
            netBuffer = NET_BUFFER_NEXT_NB(netBuffer);
        }
        list = NET_BUFFER_LIST_NEXT_NBL(list);
    }
}


static UINT64 WFP_AssociateCaptureContext(
    const CAPTURE_FILTER_IDENTITY *identity,
    const CAPTURE_PACKET_RECORD *templateRecord,
    UINT64 flowHandle,
    UINT16 layerId,
    UINT32 calloutId,
    UCHAR direction)
{
    if (! identity || ! templateRecord || ! flowHandle || ! calloutId)
        return 0;

    CAPTURE_PACKET_RECORD record = *templateRecord;
    record.direction = direction;
    UINT64 context = Capture_CreateFlowContext(
        identity, &record, flowHandle, layerId, calloutId);
    if (! context)
        return Capture_LookupFlowContext(flowHandle, layerId, calloutId);

    NTSTATUS status = FwpsFlowAssociateContext(
        flowHandle, layerId, calloutId, context);
    if (status == STATUS_FWP_ALREADY_EXISTS) {
        Capture_DeleteFlowContext(context);
        return Capture_LookupFlowContext(flowHandle, layerId, calloutId);
    }
    if (! NT_SUCCESS(status)) {
        Capture_DeleteFlowContext(context);
        return 0;
    }
    return context;
}


static void NTAPI WFP_flow_classify(
    const FWPS_INCOMING_VALUES *inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
    void *layerData,
    const void *classifyContext,
    const FWPS_FILTER1 *filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT *classifyOut)
{
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(flowContext);
    UNREFERENCED_PARAMETER(classifyOut);

    if (! inFixedValues || ! inMetaValues || ! filter ||
            ! FWPS_IS_METADATA_FIELD_PRESENT(
                inMetaValues, FWPS_METADATA_FIELD_FLOW_HANDLE)) {
        return;
    }

    CAPTURE_FILTER_IDENTITY identity;
    if (! WFP_GetCaptureIdentity(inMetaValues, &identity))
        return;

    CAPTURE_PACKET_RECORD record;
    if (! WFP_BuildPacketRecord(
            inFixedValues,
            WFP_GetFlowDirection(inFixedValues),
            CAPTURE_PACKET_LAYER_TRANSPORT,
            &record)) {
        return;
    }

    record.process_create_time = identity.process_create_time;
    record.process_id = identity.process_id;
    record.session_id = identity.session_id;
    identity.loopback = record.loopback;

    const BOOLEAN v6 = inFixedValues->layerId ==
        FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6;
    WFP_AssociateCaptureContext(
        &identity,
        &record,
        inMetaValues->flowHandle,
        v6 ? FWPS_LAYER_OUTBOUND_TRANSPORT_V6 :
             FWPS_LAYER_OUTBOUND_TRANSPORT_V4,
        v6 ? WFP_transport_out_callout_id_v6 :
             WFP_transport_out_callout_id_v4,
        CAPTURE_PACKET_DIRECTION_OUTBOUND);
    WFP_AssociateCaptureContext(
        &identity,
        &record,
        inMetaValues->flowHandle,
        v6 ? FWPS_LAYER_INBOUND_TRANSPORT_V6 :
             FWPS_LAYER_INBOUND_TRANSPORT_V4,
        v6 ? WFP_transport_in_callout_id_v6 :
             WFP_transport_in_callout_id_v4,
        CAPTURE_PACKET_DIRECTION_INBOUND);

    if (record.protocol == IPPROTO_TCP) {
        WFP_AssociateCaptureContext(
            &identity,
            &record,
            inMetaValues->flowHandle,
            v6 ? FWPS_LAYER_STREAM_V6 : FWPS_LAYER_STREAM_V4,
            v6 ? WFP_stream_callout_id_v6 : WFP_stream_callout_id_v4,
            record.direction);
    }
    else if (record.protocol == IPPROTO_UDP) {
        WFP_AssociateCaptureContext(
            &identity,
            &record,
            inMetaValues->flowHandle,
            v6 ? FWPS_LAYER_DATAGRAM_DATA_V6 : FWPS_LAYER_DATAGRAM_DATA_V4,
            v6 ? WFP_datagram_callout_id_v6 : WFP_datagram_callout_id_v4,
            record.direction);
    }
}


static void NTAPI WFP_transport_classify(
    const FWPS_INCOMING_VALUES *inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
    void *layerData,
    const void *classifyContext,
    const FWPS_FILTER1 *filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT *classifyOut)
{
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(classifyOut);

    if (! flowContext && inFixedValues && inMetaValues &&
            FWPS_IS_METADATA_FIELD_PRESENT(
                inMetaValues, FWPS_METADATA_FIELD_FLOW_HANDLE)) {
        UINT32 calloutId = 0;
        UCHAR direction = CAPTURE_PACKET_DIRECTION_OUTBOUND;

        if (inFixedValues->layerId == FWPS_LAYER_INBOUND_TRANSPORT_V4) {
            calloutId = WFP_transport_in_callout_id_v4;
            direction = CAPTURE_PACKET_DIRECTION_INBOUND;
        }
        else if (inFixedValues->layerId == FWPS_LAYER_INBOUND_TRANSPORT_V6) {
            calloutId = WFP_transport_in_callout_id_v6;
            direction = CAPTURE_PACKET_DIRECTION_INBOUND;
        }
        else if (inFixedValues->layerId == FWPS_LAYER_OUTBOUND_TRANSPORT_V4) {
            calloutId = WFP_transport_out_callout_id_v4;
        }
        else if (inFixedValues->layerId == FWPS_LAYER_OUTBOUND_TRANSPORT_V6) {
            calloutId = WFP_transport_out_callout_id_v6;
        }

        if (calloutId) {
            flowContext = Capture_LookupFlowContext(
                inMetaValues->flowHandle,
                inFixedValues->layerId,
                calloutId);
        }

        if (! flowContext && calloutId) {
            CAPTURE_FILTER_IDENTITY identity;
            CAPTURE_PACKET_RECORD record;
            if (WFP_GetCaptureIdentity(inMetaValues, &identity) &&
                    WFP_BuildPacketRecord(
                        inFixedValues, direction,
                        CAPTURE_PACKET_LAYER_TRANSPORT, &record)) {
                record.process_create_time = identity.process_create_time;
                record.process_id = identity.process_id;
                record.session_id = identity.session_id;
                identity.loopback = record.loopback;
                flowContext = WFP_AssociateCaptureContext(
                    &identity,
                    &record,
                    inMetaValues->flowHandle,
                    inFixedValues->layerId,
                    calloutId,
                    direction);
            }
        }
    }

    if (! flowContext) {
        CAPTURE_FILTER_IDENTITY identity;
        if (inMetaValues &&
                WFP_GetCaptureIdentity(inMetaValues, &identity))
            Capture_CountDroppedIdentity(&identity);
        return;
    }

    WFP_RecordNetBufferList(
        inFixedValues,
        inMetaValues,
        layerData,
        flowContext,
        CAPTURE_PACKET_LAYER_TRANSPORT);
}


static void NTAPI WFP_stream_classify(
    const FWPS_INCOMING_VALUES *inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
    void *layerData,
    const void *classifyContext,
    const FWPS_FILTER1 *filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT *classifyOut)
{
    UNREFERENCED_PARAMETER(inFixedValues);
    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(classifyOut);

    if (! flowContext || ! layerData)
        return;

    FWPS_STREAM_CALLOUT_IO_PACKET *ioPacket =
        (FWPS_STREAM_CALLOUT_IO_PACKET *)layerData;
    if (! ioPacket->streamData || ! ioPacket->streamData->dataLength)
        return;

    UCHAR buffer[CAPTURE_PACKET_SNAPLEN_MAX];
    SIZE_T available = ioPacket->streamData->dataLength;
    ULONG originalLength = available > 0xffffffffULL ?
        (ULONG)-1 : (ULONG)available;
    ULONG copyLength = available > sizeof(buffer) ?
        sizeof(buffer) : (ULONG)available;
    SIZE_T copied = 0;
    FwpsCopyStreamDataToBuffer(
        ioPacket->streamData, buffer, copyLength, &copied);
    if (copied) {
        Capture_RecordPayloadByFlow(
            flowContext,
            buffer,
            (ULONG)copied,
            originalLength,
            CAPTURE_PACKET_LAYER_STREAM);
    }
}


static void NTAPI WFP_datagram_classify(
    const FWPS_INCOMING_VALUES *inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
    void *layerData,
    const void *classifyContext,
    const FWPS_FILTER1 *filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT *classifyOut)
{
    UNREFERENCED_PARAMETER(inFixedValues);
    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(classifyOut);

    if (! flowContext)
        return;

    WFP_RecordNetBufferList(
        inFixedValues,
        inMetaValues,
        layerData,
        flowContext,
        CAPTURE_PACKET_LAYER_DATAGRAM);
}


//---------------------------------------------------------------------------
// WFP_notify
//---------------------------------------------------------------------------


NTSTATUS WFP_notify(
	FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	const GUID * filterKey,
	const FWPS_FILTER1* filter) // FWPS_FILTER1 is the latest supported by windows 7
{
	UNREFERENCED_PARAMETER(notifyType);
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);
	return STATUS_SUCCESS;
}


//---------------------------------------------------------------------------
// WFP_flow_delete
//---------------------------------------------------------------------------


NTSTATUS WFP_flow_delete(UINT16 layerId, UINT32 calloutId, UINT64 flowContext)
{
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    Capture_DeleteFlowContext(flowContext);
    return STATUS_SUCCESS;
}


//---------------------------------------------------------------------------
// GetNetwork5TupleIndexesForLayer
//---------------------------------------------------------------------------


void
GetNetwork5TupleIndexesForLayer(
   _In_ UINT16 layerId,
   _Out_ UINT* localAddressIndex,
   _Out_ UINT* remoteAddressIndex,
   _Out_ UINT* localPortIndex,
   _Out_ UINT* remotePortIndex,
   _Out_ UINT* protocolIndex,
   _Out_ UINT* flagsIndex
   )
{
   switch (layerId)
   {
   case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
      *localAddressIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS;
      *remoteAddressIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS;
      *localPortIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT;
      *remotePortIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT;
      *protocolIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL;
      *flagsIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_FLAGS;
      break;
   case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
      *localAddressIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS;
      *remoteAddressIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS;
      *localPortIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT;
      *remotePortIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT;
      *protocolIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL;
      *flagsIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_FLAGS;
      break;
   case FWPS_LAYER_ALE_CONNECT_REDIRECT_V4:
      *localAddressIndex = FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_LOCAL_ADDRESS;
      *remoteAddressIndex = FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS;
      *localPortIndex = FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_LOCAL_PORT;
      *remotePortIndex = FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_PORT;
      *protocolIndex = FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL;
      *flagsIndex = FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_FLAGS;
      break;
   case FWPS_LAYER_ALE_CONNECT_REDIRECT_V6:
      *localAddressIndex = FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_LOCAL_ADDRESS;
      *remoteAddressIndex = FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_ADDRESS;
      *localPortIndex = FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_LOCAL_PORT;
      *remotePortIndex = FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_PORT;
      *protocolIndex = FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_PROTOCOL;
      *flagsIndex = FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_FLAGS;
      break;
   case FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4:
      *localAddressIndex = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS;
      *remoteAddressIndex = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS;
      *localPortIndex = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT;
      *remotePortIndex = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT;
      *protocolIndex = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL;
      *flagsIndex = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_FLAGS;
      break;
   case FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6:
      *localAddressIndex = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_ADDRESS;
      *remoteAddressIndex = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_ADDRESS;
      *localPortIndex = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_PORT;
      *remotePortIndex = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_PORT;
      *protocolIndex = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_PROTOCOL;
      *flagsIndex = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_FLAGS;
      break;
   case FWPS_LAYER_DATAGRAM_DATA_V4:
      *localAddressIndex = FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_ADDRESS;
      *remoteAddressIndex = FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_ADDRESS;
      *localPortIndex = FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_PORT;
      *remotePortIndex = FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_PORT;
      *protocolIndex = FWPS_FIELD_DATAGRAM_DATA_V4_IP_PROTOCOL;
      *flagsIndex = FWPS_FIELD_DATAGRAM_DATA_V4_FLAGS;
      break;
   case FWPS_LAYER_DATAGRAM_DATA_V6:
      *localAddressIndex = FWPS_FIELD_DATAGRAM_DATA_V6_IP_LOCAL_ADDRESS;
      *remoteAddressIndex = FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_ADDRESS;
      *localPortIndex = FWPS_FIELD_DATAGRAM_DATA_V6_IP_LOCAL_PORT;
      *remotePortIndex = FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_PORT;
      *protocolIndex = FWPS_FIELD_DATAGRAM_DATA_V6_IP_PROTOCOL;
      *flagsIndex = FWPS_FIELD_DATAGRAM_DATA_V6_FLAGS;
      break;
   case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
      *localAddressIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS;
      *remoteAddressIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS;
      *localPortIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT;
      *remotePortIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT;
      *protocolIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL;
      *flagsIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_FLAGS;
      break;
   case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6:
      *localAddressIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS;
      *remoteAddressIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS;
      *localPortIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT;
      *remotePortIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT;
      *protocolIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL;
      *flagsIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_FLAGS;
      break;
   case FWPS_LAYER_OUTBOUND_TRANSPORT_V4:
      *localAddressIndex = FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS;
      *remoteAddressIndex = FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS;
      *localPortIndex = FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_PORT;
      *remotePortIndex = FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_PORT;
      *protocolIndex = FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_PROTOCOL;
      *flagsIndex = (UINT)-1;
      break;
   case FWPS_LAYER_OUTBOUND_TRANSPORT_V6:
      *localAddressIndex = FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_LOCAL_ADDRESS;
      *remoteAddressIndex = FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_REMOTE_ADDRESS;
      *localPortIndex = FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_LOCAL_PORT;
      *remotePortIndex = FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_REMOTE_PORT;
      *protocolIndex = FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_PROTOCOL;
      *flagsIndex = (UINT)-1;
      break;
   case FWPS_LAYER_INBOUND_TRANSPORT_V4:
      *localAddressIndex = FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS;
      *remoteAddressIndex = FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS;
      *localPortIndex = FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_PORT;
      *remotePortIndex = FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_PORT;
      *protocolIndex = FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_PROTOCOL;
      *flagsIndex = (UINT)-1;
      break;
   case FWPS_LAYER_INBOUND_TRANSPORT_V6:
      *localAddressIndex = FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_LOCAL_ADDRESS;
      *remoteAddressIndex = FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_REMOTE_ADDRESS;
      *localPortIndex = FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_LOCAL_PORT;
      *remotePortIndex = FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_REMOTE_PORT;
      *protocolIndex = FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_PROTOCOL;
      *flagsIndex = (UINT)-1;
      break;
   default:
      *localAddressIndex = -1;
      *remoteAddressIndex = -1;
      *localPortIndex = -1;
      *remotePortIndex = -1;
      *protocolIndex = -1;
      *flagsIndex = -1;
      NT_ASSERT(0);
   }
}
