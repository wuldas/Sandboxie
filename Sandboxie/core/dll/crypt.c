/*
 * Copyright 2004-2020 Sandboxie Holdings, LLC 
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
// Cryptography
//---------------------------------------------------------------------------

#include "dll.h"

#include <windows.h>
#include <wincrypt.h>
#include "core/svc/ComWire.h"
#include "crypt_https_trust.h"



//---------------------------------------------------------------------------
// Functions
//---------------------------------------------------------------------------


static void Crypt_InitPromptData(
    COM_CRYPT_PROTECT_DATA_REQ *req,
    CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct);

static BOOL Crypt_CryptUnprotectData(
    DATA_BLOB *pDataIn, LPWSTR *ppszDataDescr, DATA_BLOB *pOptionalEntropy,
    PVOID pvReserved, CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct,
    DWORD dwFlags, DATA_BLOB *pDataOut);

static BOOL Crypt_CryptProtectData(
    DATA_BLOB *pDataIn, LPCWSTR szDataDescr, DATA_BLOB *pOptionalEntropy,
    PVOID pvReserved, CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct,
    DWORD dwFlags, DATA_BLOB *pDataOut);

static BOOL Crypt_CertGetCertificateChain(
    ULONG_PTR hChainEngine, ULONG_PTR pCertContext, ULONG_PTR pTime,
    ULONG_PTR hAdditionalStore, ULONG_PTR pChainPara, ULONG dwFlags,
    ULONG_PTR pvReserved, ULONG_PTR ppChainContext);

static BOOL Crypt_CertVerifyCertificateChainPolicy(
    ULONG_PTR pszPolicyOID, ULONG_PTR pChainContext,
    ULONG_PTR pPolicyPara, ULONG_PTR pPolicyStatus);

static LONG Crypt_InitializeSecurityContextW(
    ULONG_PTR phCredential, ULONG_PTR phContext, ULONG_PTR pszTargetName,
    ULONG fContextReq, ULONG Reserved1, ULONG TargetDataRep,
    ULONG_PTR pInput, ULONG Reserved2, ULONG_PTR phNewContext,
    ULONG_PTR pOutput, ULONG_PTR pfContextAttr, ULONG_PTR ptsExpiry);

static LONG Crypt_AcquireCredentialsHandleW(
    ULONG_PTR pszPrincipal, ULONG_PTR pszPackage, ULONG fCredentialUse,
    ULONG_PTR pvLogonId, ULONG_PTR pAuthData, ULONG_PTR pGetKeyFn,
    ULONG_PTR pvGetKeyArgument, ULONG_PTR phCredential, ULONG_PTR ptsExpiry);

#ifdef _WIN64

static int Crypt_GetKeyStorageInterface(void * a, void *buffer, void* c);
typedef int (*P_GetKeyStorageInterface) (void * a, void *buffer, void * c);
static P_GetKeyStorageInterface __sys_GetKeyStorageInterface = NULL;

static void Crypt_CryptClassErrorHandler(ULONG_PTR a);
typedef void (*P_CryptClassErrorHandler) (ULONG_PTR a);
static P_CryptClassErrorHandler __sys_CryptClassErrorHandler;

#endif // _WIN64

//---------------------------------------------------------------------------

typedef BOOL (*P_CryptUnprotectData)(
    DATA_BLOB *pDataIn, LPWSTR *ppszDataDescr, DATA_BLOB *pOptionalEntropy,
    PVOID pvReserved, CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct,
    DWORD dwFlags, DATA_BLOB *pDataOut);

typedef BOOL (*P_CryptProtectData)(
    DATA_BLOB *pDataIn, LPCWSTR szDataDescr, DATA_BLOB *pOptionalEntropy,
    PVOID pvReserved, CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct,
    DWORD dwFlags, DATA_BLOB *pDataOut);

typedef BOOL (*P_CertGetCertificateChain)(
    ULONG_PTR hChainEngine, ULONG_PTR pCertContext, ULONG_PTR pTime,
    ULONG_PTR hAdditionalStore, ULONG_PTR pChainPara, ULONG dwFlags,
    ULONG_PTR pvReserved, ULONG_PTR ppChainContext);

typedef BOOL (*P_CertVerifyCertificateChainPolicy)(
    ULONG_PTR pszPolicyOID, ULONG_PTR pChainContext,
    ULONG_PTR pPolicyPara, ULONG_PTR pPolicyStatus);

typedef LONG (*P_InitializeSecurityContextW)(
    ULONG_PTR phCredential, ULONG_PTR phContext, ULONG_PTR pszTargetName,
    ULONG fContextReq, ULONG Reserved1, ULONG TargetDataRep,
    ULONG_PTR pInput, ULONG Reserved2, ULONG_PTR phNewContext,
    ULONG_PTR pOutput, ULONG_PTR pfContextAttr, ULONG_PTR ptsExpiry);

typedef LONG (*P_QueryContextAttributesW)(
    ULONG_PTR phContext, ULONG ulAttribute, void *pBuffer);

typedef LONG (*P_AcquireCredentialsHandleW)(
    ULONG_PTR pszPrincipal, ULONG_PTR pszPackage, ULONG fCredentialUse,
    ULONG_PTR pvLogonId, ULONG_PTR pAuthData, ULONG_PTR pGetKeyFn,
    ULONG_PTR pvGetKeyArgument, ULONG_PTR phCredential, ULONG_PTR ptsExpiry);


//---------------------------------------------------------------------------


static P_CryptUnprotectData         __sys_CryptUnprotectData        = NULL;
static P_CryptProtectData           __sys_CryptProtectData          = NULL;
static P_CertGetCertificateChain    __sys_CertGetCertificateChain   = NULL;
static P_CertVerifyCertificateChainPolicy
    __sys_CertVerifyCertificateChainPolicy = NULL;
static P_InitializeSecurityContextW
    __sys_InitializeSecurityContextW = NULL;
static P_QueryContextAttributesW
    __sys_QueryContextAttributesW = NULL;
static P_AcquireCredentialsHandleW
    __sys_AcquireCredentialsHandleW = NULL;


//---------------------------------------------------------------------------
// Variables
//---------------------------------------------------------------------------


static BOOLEAN Crypt_CallSbieSvc = FALSE;


//---------------------------------------------------------------------------
// Crypt_InitPromptData
//---------------------------------------------------------------------------


_FX void Crypt_InitPromptData(
    COM_CRYPT_PROTECT_DATA_REQ *req,
    CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct)
{
    if (pPromptStruct &&
            pPromptStruct->cbSize == sizeof(CRYPTPROTECT_PROMPTSTRUCT)) {

        req->prompt_flags = pPromptStruct->dwPromptFlags;
        req->prompt_hwnd  = (ULONG_PTR)pPromptStruct->hwndApp;

        if (pPromptStruct->szPrompt) {

            ULONG len =
                (wcslen(pPromptStruct->szPrompt) + 1) * sizeof(WCHAR);
            if (len > sizeof(req->prompt_text))
                len = sizeof(req->prompt_text);
            memcpy(req->prompt_text, pPromptStruct->szPrompt, len);

        } else
            req->prompt_text[0] = L'\0';

    } else {

        req->prompt_flags = 0;
        req->prompt_hwnd = 0;
        req->prompt_text[0] = L'\0';
    }

    //
    // if ComServer::CryptProtectDataSlave in the SbieSvc COM Proxy
    // wants to display UI through CryptProtectData/CryptUnprotectData,
    // we want to allow the dialog box to go to the foreground
    //

    Gui_AllowSetForegroundWindow();
}


//---------------------------------------------------------------------------
// Crypt_CryptUnprotectData
//---------------------------------------------------------------------------


_FX BOOL Crypt_CryptUnprotectData(
    DATA_BLOB *pDataIn, LPWSTR *ppszDataDescr, DATA_BLOB *pOptionalEntropy,
    PVOID pvReserved, CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct,
    DWORD dwFlags, DATA_BLOB *pDataOut)
{
    COM_CRYPT_PROTECT_DATA_REQ *req;
    COM_CRYPT_PROTECT_DATA_RPL *rpl;
    ULONG req_len;
    ULONG entropy_len;
    ULONG error;
    UCHAR *ptr;

    //
    // first try system procedure
    //

    if (! Crypt_CallSbieSvc) {

        BOOL ok = __sys_CryptUnprotectData(
            pDataIn, ppszDataDescr, pOptionalEntropy, pvReserved,
            pPromptStruct, dwFlags, pDataOut);
        if (ok || GetLastError() != RPC_S_SERVER_UNAVAILABLE)
            return ok;
    }

    Crypt_CallSbieSvc = TRUE;

    //
    // otherwise call SbieSvc decrypt service
    //

    if (pOptionalEntropy)
        entropy_len = pOptionalEntropy->cbData;
    else
        entropy_len = 0;

    req_len = sizeof(COM_CRYPT_PROTECT_DATA_REQ)
            + pDataIn->cbData + entropy_len;

    req = (COM_CRYPT_PROTECT_DATA_REQ *)Dll_AllocTemp(req_len);
    req->h.length = req_len;
    req->h.msgid = MSGID_COM_CRYPT_PROTECT_DATA;

    req->mode = L'U';
    req->flags = dwFlags;
    req->data_len = pDataIn->cbData;
    req->entropy_len = entropy_len;
    req->descr_len = 0;

    ptr = (UCHAR *)req->data;
    memcpy(ptr, pDataIn->pbData, req->data_len);
    if (entropy_len) {
        ptr += req->data_len;
        memcpy(ptr, pOptionalEntropy->pbData, entropy_len);
    }

    Crypt_InitPromptData(req, pPromptStruct);

    rpl = (COM_CRYPT_PROTECT_DATA_RPL *)
                                SbieDll_CallServer((MSG_HEADER *)req);
    Dll_Free(req);

    if (! rpl)
        error = RPC_S_SERVER_UNAVAILABLE;
    else
        error = rpl->h.status;

    if (error == 0) {

        pDataOut->pbData = LocalAlloc(LPTR, rpl->data_len);
        if (! pDataOut->pbData)
            error = ERROR_NOT_ENOUGH_MEMORY;
        else {
            memcpy(pDataOut->pbData, rpl->data, rpl->data_len);
            pDataOut->cbData = rpl->data_len;

            if (ppszDataDescr) {

                ULONG descr_len = (rpl->descr_len + 1) * sizeof(WCHAR);
                *ppszDataDescr = LocalAlloc(LPTR, descr_len);
                if (! *ppszDataDescr) {
                    LocalFree(pDataOut->pbData);
                    pDataOut->pbData = NULL;
                    error = ERROR_NOT_ENOUGH_MEMORY;
                } else {
                    wmemcpy(*ppszDataDescr, (WCHAR*)(rpl->data + rpl->data_len),
                            rpl->descr_len);
                    (*ppszDataDescr)[rpl->descr_len] = L'\0';
                }
            }
        }
    }

    if (rpl)
        Dll_Free(rpl);
    SetLastError(error);
    return (error == 0 ? TRUE : FALSE);
}


//---------------------------------------------------------------------------
// Crypt_CryptProtectData
//---------------------------------------------------------------------------


_FX BOOL Crypt_CryptProtectData(
    DATA_BLOB *pDataIn, LPCWSTR szDataDescr, DATA_BLOB *pOptionalEntropy,
    PVOID pvReserved, CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct,
    DWORD dwFlags, DATA_BLOB *pDataOut)
{
    COM_CRYPT_PROTECT_DATA_REQ *req;
    COM_CRYPT_PROTECT_DATA_RPL *rpl;
    ULONG req_len;
    ULONG entropy_len;
    ULONG descr_len;
    ULONG error;
    UCHAR *ptr;

    //
    // first try system procedure
    //

    if (! Crypt_CallSbieSvc) {

        BOOL ok = __sys_CryptProtectData(
            pDataIn, szDataDescr, pOptionalEntropy, pvReserved,
            pPromptStruct, dwFlags, pDataOut);
        if (ok || GetLastError() != RPC_S_SERVER_UNAVAILABLE)
            return ok;
    }

    Crypt_CallSbieSvc = TRUE;

    //
    // otherwise call SbieSvc crypt service
    //

    if (pOptionalEntropy)
        entropy_len = pOptionalEntropy->cbData;
    else
        entropy_len = 0;
    if (szDataDescr)
        descr_len = wcslen(szDataDescr);
    else
        descr_len = 0;

    req_len = sizeof(COM_CRYPT_PROTECT_DATA_REQ)
            + pDataIn->cbData + entropy_len
            + (descr_len + 1) * sizeof(WCHAR);

    req = (COM_CRYPT_PROTECT_DATA_REQ *)Dll_AllocTemp(req_len);
    req->h.length = req_len;
    req->h.msgid = MSGID_COM_CRYPT_PROTECT_DATA;

    req->mode = L'P';
    req->flags = dwFlags;
    req->data_len = pDataIn->cbData;
    req->entropy_len = entropy_len;
    req->descr_len = descr_len;

    ptr = (UCHAR *)req->data;
    memcpy(ptr, pDataIn->pbData, req->data_len);
    ptr += req->data_len;
    if (entropy_len) {
        memcpy(ptr, pOptionalEntropy->pbData, entropy_len);
        ptr += req->entropy_len;
    }
    if (descr_len)
        wmemcpy((WCHAR *)ptr, szDataDescr, descr_len + 1);

    Crypt_InitPromptData(req, pPromptStruct);

    rpl = (COM_CRYPT_PROTECT_DATA_RPL *)
                                SbieDll_CallServer((MSG_HEADER *)req);
    Dll_Free(req);

    if (! rpl)
        error = RPC_S_SERVER_UNAVAILABLE;
    else
        error = rpl->h.status;

    if (error == 0) {

        pDataOut->pbData = LocalAlloc(LPTR, rpl->data_len);
        if (! pDataOut->pbData)
            error = ERROR_NOT_ENOUGH_MEMORY;
        else {
            memcpy(pDataOut->pbData, rpl->data, rpl->data_len);
            pDataOut->cbData = rpl->data_len;
        }
    }

    if (rpl)
        Dll_Free(rpl);
    SetLastError(error);
    return (error == 0 ? TRUE : FALSE);
}


//---------------------------------------------------------------------------
// Crypt_CertGetCertificateChain
//---------------------------------------------------------------------------


_FX BOOL Crypt_CertGetCertificateChain(
    ULONG_PTR hChainEngine, ULONG_PTR pCertContext, ULONG_PTR pTime,
    ULONG_PTR hAdditionalStore, ULONG_PTR pChainPara, ULONG dwFlags,
    ULONG_PTR pvReserved, ULONG_PTR ppChainContext)
{
    //
    // if the function CRYPT32!WaitForCryptService detects the CryptSvc
    // service is not started yet, it will start the service and then
    // delays for a fixed length of five seconds.  to eliminate the delay,
    // we need to start the CryptSvc beforehand.  we hook this API because
    // it is used by WinVerifyTrust and ends up calling WaitForCryptService
    //

    BOOLEAN event_created = FALSE;
    HANDLE hEvent = Ipc_GetServerEvent(Scm_CryptSvc, &event_created);
    if (hEvent) {
        if (event_created)
            if (SbieDll_StartBoxedService(Scm_CryptSvc, FALSE))
                WaitForSingleObject(hEvent, 8 * 1000);
        CloseHandle(hEvent);
    }

    {
        BOOL ok = __sys_CertGetCertificateChain(
            hChainEngine, pCertContext, pTime, hAdditionalStore,
            pChainPara, dwFlags, pvReserved, ppChainContext);
        if (ok && ppChainContext) {
            PCCERT_CHAIN_CONTEXT *chainOut =
                (PCCERT_CHAIN_CONTEXT *)ppChainContext;
            if (*chainOut) {
                HCERTSTORE sessionCas = CryptHttps_OpenSessionCaStore();
                if (sessionCas) {
                    CryptHttps_RelaxSessionCaChain(*chainOut, sessionCas);
                    CertCloseStore(sessionCas, 0);
                }
            }
        }
        return ok;
    }
}


//---------------------------------------------------------------------------
// Crypt_CertVerifyCertificateChainPolicy
//---------------------------------------------------------------------------


_FX BOOL Crypt_CertVerifyCertificateChainPolicy(
    ULONG_PTR pszPolicyOID, ULONG_PTR pChainContext,
    ULONG_PTR pPolicyPara, ULONG_PTR pPolicyStatus)
{
    BOOL ok = __sys_CertVerifyCertificateChainPolicy(
        pszPolicyOID, pChainContext, pPolicyPara, pPolicyStatus);
    if (pChainContext && pPolicyStatus) {
        CERT_CHAIN_POLICY_STATUS *status =
            (CERT_CHAIN_POLICY_STATUS *)pPolicyStatus;
        if ((! ok) || (status->dwError != 0)) {
            if (CryptHttps_RelaxSessionCaPolicy(
                    (PCCERT_CHAIN_CONTEXT)pChainContext, status))
                return TRUE;
        }
    }
    return ok;
}


#ifndef SEC_E_UNTRUSTED_ROOT
#define SEC_E_UNTRUSTED_ROOT            ((LONG)0x80090325L)
#endif
#ifndef SECPKG_ATTR_REMOTE_CERT_CONTEXT
#define SECPKG_ATTR_REMOTE_CERT_CONTEXT 0x53
#endif

//---------------------------------------------------------------------------
// Crypt_AcquireCredentialsHandleW
//---------------------------------------------------------------------------


static BOOLEAN Crypt_HttpsIsSchannelPackage(const WCHAR *package)
{
    static const WCHAR *name =
        L"Microsoft Unified Security Protocol Provider";

    if (! package)
        return FALSE;
    return _wcsicmp(package, name) == 0;
}


_FX LONG Crypt_AcquireCredentialsHandleW(
    ULONG_PTR pszPrincipal, ULONG_PTR pszPackage, ULONG fCredentialUse,
    ULONG_PTR pvLogonId, ULONG_PTR pAuthData, ULONG_PTR pGetKeyFn,
    ULONG_PTR pvGetKeyArgument, ULONG_PTR phCredential, ULONG_PTR ptsExpiry)
{
    //
    // For Schannel client credentials, tolerate "revocation could not be
    // checked" soft failures.  The HTTPS MITM leaf has no CRL/OCSP
    // endpoint, so without these flags a sandboxed curl/WinHTTP client
    // fails the handshake with CRYPT_E_NO_REVOCATION_CHECK even though the
    // chain is otherwise trusted via the persistent host CA.  These two
    // flags only suppress the *soft* "cannot check revocation" errors; they
    // do NOT bypass CRYPT_E_REVOKED and do not change the trust anchors.
    //
    // SCH_CRED_IGNORE_NO_REVOCATION_CHECK   0x00000800
    // SCH_CRED_IGNORE_REVOCATION_OFFLINE    0x00001000
    //

    if (Crypt_HttpsIsSchannelPackage((const WCHAR *)pszPackage)) {

        ULONG version = pAuthData ? *(ULONG *)pAuthData : 0;
        ULONG flagsOffset = 0;

        if (version >= 1 && version <= 4) {       // SCHANNEL_CRED
            flagsOffset = 0x2C;                   // ... dwSessionLifespan
        }
        else if (version == 5) {                  // SCH_CREDENTIALS
            flagsOffset = 0x34;
        }


        //
        // SECPKG_CRED_OUTBOUND is 2; only augment client credentials
        //

        if ((fCredentialUse & 2) && flagsOffset) {

            ULONG *flags = (ULONG *)(pAuthData + flagsOffset);
            *flags |= 0x1800;
        }
    }

    return __sys_AcquireCredentialsHandleW(
        pszPrincipal, pszPackage, fCredentialUse, pvLogonId, pAuthData,
        pGetKeyFn, pvGetKeyArgument, phCredential, ptsExpiry);
}


//---------------------------------------------------------------------------
// Crypt_InitializeSecurityContextW
//---------------------------------------------------------------------------


_FX LONG Crypt_InitializeSecurityContextW(
    ULONG_PTR phCredential, ULONG_PTR phContext, ULONG_PTR pszTargetName,
    ULONG fContextReq, ULONG Reserved1, ULONG TargetDataRep,
    ULONG_PTR pInput, ULONG Reserved2, ULONG_PTR phNewContext,
    ULONG_PTR pOutput, ULONG_PTR pfContextAttr, ULONG_PTR ptsExpiry)
{
    LONG status;
    LONG queryStatus;
    ULONG_PTR ctx;
    PCCERT_CONTEXT cert;
    HCERTSTORE sessionCas;

    status = __sys_InitializeSecurityContextW(
        phCredential, phContext, pszTargetName, fContextReq, Reserved1,
        TargetDataRep, pInput, Reserved2, phNewContext, pOutput,
        pfContextAttr, ptsExpiry);
    if (status != SEC_E_UNTRUSTED_ROOT)
        return status;

    if (! __sys_QueryContextAttributesW) {
        HMODULE module = GetModuleHandleW(L"sspicli.dll");
        if (module)
            __sys_QueryContextAttributesW = (P_QueryContextAttributesW)
                GetProcAddress(module, "QueryContextAttributesW");
        if (! __sys_QueryContextAttributesW) {
            module = GetModuleHandleW(L"secur32.dll");
            if (module)
                __sys_QueryContextAttributesW =
                    (P_QueryContextAttributesW)GetProcAddress(
                        module, "QueryContextAttributesW");
        }
    }
    if (! __sys_QueryContextAttributesW) {
        return status;
    }

    ctx = phNewContext ? phNewContext : phContext;
    if (! ctx) {
        return status;
    }
    cert = NULL;
    queryStatus = __sys_QueryContextAttributesW(
        ctx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &cert);
    if (queryStatus != 0 || ! cert) {
        return status;
    }

    sessionCas = CryptHttps_OpenSessionCaStore();
    if (sessionCas && CryptHttps_LeafSignedByKnownCas(cert, sessionCas)) {
        status = 0;
    } else {
    }
    if (sessionCas)
        CertCloseStore(sessionCas, 0);
    CertFreeCertificateContext(cert);
    return status;
}


//---------------------------------------------------------------------------
// Crypt_Init
//---------------------------------------------------------------------------


_FX BOOLEAN Crypt_Init(HMODULE module)
{
    void *CryptProtectData;
    void *CryptUnprotectData;
    void *CertGetCertificateChain;
    void *CertVerifyCertificateChainPolicy;


    //
    // in app mode we have our original token so no need to hook this
    //

    if (Ipc_OpenCOM && Dll_CompartmentMode) 
        return TRUE;

    //
    // hook cryptography services
    //

    CryptProtectData = GetProcAddress(module, "CryptProtectData");
    CryptUnprotectData = GetProcAddress(module, "CryptUnprotectData");
    CertGetCertificateChain =
                        GetProcAddress(module, "CertGetCertificateChain");
    CertVerifyCertificateChainPolicy =
                        GetProcAddress(module, "CertVerifyCertificateChainPolicy");

    // $Workaround$ - 3rd party fix
    if ((! CryptProtectData) && (Dll_OsBuild >= 8400)
            //&& (Dll_ImageType == DLL_IMAGE_MOZILLA_FIREFOX)
            && GetModuleHandle(L"UMEngx86.dll")) {
        // on Windows 8 with Norton 360, and with the Norton toolbar
        // activated in Firefox, the GetProcAddress calls above fail,
        // so silently ignore that
        return TRUE;
    }

    SBIEDLL_HOOK(Crypt_,CryptProtectData);
    SBIEDLL_HOOK(Crypt_,CryptUnprotectData);
    SBIEDLL_HOOK(Crypt_,CertGetCertificateChain);
    if (CertVerifyCertificateChainPolicy) {
        SBIEDLL_HOOK(Crypt_,CertVerifyCertificateChainPolicy);
    }

    return TRUE;
}


//---------------------------------------------------------------------------
// Crypt_InitSspi
//---------------------------------------------------------------------------


_FX BOOLEAN Crypt_InitSspi(HMODULE module)
{
    void *InitializeSecurityContextW;
    void *QueryContextAttributesW;
    void *AcquireCredentialsHandleW;

    InitializeSecurityContextW =
        GetProcAddress(module, "InitializeSecurityContextW");
    QueryContextAttributesW =
        GetProcAddress(module, "QueryContextAttributesW");
    if (QueryContextAttributesW)
        __sys_QueryContextAttributesW =
            (P_QueryContextAttributesW)QueryContextAttributesW;
    if (! InitializeSecurityContextW)
        return TRUE;
    SBIEDLL_HOOK(Crypt_,InitializeSecurityContextW);
    AcquireCredentialsHandleW =
        GetProcAddress(module, "AcquireCredentialsHandleW");
    if (AcquireCredentialsHandleW)
        SBIEDLL_HOOK(Crypt_,AcquireCredentialsHandleW);
    return TRUE;
}

#ifdef _WIN64

typedef struct _KeyInterfaceClass
{
    ULONG_PTR header;
    void * KeyInterfaceConstructor;
    void * SPCryptOpenProvider;
    void * unknownClassFunction_2;
    void * unknownClassFunction_3;
    void * unknownClassFunction_4;
    void * unknownClassFunction_5;
    void * unknownClassFunction_6;
    void * unknownClassFunction_7;
    void * unknownClassFunction_8;
    void * ErrorHandler;
} KeyInterfaceClass;


void Crypt_CryptClassErrorHandler(ULONG_PTR classAddress)
{
    if (classAddress <= 2) {
        __sys_CryptClassErrorHandler(0);
    }
    else
        __sys_CryptClassErrorHandler(classAddress);
    return;
}


int Crypt_GetKeyStorageInterface(void * a, void *data, void *c)
{
    int rc;
    KeyInterfaceClass* ClassPtr;
    rc = __sys_GetKeyStorageInterface(a, data, c);

    if (data) {
        void * CryptClassErrorHandler;

        ClassPtr = (KeyInterfaceClass*)(*(ULONG_PTR *)data);
        if (__sys_CryptClassErrorHandler != ClassPtr->ErrorHandler) {
            HMODULE module = NULL; // fix-me: 
            CryptClassErrorHandler = (P_CryptClassErrorHandler)ClassPtr->ErrorHandler;
            SBIEDLL_HOOK(Crypt_, CryptClassErrorHandler);
        }
    }
    return rc;
}


_FX BOOLEAN NcryptProv_Init(HMODULE module)
{
    void * GetKeyStorageInterface;
    GetKeyStorageInterface = GetProcAddress(module, "GetKeyStorageInterface");

    if (GetKeyStorageInterface) {
        SBIEDLL_HOOK(Crypt_, GetKeyStorageInterface);
    }
    return TRUE;
}

#endif  // _WIN64