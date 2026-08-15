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
// HTTPS connect-redirect decision tests
//---------------------------------------------------------------------------

#include <stdio.h>
#include <string.h>

#include "../../Sandboxie/core/drv/capture_https.h"


static int Require(int condition, const char *message)
{
    if (! condition) {
        fprintf(stderr, "FAILED: %s\n", message);
        return 0;
    }
    return 1;
}


static void FillTarget(CAPTURE_FILTER_TARGET *target)
{
    memset(target, 0, sizeof(*target));
    target->scope = CAPTURE_FILTER_SCOPE_PROCESS;
    target->process_id = 4242;
    target->session_id = 1;
    target->process_create_time = 1001;
    wcscpy_s(target->box_name, BOXNAME_COUNT, L"DefaultBox");
    wcscpy_s(target->sid_string, 96, L"S-1-5-21-1-2-3-1001");
}


static void FillIdentity(CAPTURE_FILTER_IDENTITY *identity)
{
    memset(identity, 0, sizeof(*identity));
    identity->process_id = 4242;
    identity->session_id = 1;
    identity->process_create_time = 1001;
    wcscpy_s(identity->box_name, BOXNAME_COUNT, L"DefaultBox");
    wcscpy_s(identity->sid_string, 96, L"S-1-5-21-1-2-3-1001");
}


static CAPTURE_HTTPS_FLOW MakeIpv4HttpsFlow(
    const CAPTURE_FILTER_TARGET *target,
    const CAPTURE_FILTER_IDENTITY *identity)
{
    CAPTURE_HTTPS_FLOW flow;
    memset(&flow, 0, sizeof(flow));
    flow.target = target;
    flow.identity = identity;
    flow.protocol = CAPTURE_HTTPS_TCP;
    flow.address_family = CAPTURE_HTTPS_AF_INET;
    flow.remote_port = CAPTURE_HTTPS_PORT;
    flow.listen_port = 18443;
    flow.remote_address[0] = 1;
    flow.remote_address[1] = 1;
    flow.remote_address[2] = 1;
    flow.remote_address[3] = 1;
    return flow;
}


static int TestMatchingTcp443Redirects(void)
{
    CAPTURE_FILTER_TARGET target;
    CAPTURE_FILTER_IDENTITY identity;
    CAPTURE_HTTPS_FLOW flow;

    FillTarget(&target);
    FillIdentity(&identity);
    flow = MakeIpv4HttpsFlow(&target, &identity);
    return Require(
        CaptureHttps_Decide(&flow) == CAPTURE_HTTPS_DECISION_REDIRECT,
        "matching TCP/443 redirects");
}


static int TestWrongPortContinues(void)
{
    CAPTURE_FILTER_TARGET target;
    CAPTURE_FILTER_IDENTITY identity;
    CAPTURE_HTTPS_FLOW flow;

    FillTarget(&target);
    FillIdentity(&identity);
    flow = MakeIpv4HttpsFlow(&target, &identity);
    flow.remote_port = 80;
    return Require(
        CaptureHttps_Decide(&flow) == CAPTURE_HTTPS_DECISION_CONTINUE,
        "TCP/80 is not redirected");
}


static int TestUdp443Continues(void)
{
    CAPTURE_FILTER_TARGET target;
    CAPTURE_FILTER_IDENTITY identity;
    CAPTURE_HTTPS_FLOW flow;

    FillTarget(&target);
    FillIdentity(&identity);
    flow = MakeIpv4HttpsFlow(&target, &identity);
    flow.protocol = 17;
    return Require(
        CaptureHttps_Decide(&flow) == CAPTURE_HTTPS_DECISION_CONTINUE,
        "UDP/443 is not redirected");
}


static int TestPidAloneIsNotEnough(void)
{
    CAPTURE_FILTER_TARGET target;
    CAPTURE_FILTER_IDENTITY identity;
    CAPTURE_HTTPS_FLOW flow;

    FillTarget(&target);
    FillIdentity(&identity);
    identity.process_create_time = 9999;
    flow = MakeIpv4HttpsFlow(&target, &identity);
    return Require(
        CaptureHttps_Decide(&flow) == CAPTURE_HTTPS_DECISION_CONTINUE,
        "PID without createTime does not redirect");
}


static int TestMissingListenPortContinues(void)
{
    CAPTURE_FILTER_TARGET target;
    CAPTURE_FILTER_IDENTITY identity;
    CAPTURE_HTTPS_FLOW flow;

    FillTarget(&target);
    FillIdentity(&identity);
    flow = MakeIpv4HttpsFlow(&target, &identity);
    flow.listen_port = 0;
    return Require(
        CaptureHttps_Decide(&flow) == CAPTURE_HTTPS_DECISION_CONTINUE,
        "unpublished listen port does not redirect");
}


static int TestSelfRedirectedContinues(void)
{
    CAPTURE_FILTER_TARGET target;
    CAPTURE_FILTER_IDENTITY identity;
    CAPTURE_HTTPS_FLOW flow;

    FillTarget(&target);
    FillIdentity(&identity);
    flow = MakeIpv4HttpsFlow(&target, &identity);
    flow.already_redirected_by_self = TRUE;
    return Require(
        CaptureHttps_Decide(&flow) == CAPTURE_HTTPS_DECISION_CONTINUE,
        "self-redirected flow is skipped");
}


static int TestListenerDestinationContinues(void)
{
    CAPTURE_FILTER_TARGET target;
    CAPTURE_FILTER_IDENTITY identity;
    CAPTURE_HTTPS_FLOW flow;

    FillTarget(&target);
    FillIdentity(&identity);
    flow = MakeIpv4HttpsFlow(&target, &identity);
    memset(flow.remote_address, 0, sizeof(flow.remote_address));
    flow.remote_address[0] = 127;
    flow.remote_address[3] = 1;
    flow.remote_port = flow.listen_port;
    return Require(
        CaptureHttps_IsListenerDestination(
            flow.address_family, flow.remote_address,
            flow.remote_port, flow.listen_port),
        "loopback listen dest is detected") &&
        Require(
            CaptureHttps_Decide(&flow) == CAPTURE_HTTPS_DECISION_CONTINUE,
            "dest equal to listener is not redirected");
}


static int TestDifferentBoxContinues(void)
{
    CAPTURE_FILTER_TARGET target;
    CAPTURE_FILTER_IDENTITY identity;
    CAPTURE_HTTPS_FLOW flow;

    FillTarget(&target);
    FillIdentity(&identity);
    wcscpy_s(identity.box_name, BOXNAME_COUNT, L"OtherBox");
    flow = MakeIpv4HttpsFlow(&target, &identity);
    return Require(
        CaptureHttps_Decide(&flow) == CAPTURE_HTTPS_DECISION_CONTINUE,
        "other box is not redirected");
}


static int TestFillContext(void)
{
    CAPTURE_FILTER_IDENTITY identity;
    HTTPS_REDIRECT_CONTEXT context;
    UCHAR address[16];

    FillIdentity(&identity);
    memset(address, 0, sizeof(address));
    address[0] = 93;
    address[3] = 184;
    memset(&context, 0xCC, sizeof(context));
    CaptureHttps_FillContext(
        &context, 0x1111111111111111ull, 0x2222222222222222ull,
        0x3333333333333333ull, &identity, CAPTURE_HTTPS_AF_INET,
        443, address);

    return Require(context.magic == HTTPS_REDIRECT_CONTEXT_MAGIC,
                   "context magic") &&
        Require(context.version == HTTPS_REDIRECT_CONTEXT_VERSION,
                "context version") &&
        Require(context.capture_id_high == 0x1111111111111111ull,
                "context capture high") &&
        Require(context.capture_id_low == 0x2222222222222222ull,
                "context capture low") &&
        Require(context.generation == 0x3333333333333333ull,
                "context generation") &&
        Require(context.process_id == identity.process_id, "context pid") &&
        Require(context.session_id == identity.session_id,
                "context session") &&
        Require(context.process_create_time == identity.process_create_time,
                "context createTime") &&
        Require(context.address_family == CAPTURE_HTTPS_AF_INET,
                "context family") &&
        Require(context.original_port == 443, "context original port") &&
        Require(context.reserved == 0, "context reserved") &&
        Require(memcmp(context.original_address, address, 16) == 0,
                "context original address");
}


static int TestCreateContextIsHeapNotStack(void)
{
    CAPTURE_FILTER_IDENTITY identity;
    HTTPS_REDIRECT_CONTEXT stack;
    HTTPS_REDIRECT_CONTEXT *heap;
    UCHAR address[16];

    FillIdentity(&identity);
    memset(address, 0, sizeof(address));
    address[0] = 1;
    address[3] = 1;
    memset(&stack, 0xCC, sizeof(stack));
    heap = CaptureHttps_CreateContext(
        1, 2, 3, &identity, CAPTURE_HTTPS_AF_INET, 443, address);
    if (! Require(heap != NULL, "create context allocates") ||
            ! Require(heap != &stack, "context is not the stack dummy") ||
            ! Require(heap->magic == HTTPS_REDIRECT_CONTEXT_MAGIC,
                      "heap context magic") ||
            ! Require(heap->original_port == 443, "heap context port")) {
        CaptureHttps_ReleaseContext(heap);
        return 0;
    }
    CaptureHttps_ReleaseContext(heap);
    CaptureHttps_ReleaseContext(NULL);
    return Require(
        CaptureHttps_CreateContext(
            1, 2, 3, NULL, CAPTURE_HTTPS_AF_INET, 443, address) == NULL,
        "null identity does not allocate");
}


int main(void)
{
    int ok = TestMatchingTcp443Redirects() &&
        TestWrongPortContinues() &&
        TestUdp443Continues() &&
        TestPidAloneIsNotEnough() &&
        TestMissingListenPortContinues() &&
        TestSelfRedirectedContinues() &&
        TestListenerDestinationContinues() &&
        TestDifferentBoxContinues() &&
        TestFillContext() &&
        TestCreateContextIsHeapNotStack();
    if (! ok)
        return 1;
    printf("https redirect tests passed\n");
    return 0;
}
