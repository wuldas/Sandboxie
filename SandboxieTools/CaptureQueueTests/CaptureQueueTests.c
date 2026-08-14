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
// Capture Connection Queue Tests
//---------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../Sandboxie/core/drv/capture_queue.h"
#include "../../Sandboxie/core/drv/capture_filter.h"
#include "../../Sandboxie/core/drv/capture_network.h"
#include "../../Sandboxie/core/drv/capture_packet.h"
#include "../../Sandboxie/core/drv/capture_stream.h"


static void *TestAlloc(SIZE_T size)
{
    return malloc(size);
}


static void TestFree(void *ptr)
{
    free(ptr);
}


static int Require(int condition, const char *message)
{
    if (! condition) {
        fprintf(stderr, "FAILED: %s\n", message);
        return 0;
    }
    return 1;
}


static CAPTURE_QUEUE_RECORD MakeRecord(ULONG processId)
{
    CAPTURE_QUEUE_RECORD record;
    memset(&record, 0, sizeof(record));
    record.process_id = processId;
    return record;
}


static int TestPreservesOrderAndAssignsSequence(void)
{
    CAPTURE_QUEUE *queue = CaptureQueue_Create(3, TestAlloc);
    if (! Require(queue != NULL, "queue allocation"))
        return 0;

    CAPTURE_QUEUE_RECORD record = MakeRecord(10);
    CaptureQueue_Push(queue, &record);
    record = MakeRecord(20);
    CaptureQueue_Push(queue, &record);

    CAPTURE_QUEUE_RECORD output[3];
    memset(output, 0, sizeof(output));
    ULONG64 next = 0, oldest = 0, newest = 0, dropped = 0;
    ULONG remaining = 99;
    ULONG count = CaptureQueue_Drain(
        queue, output, 3, &next, &oldest, &newest, &dropped,
        &remaining);

    int ok =
        Require(count == 2, "two records returned") &&
        Require(output[0].process_id == 10, "first record preserved") &&
        Require(output[1].process_id == 20, "second record preserved") &&
        Require(output[0].sequence == 1, "first sequence assigned") &&
        Require(output[1].sequence == 2, "second sequence assigned") &&
        Require(oldest == 1 && newest == 2, "sequence window returned") &&
        Require(next == 2, "next cursor returned") &&
        Require(dropped == 0, "no drops before overflow") &&
        Require(remaining == 0, "drain empties the queue");

    CaptureQueue_Destroy(queue, TestFree);
    return ok;
}


static int TestOverwriteIsBoundedAndCounted(void)
{
    CAPTURE_QUEUE *queue = CaptureQueue_Create(2, TestAlloc);
    if (! Require(queue != NULL, "queue allocation"))
        return 0;

    CAPTURE_QUEUE_RECORD record = MakeRecord(10);
    CaptureQueue_Push(queue, &record);
    record = MakeRecord(20);
    CaptureQueue_Push(queue, &record);
    record = MakeRecord(30);
    CaptureQueue_Push(queue, &record);

    CAPTURE_QUEUE_RECORD output[2];
    ULONG64 next = 0, oldest = 0, newest = 0, dropped = 0;
    ULONG remaining = 99;
    ULONG count = CaptureQueue_Drain(
        queue, output, 2, &next, &oldest, &newest, &dropped,
        &remaining);

    int ok =
        Require(count == 2, "capacity remains bounded") &&
        Require(output[0].process_id == 20, "oldest record evicted") &&
        Require(output[1].process_id == 30, "newest record retained") &&
        Require(oldest == 2 && newest == 3, "retained sequence window") &&
        Require(dropped == 1, "one overwritten record counted") &&
        Require(next == 3, "cursor advances to newest returned record") &&
        Require(remaining == 0, "overflowed queue drains completely");

    CaptureQueue_Destroy(queue, TestFree);
    return ok;
}


static int TestDrainBatchLimit(void)
{
    CAPTURE_QUEUE *queue = CaptureQueue_Create(4, TestAlloc);
    if (! Require(queue != NULL, "queue allocation"))
        return 0;

    for (ULONG i = 1; i <= 4; ++i) {
        CAPTURE_QUEUE_RECORD record = MakeRecord(i * 10);
        CaptureQueue_Push(queue, &record);
    }

    CAPTURE_QUEUE_RECORD output[2];
    ULONG64 next = 0;
    ULONG remaining = 0;
    ULONG count = CaptureQueue_Drain(
        queue, output, 2, &next, NULL, NULL, NULL, &remaining);

    int ok =
        Require(count == 2, "batch limit respected") &&
        Require(output[0].sequence == 1, "drain starts at oldest record") &&
        Require(output[1].sequence == 2, "drain preserves FIFO order") &&
        Require(next == 2, "cursor equals final returned sequence") &&
        Require(remaining == 2, "undrained records remain bounded");

    CAPTURE_QUEUE_RECORD finalOutput[2];
    count = CaptureQueue_Drain(
        queue, finalOutput, 2, &next, NULL, NULL, NULL, &remaining);
    ok = ok &&
        Require(count == 2, "second drain returns remaining records") &&
        Require(finalOutput[0].sequence == 3, "second drain resumes FIFO") &&
        Require(finalOutput[1].sequence == 4, "newest record returned") &&
        Require(remaining == 0, "second drain empties queue");

    CaptureQueue_Destroy(queue, TestFree);
    return ok;
}


static int TestResetClearsRetentionButKeepsMonotonicCursor(void)
{
    CAPTURE_QUEUE *queue = CaptureQueue_Create(2, TestAlloc);
    if (! Require(queue != NULL, "queue allocation"))
        return 0;

    CAPTURE_QUEUE_RECORD record = MakeRecord(10);
    CaptureQueue_Push(queue, &record);
    CaptureQueue_Reset(queue);
    record = MakeRecord(20);
    CaptureQueue_Push(queue, &record);

    CAPTURE_QUEUE_RECORD output;
    ULONG64 next = 0, dropped = 99;
    ULONG count = CaptureQueue_Drain(
        queue, &output, 1, &next, NULL, NULL, &dropped, NULL);

    int ok =
        Require(count == 1, "record returned after reset") &&
        Require(output.sequence == 2, "sequence remains monotonic") &&
        Require(output.process_id == 20, "post-reset record retained") &&
        Require(dropped == 0, "reset clears drop accounting");

    CaptureQueue_Destroy(queue, TestFree);
    return ok;
}


static int TestSequenceWrapStartsNewBoundedEpoch(void)
{
    CAPTURE_QUEUE *queue = CaptureQueue_Create(2, TestAlloc);
    if (! Require(queue != NULL, "queue allocation"))
        return 0;

    queue->next_sequence = (ULONG64)-1;
    CAPTURE_QUEUE_RECORD record = MakeRecord(10);
    CaptureQueue_Push(queue, &record);
    if (!Require(queue->records[queue->head].sequence == (ULONG64)-1,
                 "maximum sequence is emitted")) {
        CaptureQueue_Destroy(queue, TestFree);
        return 0;
    }

    record = MakeRecord(20);
    CaptureQueue_Push(queue, &record);

    CAPTURE_QUEUE_RECORD output[2];
    ULONG64 dropped = 0;
    ULONG remaining = 99;
    ULONG count = CaptureQueue_Drain(
        queue, output, 2, NULL, NULL, NULL, &dropped, &remaining);

    int ok =
        Require(count == 1, "wrap discards prior sequence epoch") &&
        Require(output[0].sequence == 1, "new sequence epoch starts at one") &&
        Require(output[0].process_id == 20, "new epoch record retained") &&
        Require(dropped == 1, "discarded epoch is counted as dropped") &&
        Require(remaining == 0, "new epoch drains completely");

    queue->dropped_count = (ULONG64)-1;
    record = MakeRecord(30);
    CaptureQueue_Push(queue, &record);
    record = MakeRecord(40);
    CaptureQueue_Push(queue, &record);
    record = MakeRecord(50);
    CaptureQueue_Push(queue, &record);
    ok = ok && Require(queue->dropped_count == (ULONG64)-1,
                       "drop counter saturates instead of wrapping");

    CaptureQueue_Destroy(queue, TestFree);
    return ok;
}


static int TestIpv4HostOrderEncodingProducesNetworkBytes(void)
{
    UCHAR address[16];
    memset(address, 0xA5, sizeof(address));

    CaptureNetwork_EncodeIpv4(address, 0x7F000001UL);
    if (!Require(address[0] == 127 && address[1] == 0 &&
                 address[2] == 0 && address[3] == 1,
                 "IPv4 loopback is encoded in network byte order")) {
        return 0;
    }

    for (ULONG index = 4; index < 16; ++index) {
        if (!Require(address[index] == 0,
                     "unused IPv4 address bytes are cleared")) {
            return 0;
        }
    }

    CaptureNetwork_EncodeIpv4(address, 0xC0A80102UL);
    return Require(address[0] == 192 && address[1] == 168 &&
                   address[2] == 1 && address[3] == 2,
                   "IPv4 private address is encoded in network byte order");
}


static void SetIdentityText(
    CAPTURE_FILTER_IDENTITY *identity, const WCHAR *box, const WCHAR *sid)
{
    wcsncpy_s(identity->box_name, BOXNAME_COUNT, box, _TRUNCATE);
    wcsncpy_s(identity->sid_string, 96, sid, _TRUNCATE);
}


static int TestFilterSeparatesBoxSidAndSession(void)
{
    CAPTURE_FILTER_TARGET target;
    CAPTURE_FILTER_IDENTITY identity;
    memset(&target, 0, sizeof(target));
    memset(&identity, 0, sizeof(identity));

    target.scope = CAPTURE_FILTER_SCOPE_BOX;
    target.flags = CAPTURE_FILTER_FLAG_INCLUDE_FUTURE;
    target.session_id = 7;
    wcscpy_s(target.box_name, BOXNAME_COUNT, L"BoxA");
    wcscpy_s(target.sid_string, 96, L"S-1-5-21-100");

    identity.process_id = 10;
    identity.process_create_time = 1000;
    identity.session_id = 7;
    SetIdentityText(&identity, L"BoxA", L"S-1-5-21-100");

    if (!Require(CaptureFilter_Matches(&target, &identity),
                 "matching sandbox identity is accepted"))
        return 0;

    SetIdentityText(&identity, L"BoxB", L"S-1-5-21-100");
    if (!Require(!CaptureFilter_Matches(&target, &identity),
                 "other sandbox is rejected"))
        return 0;

    SetIdentityText(&identity, L"BoxA", L"S-1-5-21-200");
    if (!Require(!CaptureFilter_Matches(&target, &identity),
                 "other SID is rejected"))
        return 0;

    SetIdentityText(&identity, L"BoxA", L"S-1-5-21-100");
    identity.session_id = 8;
    return Require(!CaptureFilter_Matches(&target, &identity),
                   "other Windows session is rejected");
}


static int TestFilterRejectsPidReuseAndHonorsFutureFlag(void)
{
    CAPTURE_FILTER_PROCESS_KEY initial = { 10, 0, 1000 };
    CAPTURE_FILTER_TARGET target;
    CAPTURE_FILTER_IDENTITY identity;
    memset(&target, 0, sizeof(target));
    memset(&identity, 0, sizeof(identity));

    target.scope = CAPTURE_FILTER_SCOPE_BOX;
    target.session_id = 7;
    target.initial_processes = &initial;
    target.initial_process_count = 1;
    wcscpy_s(target.box_name, BOXNAME_COUNT, L"BoxA");
    wcscpy_s(target.sid_string, 96, L"S-1-5-21-100");

    identity.process_id = 10;
    identity.process_create_time = 1000;
    identity.session_id = 7;
    SetIdentityText(&identity, L"BoxA", L"S-1-5-21-100");
    if (!Require(CaptureFilter_Matches(&target, &identity),
                 "initial process is accepted"))
        return 0;

    identity.process_create_time = 2000;
    if (!Require(!CaptureFilter_Matches(&target, &identity),
                 "reused PID is rejected"))
        return 0;

    identity.process_id = 20;
    identity.process_create_time = 3000;
    if (!Require(!CaptureFilter_Matches(&target, &identity),
                 "later child is rejected without future flag"))
        return 0;

    target.flags = CAPTURE_FILTER_FLAG_INCLUDE_FUTURE;
    return Require(CaptureFilter_Matches(&target, &identity),
                   "later child is accepted with future flag");
}


static int TestFilterHonorsProcessScopeAndLoopback(void)
{
    CAPTURE_FILTER_TARGET target;
    CAPTURE_FILTER_IDENTITY identity;
    memset(&target, 0, sizeof(target));
    memset(&identity, 0, sizeof(identity));

    target.scope = CAPTURE_FILTER_SCOPE_PROCESS;
    target.process_id = 10;
    target.process_create_time = 1000;
    target.session_id = 7;
    wcscpy_s(target.box_name, BOXNAME_COUNT, L"BoxA");
    wcscpy_s(target.sid_string, 96, L"S-1-5-21-100");

    identity.process_id = 10;
    identity.process_create_time = 1000;
    identity.session_id = 7;
    identity.loopback = TRUE;
    SetIdentityText(&identity, L"BoxA", L"S-1-5-21-100");

    if (!Require(!CaptureFilter_Matches(&target, &identity),
                 "loopback is excluded by default"))
        return 0;

    target.flags = CAPTURE_FILTER_FLAG_INCLUDE_LOOPBACK;
    if (!Require(CaptureFilter_Matches(&target, &identity),
                 "loopback opt-in is honored"))
        return 0;

    identity.process_create_time = 1001;
    return Require(!CaptureFilter_Matches(&target, &identity),
                   "process scope binds creation time");
}


static CAPTURE_PACKET_RECORD MakePacketRecord(
    ULONG processId, ULONG originalLength, ULONG capturedLength)
{
    CAPTURE_PACKET_RECORD record;
    memset(&record, 0, sizeof(record));
    record.process_id = processId;
    record.original_length = originalLength;
    record.captured_length = capturedLength;
    record.layer = CAPTURE_PACKET_LAYER_TRANSPORT;
    record.direction = CAPTURE_PACKET_DIRECTION_OUTBOUND;
    if (capturedLength > CAPTURE_PACKET_SNAPLEN_MAX)
        capturedLength = CAPTURE_PACKET_SNAPLEN_MAX;
    for (ULONG i = 0; i < capturedLength; ++i)
        record.data[i] = (UCHAR)(i + processId);
    return record;
}


static int TestPacketQueuePreservesOrderAndClampsSnaplen(void)
{
    CAPTURE_PACKET_QUEUE *queue = CapturePacketQueue_Create(3, TestAlloc);
    if (! Require(queue != NULL, "packet queue allocation"))
        return 0;

    CAPTURE_PACKET_RECORD first = MakePacketRecord(10, 40, 40);
    CAPTURE_PACKET_RECORD second = MakePacketRecord(
        20, 2000, 2000);
    if (! Require(CapturePacketQueue_Push(queue, &first), "push first packet") ||
            ! Require(CapturePacketQueue_Push(queue, &second),
                      "push oversized packet")) {
        CapturePacketQueue_Destroy(queue, TestFree);
        return 0;
    }

    CAPTURE_PACKET_RECORD output[3];
    memset(output, 0, sizeof(output));
    ULONG64 next = 0, oldest = 0, newest = 0, dropped = 0;
    ULONG remaining = 99;
    ULONG count = CapturePacketQueue_Drain(
        queue, output, 3, &next, &oldest, &newest, &dropped, &remaining);

    int ok = Require(count == 2, "packet drain count") &&
        Require(output[0].process_id == 10, "first packet pid") &&
        Require(output[0].sequence == 1, "first packet sequence") &&
        Require(output[1].process_id == 20, "second packet pid") &&
        Require(output[1].captured_length == CAPTURE_PACKET_SNAPLEN_MAX,
                "snaplen clamp") &&
        Require(output[1].original_length == 2000, "original length kept") &&
        Require(output[1].data[0] == (UCHAR)20, "clamped payload prefix") &&
        Require(dropped == 0, "no drops yet") &&
        Require(remaining == 0, "packet queue empty after drain");

    CapturePacketQueue_Destroy(queue, TestFree);
    return ok;
}


static int TestPacketQueueOverwriteIsBoundedAndCounted(void)
{
    CAPTURE_PACKET_QUEUE *queue = CapturePacketQueue_Create(2, TestAlloc);
    if (! Require(queue != NULL, "packet queue overflow allocation"))
        return 0;

    CAPTURE_PACKET_RECORD record = MakePacketRecord(1, 8, 8);
    CapturePacketQueue_Push(queue, &record);
    record = MakePacketRecord(2, 8, 8);
    CapturePacketQueue_Push(queue, &record);
    record = MakePacketRecord(3, 8, 8);
    CapturePacketQueue_Push(queue, &record);

    CAPTURE_PACKET_RECORD output[2];
    memset(output, 0, sizeof(output));
    ULONG64 dropped = 0;
    ULONG remaining = 0;
    ULONG count = CapturePacketQueue_Drain(
        queue, output, 2, NULL, NULL, NULL, &dropped, &remaining);

    int ok = Require(count == 2, "overflow retains capacity") &&
        Require(output[0].process_id == 2, "oldest packet overwritten") &&
        Require(output[1].process_id == 3, "newest packet retained") &&
        Require(dropped == 1, "overflow increments drop counter");

    CapturePacketQueue_Destroy(queue, TestFree);
    return ok;
}


static int TestStreamQueueUsesIndependentRecords(void)
{
    CAPTURE_STREAM_QUEUE *queue = CaptureStreamQueue_Create(1, TestAlloc);
    if (! Require(queue != NULL, "stream queue allocation"))
        return 0;

    CAPTURE_STREAM_RECORD record;
    memset(&record, 0, sizeof(record));
    record.layer = CAPTURE_PACKET_LAYER_STREAM;
    record.original_length = 16;
    record.captured_length = 16;
    memcpy(record.data, "abcdefghijklmnop", 16);

    if (! Require(CaptureStreamQueue_Push(queue, &record), "push stream")) {
        CaptureStreamQueue_Destroy(queue, TestFree);
        return 0;
    }

    CAPTURE_STREAM_RECORD output;
    memset(&output, 0, sizeof(output));
    ULONG count = CaptureStreamQueue_Drain(
        queue, &output, 1, NULL, NULL, NULL, NULL, NULL);
    int ok = Require(count == 1, "stream drain count") &&
        Require(output.layer == CAPTURE_PACKET_LAYER_STREAM, "stream layer") &&
        Require(memcmp(output.data, "abcdefghijklmnop", 16) == 0,
                "stream payload");

    CaptureStreamQueue_Destroy(queue, TestFree);
    return ok;
}


int main(void)
{
    if (!TestPreservesOrderAndAssignsSequence() ||
            !TestOverwriteIsBoundedAndCounted() ||
            !TestDrainBatchLimit() ||
            !TestResetClearsRetentionButKeepsMonotonicCursor() ||
            !TestSequenceWrapStartsNewBoundedEpoch() ||
            !TestIpv4HostOrderEncodingProducesNetworkBytes() ||
            !TestFilterSeparatesBoxSidAndSession() ||
            !TestFilterRejectsPidReuseAndHonorsFutureFlag() ||
            !TestFilterHonorsProcessScopeAndLoopback() ||
            !TestPacketQueuePreservesOrderAndClampsSnaplen() ||
            !TestPacketQueueOverwriteIsBoundedAndCounted() ||
            !TestStreamQueueUsesIndependentRecords()) {
        return 1;
    }

    printf("capture_queue tests passed\n");
    return 0;
}
