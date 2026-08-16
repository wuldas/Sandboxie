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
// HTTP/2 frame codec tests
//---------------------------------------------------------------------------

#include "../SbieCapture/http2.h"

#include <stdio.h>
#include <string.h>


static int g_failures = 0;
static int g_checks = 0;


static int Require(int condition, const char *message)
{
    ++g_checks;
    if (! condition) {
        ++g_failures;
        fprintf(stderr, "FAIL: %s\n", message);
    }
    return condition;
}


/* build a frame (9-byte header + payload) into out; returns total length */
static ULONG MakeFrame(
    UCHAR *out,
    UCHAR type,
    UCHAR flags,
    ULONG stream_id,
    const UCHAR *payload,
    ULONG payload_len)
{
    out[0] = (UCHAR)(payload_len >> 16);
    out[1] = (UCHAR)(payload_len >> 8);
    out[2] = (UCHAR)payload_len;
    out[3] = type;
    out[4] = flags;
    out[5] = (UCHAR)(stream_id >> 24);
    out[6] = (UCHAR)(stream_id >> 16);
    out[7] = (UCHAR)(stream_id >> 8);
    out[8] = (UCHAR)stream_id;
    if (payload && payload_len)
        memcpy(out + 9, payload, payload_len);
    return 9 + payload_len;
}


/* parse + process a full frame; returns HTTP2_OK/ERROR */
static int Feed(HTTP2_SESSION *session, const UCHAR *frame, ULONG frame_len,
                HTTP2_FRAME_RESULT *result)
{
    HTTP2_FRAME_HEADER h;
    if (Http2_ParseFrameHeader(frame, frame_len, &h) != HTTP2_OK)
        return HTTP2_ERROR;
    if (frame_len < 9 + h.length)
        return HTTP2_ERROR;
    return Http2_ProcessFrame(session, &h, frame + 9, result);
}


static void TestFrameHeader(void)
{
    UCHAR raw[9];
    UCHAR out[9];
    HTTP2_FRAME_HEADER h;
    HTTP2_FRAME_HEADER back;

    memset(&h, 0, sizeof(h));
    h.length = 0x010203;
    h.type = HTTP2_FRAME_HEADERS;
    h.flags = HTTP2_FLAG_END_HEADERS;
    h.stream_id = 0x7fffffff;
    Require(Http2_WriteFrameHeader(out, sizeof(out), &h) == HTTP2_OK,
            "write frame header");
    Require(Http2_ParseFrameHeader(out, sizeof(out), &back) == HTTP2_OK,
            "parse frame header");
    Require(back.length == 0x010203 && back.type == HTTP2_FRAME_HEADERS &&
            back.flags == HTTP2_FLAG_END_HEADERS &&
            back.stream_id == 0x7fffffff, "frame header round-trip");

    /* reserved bit set -> error */
    memcpy(raw, out, 9);
    raw[5] |= 0x80;
    Require(Http2_ParseFrameHeader(raw, sizeof(raw), &back) == HTTP2_ERROR,
            "reserved bit rejected");

    /* truncated header -> need more */
    Require(Http2_ParseFrameHeader(out, 8, &back) == HTTP2_NEED_MORE,
            "short header needs more");

    /* length > 24 bits rejected on write */
    h.length = 0x01000000;
    Require(Http2_WriteFrameHeader(out, sizeof(out), &h) == HTTP2_ERROR,
            "oversize length rejected");
}


static void TestSettings(void)
{
    UCHAR payload[24];
    HTTP2_SETTINGS s;
    ULONG inc = 0;

    /* header_table_size=4096, initial_window_size=65535 */
    memset(payload, 0, sizeof(payload));
    payload[0] = 0x00; payload[1] = 0x01;                 /* HEADER_TABLE_SIZE */
    payload[2] = 0x00; payload[3] = 0x00;
    payload[4] = 0x10; payload[5] = 0x00;                 /* 4096 */
    payload[6] = 0x00; payload[7] = 0x04;                 /* INITIAL_WINDOW_SIZE */
    payload[8] = 0x00; payload[9] = 0x00;
    payload[10] = 0xff; payload[11] = 0xff;               /* 65535 */
    Require(Http2_ParseSettings(payload, 12, &s) == HTTP2_OK, "parse settings");
    Require(s.header_table_size == 4096 && s.initial_window_size == 65535,
            "settings values");

    /* unknown id (0x42) must be ignored */
    payload[0] = 0x00; payload[1] = 0x42;
    payload[2] = 0; payload[3] = 0; payload[4] = 0; payload[5] = 0;
    Require(Http2_ParseSettings(payload, 6, &s) == HTTP2_OK,
            "unknown settings id ignored");

    /* ENABLE_PUSH = 2 -> error */
    payload[0] = 0x00; payload[1] = 0x02;
    payload[2] = 0; payload[3] = 0; payload[4] = 0; payload[5] = 0x02;
    Require(Http2_ParseSettings(payload, 6, &s) == HTTP2_ERROR,
            "enable_push > 1 rejected");

    /* INITIAL_WINDOW_SIZE > 2^31-1 -> error */
    payload[0] = 0x00; payload[1] = 0x04;
    payload[2] = 0x80; payload[3] = 0; payload[4] = 0; payload[5] = 0;
    Require(Http2_ParseSettings(payload, 6, &s) == HTTP2_ERROR,
            "oversize initial window rejected");

    /* MAX_FRAME_SIZE < 16384 -> error */
    payload[0] = 0x00; payload[1] = 0x05;
    payload[2] = 0; payload[3] = 0; payload[4] = 0x3f; payload[5] = 0xff; /* 16383 */
    Require(Http2_ParseSettings(payload, 6, &s) == HTTP2_ERROR,
            "small max frame size rejected");

    /* WINDOW_UPDATE: valid */
    payload[0] = 0; payload[1] = 0; payload[2] = 0; payload[3] = 100;
    Require(Http2_ParseWindowUpdate(payload, 4, &inc) == HTTP2_OK &&
            inc == 100, "window update valid");

    /* WINDOW_UPDATE: reserved bit */
    payload[0] = 0x80; payload[1] = 0; payload[2] = 0; payload[3] = 1;
    Require(Http2_ParseWindowUpdate(payload, 4, &inc) == HTTP2_ERROR,
            "window update reserved bit rejected");

    /* WINDOW_UPDATE: zero */
    payload[0] = 0; payload[1] = 0; payload[2] = 0; payload[3] = 0;
    Require(Http2_ParseWindowUpdate(payload, 4, &inc) == HTTP2_ERROR,
            "window update zero rejected");

    /* PING: length must be 8 */
    Require(Http2_ParsePing(payload, 8) == HTTP2_OK, "ping valid");
    Require(Http2_ParsePing(payload, 4) == HTTP2_ERROR, "ping wrong length");

    /* GOAWAY */
    {
        ULONG lsid = 0, ec = 0;
        payload[0] = 0x00; payload[1] = 0x00; payload[2] = 0x00; payload[3] = 0x03;
        payload[4] = 0x00; payload[5] = 0x00; payload[6] = 0x00; payload[7] = 0x00;
        Require(Http2_ParseGoAway(payload, 8, &lsid, &ec) == HTTP2_OK &&
                lsid == 3 && ec == 0, "goaway valid");
    }

    /* RST_STREAM */
    {
        ULONG ec = 0;
        payload[0] = 0; payload[1] = 0; payload[2] = 0; payload[3] = HTTP2_CANCEL;
        Require(Http2_ParseRstStream(payload, 4, &ec) == HTTP2_OK &&
                ec == HTTP2_CANCEL, "rst stream valid");
    }
}


static void TestHeaderReassembly(void)
{
    HTTP2_SESSION s;
    HTTP2_FRAME_RESULT r;
    UCHAR frame[128];
    ULONG flen;
    UCHAR fragA[] = { 'A', 'A', 'A' };
    UCHAR fragB[] = { 'B', 'B', 'B' };

    Http2_SessionInit(&s);

    /* HEADERS on stream 1 without END_HEADERS */
    flen = MakeFrame(frame, HTTP2_FRAME_HEADERS, 0, 1, fragA, 3);
    Require(Feed(&s, frame, flen, &r) == HTTP2_OK, "headers frame");
    Require(! r.have_header_block, "headers no end -> no block yet");
    Require(s.header_block_active, "header block active");

    /* CONTINUATION with END_HEADERS */
    flen = MakeFrame(frame, HTTP2_FRAME_CONTINUATION, HTTP2_FLAG_END_HEADERS, 1,
                     fragB, 3);
    Require(Feed(&s, frame, flen, &r) == HTTP2_OK, "continuation frame");
    Require(r.have_header_block, "continuation completes block");
    Require(r.header_block_len == 6 &&
            memcmp(r.header_block, "AAABBB", 6) == 0, "reassembled block");
    Require(! s.header_block_active, "header block done");
}


static void TestHeadersPaddedPriority(void)
{
    HTTP2_SESSION s;
    HTTP2_FRAME_RESULT r;
    UCHAR frame[128];
    UCHAR payload[16];
    ULONG flen;

    Http2_SessionInit(&s);

    /* PADDED + PRIORITY: [pad=2][dep=0 (4B)][weight=0][frag "XY"][2 pad bytes] */
    payload[0] = 2;                    /* pad length */
    payload[1] = 0; payload[2] = 0;    /* stream dependency (top 2 bytes of 4) */
    payload[3] = 0; payload[4] = 0;    /* stream dependency (low 2 bytes) */
    payload[5] = 0;                    /* weight */
    payload[6] = 'X'; payload[7] = 'Y';
    payload[8] = 0; payload[9] = 0;    /* padding */
    flen = MakeFrame(frame, HTTP2_FRAME_HEADERS,
                     HTTP2_FLAG_PADDED | HTTP2_FLAG_PRIORITY | HTTP2_FLAG_END_HEADERS,
                     1, payload, 10);
    Require(Feed(&s, frame, flen, &r) == HTTP2_OK, "padded+priority headers");
    Require(r.have_header_block && r.header_block_len == 2 &&
            memcmp(r.header_block, "XY", 2) == 0, "padded+priority fragment");
}


static void TestDataAndStreamState(void)
{
    HTTP2_SESSION s;
    HTTP2_FRAME_RESULT r;
    UCHAR frame[128];
    UCHAR frag[] = { 0x82 };   /* HPACK: :method GET */
    UCHAR data[] = { 'h', 'e', 'l', 'l', 'o' };
    HTTP2_STREAM *st;
    ULONG flen;

    Http2_SessionInit(&s);

    /* HEADERS stream 1, END_HEADERS, END_STREAM -> half-closed remote */
    flen = MakeFrame(frame, HTTP2_FRAME_HEADERS,
                     HTTP2_FLAG_END_HEADERS | HTTP2_FLAG_END_STREAM, 1, frag, 1);
    Require(Feed(&s, frame, flen, &r) == HTTP2_OK, "headers end_stream");
    Require(r.end_stream && r.have_header_block, "headers end_stream result");
    st = Http2_GetStream(&s, 1);
    Require(st && st->state == HTTP2_STATE_HALF_CLOSED_REMOTE,
            "stream half-closed remote");

    /* DATA on half-closed-remote stream -> error (we already got END_STREAM) */
    flen = MakeFrame(frame, HTTP2_FRAME_DATA, HTTP2_FLAG_END_STREAM, 1, data, 5);
    Require(Feed(&s, frame, flen, &r) == HTTP2_ERROR, "data on half-closed rejected");

    /* new session: DATA on open stream */
    Http2_SessionInit(&s);
    flen = MakeFrame(frame, HTTP2_FRAME_HEADERS, HTTP2_FLAG_END_HEADERS, 3, frag, 1);
    Require(Feed(&s, frame, flen, &r) == HTTP2_OK, "headers open stream 3");
    st = Http2_GetStream(&s, 3);
    Require(st && st->state == HTTP2_STATE_OPEN, "stream open");

    flen = MakeFrame(frame, HTTP2_FRAME_DATA, HTTP2_FLAG_END_STREAM, 3, data, 5);
    Require(Feed(&s, frame, flen, &r) == HTTP2_OK, "data on open stream");
    Require(r.is_data && r.data_len == 5 && memcmp(r.data, "hello", 5) == 0,
            "data payload");
    Require(r.end_stream, "data end stream");
    Require(st->state == HTTP2_STATE_HALF_CLOSED_REMOTE, "data closes remote");

    /* DATA with padding */
    Http2_SessionInit(&s);
    flen = MakeFrame(frame, HTTP2_FRAME_HEADERS, HTTP2_FLAG_END_HEADERS, 5, frag, 1);
    Require(Feed(&s, frame, flen, &r) == HTTP2_OK, "headers for padded data");
    {
        UCHAR pdata[8];
        pdata[0] = 2;                        /* pad length */
        pdata[1] = 'a'; pdata[2] = 'b';      /* data */
        pdata[3] = 'c';
        pdata[4] = 0; pdata[5] = 0;          /* padding */
        flen = MakeFrame(frame, HTTP2_FRAME_DATA, HTTP2_FLAG_PADDED, 5, pdata, 6);
        Require(Feed(&s, frame, flen, &r) == HTTP2_OK, "padded data");
        Require(r.is_data && r.data_len == 3 && memcmp(r.data, "abc", 3) == 0,
                "padded data payload");
    }

    /* RST_STREAM closes stream */
    {
        UCHAR rst[4] = { 0, 0, 0, HTTP2_CANCEL };
        flen = MakeFrame(frame, HTTP2_FRAME_RST_STREAM, 0, 5, rst, 4);
        Require(Feed(&s, frame, flen, &r) == HTTP2_OK, "rst stream");
        st = Http2_GetStream(&s, 5);
        Require(st && st->state == HTTP2_STATE_CLOSED, "stream closed by rst");
    }
}


static void TestFlowControl(void)
{
    HTTP2_SESSION s;
    HTTP2_FRAME_RESULT r;
    UCHAR frame[128];
    UCHAR frag[] = { 0x82 };
    UCHAR data[16];
    UCHAR wu[4];
    HTTP2_STREAM *st;
    ULONG flen;

    Http2_SessionInit(&s);
    s.local.initial_window_size = 10;
    s.connection_receive_window = 10;

    flen = MakeFrame(frame, HTTP2_FRAME_HEADERS, HTTP2_FLAG_END_HEADERS, 1, frag, 1);
    Require(Feed(&s, frame, flen, &r) == HTTP2_OK, "fc headers");
    st = Http2_GetStream(&s, 1);
    Require(st && st->receive_window == 10, "stream window initial");

    memset(data, 'x', sizeof(data));
    /* DATA of 11 bytes exceeds window 10 -> flow control error */
    flen = MakeFrame(frame, HTTP2_FRAME_DATA, 0, 1, data, 11);
    Require(Feed(&s, frame, flen, &r) == HTTP2_ERROR, "data over window rejected");

    /* DATA of 6 bytes ok, window -> 4 */
    flen = MakeFrame(frame, HTTP2_FRAME_DATA, 0, 1, data, 6);
    Require(Feed(&s, frame, flen, &r) == HTTP2_OK, "data within window");
    Require(st->receive_window == 4, "stream window decremented");
    Require(s.connection_receive_window == 4, "connection window decremented");

    /* WINDOW_UPDATE +10 -> window 14 */
    wu[0] = 0; wu[1] = 0; wu[2] = 0; wu[3] = 10;
    flen = MakeFrame(frame, HTTP2_FRAME_WINDOW_UPDATE, 0, 1, wu, 4);
    Require(Feed(&s, frame, flen, &r) == HTTP2_OK, "window update");
    Require(st->receive_window == 14, "stream window incremented");
}


static void TestMalformed(void)
{
    HTTP2_SESSION s;
    HTTP2_FRAME_RESULT r;
    UCHAR frame[128];
    UCHAR frag[] = { 0x82 };
    UCHAR data[] = { 1, 2, 3 };
    ULONG flen;

    /* SETTINGS on non-zero stream */
    Http2_SessionInit(&s);
    flen = MakeFrame(frame, HTTP2_FRAME_SETTINGS, 0, 1, frag, 0);
    Require(Feed(&s, frame, flen, &r) == HTTP2_ERROR, "settings on stream rejected");

    /* CONTINUATION without preceding HEADERS */
    Http2_SessionInit(&s);
    flen = MakeFrame(frame, HTTP2_FRAME_CONTINUATION, HTTP2_FLAG_END_HEADERS, 1, frag, 1);
    Require(Feed(&s, frame, flen, &r) == HTTP2_ERROR,
            "continuation without headers rejected");

    /* non-contiguous: HEADERS (no END_HEADERS) then DATA on other stream */
    Http2_SessionInit(&s);
    flen = MakeFrame(frame, HTTP2_FRAME_HEADERS, 0, 1, frag, 1);
    Require(Feed(&s, frame, flen, &r) == HTTP2_OK, "headers no end_headers");
    flen = MakeFrame(frame, HTTP2_FRAME_DATA, 0, 3, data, 3);
    Require(Feed(&s, frame, flen, &r) == HTTP2_ERROR,
            "frame during header block rejected");

    /* DATA on idle stream */
    Http2_SessionInit(&s);
    flen = MakeFrame(frame, HTTP2_FRAME_DATA, 0, 1, data, 3);
    Require(Feed(&s, frame, flen, &r) == HTTP2_ERROR, "data on idle stream rejected");

    /* PUSH_PROMISE from client */
    Http2_SessionInit(&s);
    flen = MakeFrame(frame, HTTP2_FRAME_PUSH_PROMISE, 0, 1, frag, 1);
    Require(Feed(&s, frame, flen, &r) == HTTP2_ERROR, "push promise from client rejected");

    /* even stream id (server-initiated) from client */
    Http2_SessionInit(&s);
    flen = MakeFrame(frame, HTTP2_FRAME_HEADERS, HTTP2_FLAG_END_HEADERS, 2, frag, 1);
    Require(Feed(&s, frame, flen, &r) == HTTP2_ERROR, "even stream id rejected");
}


int main(void)
{
    TestFrameHeader();
    TestSettings();
    TestHeaderReassembly();
    TestHeadersPaddedPriority();
    TestDataAndStreamState();
    TestFlowControl();
    TestMalformed();

    if (g_failures == 0) {
        printf("http2 tests passed (%d checks)\n", g_checks);
        return 0;
    }
    fprintf(stderr, "http2 tests FAILED: %d/%d checks failed\n",
            g_failures, g_checks);
    return 1;
}
