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
// HTTP/2 (RFC 7540) frame codec + per-connection stream table
//---------------------------------------------------------------------------

#ifndef _MY_HTTP2_H
#define _MY_HTTP2_H

#include <windows.h>

#define HTTP2_OK                    0
#define HTTP2_ERROR                (-1)
#define HTTP2_NEED_MORE             1

#define HTTP2_FRAME_HEADER_LEN      9
#define HTTP2_MAX_HEADER_BLOCK      65536
#define HTTP2_MAX_STREAMS           256

/* frame types */
#define HTTP2_FRAME_DATA            0x0
#define HTTP2_FRAME_HEADERS         0x1
#define HTTP2_FRAME_PRIORITY        0x2
#define HTTP2_FRAME_RST_STREAM      0x3
#define HTTP2_FRAME_SETTINGS        0x4
#define HTTP2_FRAME_PUSH_PROMISE    0x5
#define HTTP2_FRAME_PING            0x6
#define HTTP2_FRAME_GOAWAY          0x7
#define HTTP2_FRAME_WINDOW_UPDATE   0x8
#define HTTP2_FRAME_CONTINUATION    0x9

/* flags */
#define HTTP2_FLAG_END_STREAM       0x1
#define HTTP2_FLAG_ACK              0x1
#define HTTP2_FLAG_END_HEADERS      0x4
#define HTTP2_FLAG_PADDED           0x8
#define HTTP2_FLAG_PRIORITY         0x20

/* error codes */
#define HTTP2_NO_ERROR              0x0
#define HTTP2_PROTOCOL_ERROR        0x1
#define HTTP2_INTERNAL_ERROR        0x2
#define HTTP2_FLOW_CONTROL_ERROR    0x3
#define HTTP2_STREAM_CLOSED         0x5
#define HTTP2_FRAME_SIZE_ERROR      0x6
#define HTTP2_REFUSED_STREAM        0x7
#define HTTP2_CANCEL                0x8
#define HTTP2_COMPRESSION_ERROR     0x9
#define HTTP2_HTTP_1_1_REQUIRED     0xd

/* settings identifiers */
#define HTTP2_SETTINGS_HEADER_TABLE_SIZE      0x1
#define HTTP2_SETTINGS_ENABLE_PUSH            0x2
#define HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS 0x3
#define HTTP2_SETTINGS_INITIAL_WINDOW_SIZE    0x4
#define HTTP2_SETTINGS_MAX_FRAME_SIZE         0x5
#define HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE   0x6

#define HTTP2_DEFAULT_INITIAL_WINDOW_SIZE     65535
#define HTTP2_DEFAULT_MAX_FRAME_SIZE          16384
#define HTTP2_DEFAULT_HEADER_TABLE_SIZE       4096

typedef enum _HTTP2_STREAM_STATE {
    HTTP2_STATE_IDLE = 0,
    HTTP2_STATE_RESERVED_LOCAL,
    HTTP2_STATE_RESERVED_REMOTE,
    HTTP2_STATE_OPEN,
    HTTP2_STATE_HALF_CLOSED_LOCAL,
    HTTP2_STATE_HALF_CLOSED_REMOTE,
    HTTP2_STATE_CLOSED
} HTTP2_STREAM_STATE;

typedef struct _HTTP2_FRAME_HEADER {

    ULONG length;      /* 24-bit payload length */
    UCHAR type;
    UCHAR flags;
    ULONG stream_id;   /* 31-bit */

} HTTP2_FRAME_HEADER;

typedef struct _HTTP2_SETTINGS {

    ULONG header_table_size;
    ULONG enable_push;
    ULONG max_concurrent_streams;
    ULONG initial_window_size;
    ULONG max_frame_size;
    ULONG max_header_list_size;

} HTTP2_SETTINGS;

typedef struct _HTTP2_STREAM {

    ULONG stream_id;
    HTTP2_STREAM_STATE state;
    BOOL in_use;
    LONG receive_window;   /* local receive window remaining for this stream */

} HTTP2_STREAM;

typedef struct _HTTP2_SESSION {

    HTTP2_SETTINGS peer;
    HTTP2_SETTINGS local;
    LONG connection_receive_window;
    HTTP2_STREAM streams[HTTP2_MAX_STREAMS];
    ULONG stream_count;
    ULONG last_stream_id;   /* highest client-initiated stream id seen */
    BOOL goaway_received;
    BOOL header_block_active;
    ULONG header_block_stream_id;
    UCHAR header_block[HTTP2_MAX_HEADER_BLOCK];
    ULONG header_block_len;

} HTTP2_SESSION;

typedef struct _HTTP2_FRAME_RESULT {

    BOOL have_header_block;   /* END_HEADERS seen; complete header block ready */
    const UCHAR *header_block;
    ULONG header_block_len;
    BOOL is_data;             /* this frame carried DATA */
    const UCHAR *data;
    ULONG data_len;
    BOOL end_stream;          /* END_STREAM seen on this frame */
    ULONG stream_id;          /* stream this frame belongs to */

} HTTP2_FRAME_RESULT;

#ifdef __cplusplus
extern "C" {
#endif

int Http2_ParseFrameHeader(
        const UCHAR *data,
        ULONG size,
        HTTP2_FRAME_HEADER *out);

int Http2_WriteFrameHeader(
        UCHAR *out,
        ULONG out_capacity,
        const HTTP2_FRAME_HEADER *header);

int Http2_ParseSettings(
        const UCHAR *payload,
        ULONG len,
        HTTP2_SETTINGS *out);

int Http2_ParseWindowUpdate(
        const UCHAR *payload,
        ULONG len,
        ULONG *increment);

int Http2_ParseRstStream(
        const UCHAR *payload,
        ULONG len,
        ULONG *error_code);

int Http2_ParsePing(const UCHAR *payload, ULONG len);

int Http2_ParseGoAway(
        const UCHAR *payload,
        ULONG len,
        ULONG *last_stream_id,
        ULONG *error_code);

void Http2_SessionInit(HTTP2_SESSION *session);

HTTP2_STREAM *Http2_GetStream(HTTP2_SESSION *session, ULONG stream_id);

int Http2_ApplyPeerSettings(HTTP2_SESSION *session, const HTTP2_SETTINGS *settings);

/* Processes one complete frame (header + payload). Updates session/stream state
   and reassembles HEADERS/CONTINUATION header blocks. result is filled with the
   frame's outcome. Returns HTTP2_OK, HTTP2_ERROR (protocol violation), or
   HTTP2_NEED_MORE. */
int Http2_ProcessFrame(
        HTTP2_SESSION *session,
        const HTTP2_FRAME_HEADER *header,
        const UCHAR *payload,
        HTTP2_FRAME_RESULT *result);

#ifdef __cplusplus
}
#endif

#endif /* _MY_HTTP2_H */
