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

#include "http2.h"

#include <string.h>


//---------------------------------------------------------------------------
// Frame header (RFC 7540 4.1)
//---------------------------------------------------------------------------

int Http2_ParseFrameHeader(
    const UCHAR *data,
    ULONG size,
    HTTP2_FRAME_HEADER *out)
{
    if (! data || ! out)
        return HTTP2_ERROR;
    if (size < HTTP2_FRAME_HEADER_LEN)
        return HTTP2_NEED_MORE;
    if (data[5] & 0x80)
        return HTTP2_ERROR;   /* reserved bit must be zero */
    out->length = ((ULONG)data[0] << 16) | ((ULONG)data[1] << 8) | data[2];
    out->type = data[3];
    out->flags = data[4];
    out->stream_id = ((ULONG)(data[5] & 0x7f) << 24) |
                     ((ULONG)data[6] << 16) |
                     ((ULONG)data[7] << 8) |
                     data[8];
    return HTTP2_OK;
}


int Http2_WriteFrameHeader(
    UCHAR *out,
    ULONG out_capacity,
    const HTTP2_FRAME_HEADER *header)
{
    if (! out || ! header || out_capacity < HTTP2_FRAME_HEADER_LEN)
        return HTTP2_ERROR;
    if (header->length > 0xffffff || (header->stream_id & 0x80000000ul))
        return HTTP2_ERROR;
    out[0] = (UCHAR)(header->length >> 16);
    out[1] = (UCHAR)(header->length >> 8);
    out[2] = (UCHAR)header->length;
    out[3] = header->type;
    out[4] = header->flags;
    out[5] = (UCHAR)(header->stream_id >> 24);
    out[6] = (UCHAR)(header->stream_id >> 16);
    out[7] = (UCHAR)(header->stream_id >> 8);
    out[8] = (UCHAR)header->stream_id;
    return HTTP2_OK;
}


//---------------------------------------------------------------------------
// Payload parsers
//---------------------------------------------------------------------------

int Http2_ParseSettings(
    const UCHAR *payload,
    ULONG len,
    HTTP2_SETTINGS *out)
{
    ULONG i;

    if (! payload || ! out)
        return HTTP2_ERROR;
    memset(out, 0, sizeof(*out));
    if (len % 6 != 0)
        return HTTP2_ERROR;
    for (i = 0; i < len; i += 6) {
        USHORT id = (USHORT)((payload[i] << 8) | payload[i + 1]);
        ULONG value = ((ULONG)payload[i + 2] << 24) |
                      ((ULONG)payload[i + 3] << 16) |
                      ((ULONG)payload[i + 4] << 8) |
                      payload[i + 5];
        switch (id) {
        case HTTP2_SETTINGS_HEADER_TABLE_SIZE:
            out->header_table_size = value;
            break;
        case HTTP2_SETTINGS_ENABLE_PUSH:
            if (value > 1)
                return HTTP2_ERROR;
            out->enable_push = value;
            break;
        case HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
            out->max_concurrent_streams = value;
            break;
        case HTTP2_SETTINGS_INITIAL_WINDOW_SIZE:
            if (value > 0x7ffffffful)
                return HTTP2_ERROR;
            out->initial_window_size = value;
            break;
        case HTTP2_SETTINGS_MAX_FRAME_SIZE:
            if (value < 16384 || value > 16777215)
                return HTTP2_ERROR;
            out->max_frame_size = value;
            break;
        case HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE:
            out->max_header_list_size = value;
            break;
        default:
            /* unknown settings id must be ignored */
            break;
        }
    }
    return HTTP2_OK;
}


int Http2_ParseWindowUpdate(
    const UCHAR *payload,
    ULONG len,
    ULONG *increment)
{
    ULONG value;
    if (! payload || ! increment || len != 4)
        return HTTP2_ERROR;
    value = ((ULONG)payload[0] << 24) | ((ULONG)payload[1] << 16) |
            ((ULONG)payload[2] << 8) | payload[3];
    if (value & 0x80000000ul)
        return HTTP2_ERROR;   /* reserved bit */
    if (value == 0)
        return HTTP2_ERROR;   /* zero increment = PROTOCOL_ERROR */
    *increment = value;
    return HTTP2_OK;
}


int Http2_ParseRstStream(
    const UCHAR *payload,
    ULONG len,
    ULONG *error_code)
{
    if (! payload || ! error_code || len != 4)
        return HTTP2_ERROR;
    *error_code = ((ULONG)payload[0] << 24) | ((ULONG)payload[1] << 16) |
                  ((ULONG)payload[2] << 8) | payload[3];
    return HTTP2_OK;
}


int Http2_ParsePing(const UCHAR *payload, ULONG len)
{
    if (! payload || len != 8)
        return HTTP2_ERROR;
    return HTTP2_OK;
}


int Http2_ParseGoAway(
    const UCHAR *payload,
    ULONG len,
    ULONG *last_stream_id,
    ULONG *error_code)
{
    if (! payload || ! last_stream_id || ! error_code || len < 8)
        return HTTP2_ERROR;
    if (payload[0] & 0x80)
        return HTTP2_ERROR;
    *last_stream_id = ((ULONG)(payload[0] & 0x7f) << 24) |
                      ((ULONG)payload[1] << 16) |
                      ((ULONG)payload[2] << 8) |
                      payload[3];
    *error_code = ((ULONG)payload[4] << 24) | ((ULONG)payload[5] << 16) |
                  ((ULONG)payload[6] << 8) | payload[7];
    return HTTP2_OK;
}


//---------------------------------------------------------------------------
// Session + stream table
//---------------------------------------------------------------------------

void Http2_SessionInit(HTTP2_SESSION *session)
{
    if (! session)
        return;
    memset(session, 0, sizeof(*session));
    session->local.header_table_size = HTTP2_DEFAULT_HEADER_TABLE_SIZE;
    session->local.initial_window_size = HTTP2_DEFAULT_INITIAL_WINDOW_SIZE;
    session->local.max_frame_size = HTTP2_DEFAULT_MAX_FRAME_SIZE;
    session->connection_receive_window = HTTP2_DEFAULT_INITIAL_WINDOW_SIZE;
}


HTTP2_STREAM *Http2_GetStream(HTTP2_SESSION *session, ULONG stream_id)
{
    ULONG i;

    if (! session || stream_id == 0)
        return NULL;
    for (i = 0; i < HTTP2_MAX_STREAMS; ++i) {
        if (session->streams[i].in_use &&
                session->streams[i].stream_id == stream_id)
            return &session->streams[i];
    }
    return NULL;
}


static HTTP2_STREAM *Http2_GetOrCreateStream(
    HTTP2_SESSION *session,
    ULONG stream_id)
{
    HTTP2_STREAM *st = Http2_GetStream(session, stream_id);
    ULONG i;

    if (st)
        return st;
    /* new client-initiated stream: must be odd and monotonically increasing */
    if (stream_id <= session->last_stream_id)
        return NULL;
    if ((stream_id & 1) == 0)
        return NULL;
    if (session->stream_count >= HTTP2_MAX_STREAMS)
        return NULL;
    for (i = 0; i < HTTP2_MAX_STREAMS; ++i) {
        if (! session->streams[i].in_use) {
            st = &session->streams[i];
            memset(st, 0, sizeof(*st));
            st->stream_id = stream_id;
            st->state = HTTP2_STATE_IDLE;
            st->in_use = TRUE;
            st->receive_window = (LONG)session->local.initial_window_size;
            session->stream_count++;
            session->last_stream_id = stream_id;
            return st;
        }
    }
    return NULL;
}


int Http2_ApplyPeerSettings(HTTP2_SESSION *session, const HTTP2_SETTINGS *settings)
{
    if (! session || ! settings)
        return HTTP2_ERROR;
    session->peer = *settings;
    return HTTP2_OK;
}


//---------------------------------------------------------------------------
// Frame processing
//---------------------------------------------------------------------------

static int Http2_ProcessHeaderFrame(
    HTTP2_SESSION *session,
    const HTTP2_FRAME_HEADER *header,
    const UCHAR *payload,
    HTTP2_FRAME_RESULT *result)
{
    ULONG offset;
    ULONG frag_len;
    HTTP2_STREAM *st;

    if (header->type == HTTP2_FRAME_HEADERS) {
        if (session->header_block_active)
            return HTTP2_ERROR;   /* non-contiguous header block */

        st = Http2_GetOrCreateStream(session, header->stream_id);
        if (! st)
            return HTTP2_ERROR;
        if (st->state == HTTP2_STATE_CLOSED)
            return HTTP2_ERROR;

        offset = 0;
        frag_len = header->length;
        if (header->flags & HTTP2_FLAG_PADDED) {
            ULONG pad;
            if (header->length < 1)
                return HTTP2_ERROR;
            pad = payload[0];
            if (pad + 1 > header->length)
                return HTTP2_ERROR;
            offset = 1;
            frag_len -= 1 + pad;
        }
        if (header->flags & HTTP2_FLAG_PRIORITY) {
            if (frag_len < 5)
                return HTTP2_ERROR;
            offset += 5;
            frag_len -= 5;
        }
        if (frag_len > HTTP2_MAX_HEADER_BLOCK)
            return HTTP2_ERROR;
        memcpy(session->header_block, payload + offset, frag_len);
        session->header_block_len = frag_len;
        session->header_block_active = TRUE;
        session->header_block_stream_id = header->stream_id;

        if (header->flags & HTTP2_FLAG_END_STREAM) {
            result->end_stream = TRUE;
            st->state = HTTP2_STATE_HALF_CLOSED_REMOTE;
        }
        else if (st->state == HTTP2_STATE_IDLE) {
            st->state = HTTP2_STATE_OPEN;
        }

        if (header->flags & HTTP2_FLAG_END_HEADERS) {
            session->header_block_active = FALSE;
            result->have_header_block = TRUE;
            result->header_block = session->header_block;
            result->header_block_len = session->header_block_len;
        }
        return HTTP2_OK;
    }
    else {   /* CONTINUATION */
        if (! session->header_block_active)
            return HTTP2_ERROR;
        if (header->stream_id != session->header_block_stream_id)
            return HTTP2_ERROR;
        st = Http2_GetStream(session, header->stream_id);
        if (! st || st->state == HTTP2_STATE_CLOSED)
            return HTTP2_ERROR;
        if (header->length > HTTP2_MAX_HEADER_BLOCK - session->header_block_len)
            return HTTP2_ERROR;
        memcpy(session->header_block + session->header_block_len,
               payload, header->length);
        session->header_block_len += header->length;
        if (header->flags & HTTP2_FLAG_END_HEADERS) {
            session->header_block_active = FALSE;
            result->have_header_block = TRUE;
            result->header_block = session->header_block;
            result->header_block_len = session->header_block_len;
        }
        return HTTP2_OK;
    }
}


static int Http2_ProcessDataFrame(
    HTTP2_SESSION *session,
    const HTTP2_FRAME_HEADER *header,
    const UCHAR *payload,
    HTTP2_FRAME_RESULT *result)
{
    ULONG offset = 0;
    ULONG data_len = header->length;
    HTTP2_STREAM *st;

    st = Http2_GetStream(session, header->stream_id);
    if (! st || st->state == HTTP2_STATE_IDLE)
        return HTTP2_ERROR;
    if (st->state == HTTP2_STATE_CLOSED ||
            st->state == HTTP2_STATE_HALF_CLOSED_REMOTE)
        return HTTP2_ERROR;

    if (header->flags & HTTP2_FLAG_PADDED) {
        ULONG pad;
        if (header->length < 1)
            return HTTP2_ERROR;
        pad = payload[0];
        if (pad + 1 > header->length)
            return HTTP2_ERROR;
        offset = 1;
        data_len -= 1 + pad;
    }

    if ((LONG)data_len > st->receive_window ||
            (LONG)data_len > session->connection_receive_window)
        return HTTP2_ERROR;   /* flow-control violation */
    st->receive_window -= (LONG)data_len;
    session->connection_receive_window -= (LONG)data_len;

    result->is_data = TRUE;
    result->data = payload + offset;
    result->data_len = data_len;

    if (header->flags & HTTP2_FLAG_END_STREAM) {
        result->end_stream = TRUE;
        st->state = (st->state == HTTP2_STATE_HALF_CLOSED_LOCAL)
            ? HTTP2_STATE_CLOSED
            : HTTP2_STATE_HALF_CLOSED_REMOTE;
    }
    return HTTP2_OK;
}


int Http2_ProcessFrame(
    HTTP2_SESSION *session,
    const HTTP2_FRAME_HEADER *header,
    const UCHAR *payload,
    HTTP2_FRAME_RESULT *result)
{
    if (! session || ! header || ! result)
        return HTTP2_ERROR;
    memset(result, 0, sizeof(*result));
    result->stream_id = header->stream_id;

    /* RFC 7540 6.2: a HEADERS frame without END_HEADERS must be followed
       immediately by a CONTINUATION frame on the same stream. */
    if (session->header_block_active &&
            (header->type != HTTP2_FRAME_CONTINUATION ||
             header->stream_id != session->header_block_stream_id))
        return HTTP2_ERROR;

    switch (header->type) {
    case HTTP2_FRAME_SETTINGS:
        if (header->stream_id != 0)
            return HTTP2_ERROR;
        if (header->flags & HTTP2_FLAG_ACK) {
            if (header->length != 0)
                return HTTP2_ERROR;
            return HTTP2_OK;
        }
        {
            HTTP2_SETTINGS s;
            if (Http2_ParseSettings(payload, header->length, &s) != HTTP2_OK)
                return HTTP2_ERROR;
            return Http2_ApplyPeerSettings(session, &s);
        }

    case HTTP2_FRAME_PING:
        if (header->stream_id != 0 || header->length != 8)
            return HTTP2_ERROR;
        return HTTP2_OK;

    case HTTP2_FRAME_GOAWAY:
        if (header->stream_id != 0)
            return HTTP2_ERROR;
        {
            ULONG last_stream_id = 0;
            ULONG error_code = 0;
            if (Http2_ParseGoAway(payload, header->length,
                    &last_stream_id, &error_code) != HTTP2_OK)
                return HTTP2_ERROR;
            session->goaway_received = TRUE;
            return HTTP2_OK;
        }

    case HTTP2_FRAME_WINDOW_UPDATE:
        {
            ULONG increment = 0;
            if (Http2_ParseWindowUpdate(payload, header->length,
                    &increment) != HTTP2_OK)
                return HTTP2_ERROR;
            if (header->stream_id == 0) {
                session->connection_receive_window += (LONG)increment;
                if (session->connection_receive_window > 0x7fffffffl)
                    return HTTP2_ERROR;
            }
            else {
                HTTP2_STREAM *st = Http2_GetStream(session, header->stream_id);
                if (! st || st->state == HTTP2_STATE_IDLE ||
                        st->state == HTTP2_STATE_CLOSED)
                    return HTTP2_ERROR;
                st->receive_window += (LONG)increment;
                if (st->receive_window > 0x7fffffffl)
                    return HTTP2_ERROR;
            }
            return HTTP2_OK;
        }

    case HTTP2_FRAME_RST_STREAM:
        if (header->stream_id == 0 || header->length != 4)
            return HTTP2_ERROR;
        {
            HTTP2_STREAM *st = Http2_GetStream(session, header->stream_id);
            if (! st || st->state == HTTP2_STATE_IDLE)
                return HTTP2_ERROR;
            if (st->state == HTTP2_STATE_CLOSED)
                return HTTP2_OK;   /* RST on closed stream is ignored */
            st->state = HTTP2_STATE_CLOSED;
            return HTTP2_OK;
        }

    case HTTP2_FRAME_HEADERS:
    case HTTP2_FRAME_CONTINUATION:
        if (header->stream_id == 0)
            return HTTP2_ERROR;
        return Http2_ProcessHeaderFrame(session, header, payload, result);

    case HTTP2_FRAME_DATA:
        if (header->stream_id == 0)
            return HTTP2_ERROR;
        return Http2_ProcessDataFrame(session, header, payload, result);

    case HTTP2_FRAME_PRIORITY:
        if (header->stream_id == 0 || header->length != 5)
            return HTTP2_ERROR;
        {
            HTTP2_STREAM *st = Http2_GetStream(session, header->stream_id);
            if (! st || st->state == HTTP2_STATE_IDLE ||
                    st->state == HTTP2_STATE_CLOSED)
                return HTTP2_ERROR;
            return HTTP2_OK;
        }

    case HTTP2_FRAME_PUSH_PROMISE:
        /* a client must never send PUSH_PROMISE to a server */
        return HTTP2_ERROR;

    default:
        return HTTP2_ERROR;
    }
}
