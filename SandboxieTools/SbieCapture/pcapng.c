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
// PCAPNG writer -- transport records only, no protocol parsing
//---------------------------------------------------------------------------

#include "pcapng.h"

#include <stdio.h>
#include <string.h>

#define PCAPNG_SHB_TYPE                 0x0A0D0D0Au
#define PCAPNG_IDB_TYPE                 0x00000001u
#define PCAPNG_EPB_TYPE                 0x00000006u
#define PCAPNG_BOM_LE                   0x1A2B3C4Du
#define PCAPNG_OPT_END                  0
#define PCAPNG_OPT_COMMENT              1
#define FILETIME_UNIX_EPOCH             116444736000000000ull


struct _PCAPNG_WRITER {

    HANDLE file;
    ULONG snaplen;
    ULONG max_file_bytes;
    ULONG rotate_count;
    ULONG file_index;
    ULONG64 packet_count;
    ULONG64 byte_count;
    ULONG64 file_bytes;
    BOOL stopped;
    WCHAR path[MAX_PATH];

};


static ULONG Pcapng_Pad4(ULONG value)
{
    return (value + 3u) & ~3u;
}


static BOOL Pcapng_WriteRaw(PCAPNG_WRITER *writer, const void *data, ULONG size)
{
    DWORD written = 0;
    if (! writer || writer->file == INVALID_HANDLE_VALUE || writer->stopped)
        return FALSE;
    if (! WriteFile(writer->file, data, size, &written, NULL) || written != size)
        return FALSE;
    writer->file_bytes += size;
    return TRUE;
}


static BOOL Pcapng_WriteU16(PCAPNG_WRITER *writer, USHORT value)
{
    return Pcapng_WriteRaw(writer, &value, sizeof(value));
}


static BOOL Pcapng_WriteU32(PCAPNG_WRITER *writer, ULONG value)
{
    return Pcapng_WriteRaw(writer, &value, sizeof(value));
}


static BOOL Pcapng_WriteU64(PCAPNG_WRITER *writer, ULONG64 value)
{
    return Pcapng_WriteRaw(writer, &value, sizeof(value));
}


static BOOL Pcapng_WritePadding(PCAPNG_WRITER *writer, ULONG size)
{
    UCHAR zeros[4] = { 0, 0, 0, 0 };
    ULONG padded = Pcapng_Pad4(size);
    if (padded == size)
        return TRUE;
    return Pcapng_WriteRaw(writer, zeros, padded - size);
}


static ULONG Pcapng_FormatComment(
    const PCAPNG_PACKET *packet, char *buffer, ULONG capacity)
{
    char boxUtf8[96];
    char sidUtf8[192];
    boxUtf8[0] = 0;
    sidUtf8[0] = 0;
    if (packet->box_name) {
        WideCharToMultiByte(
            CP_UTF8, 0, packet->box_name, -1, boxUtf8, sizeof(boxUtf8),
            NULL, NULL);
        boxUtf8[sizeof(boxUtf8) - 1] = 0;
    }
    if (packet->sid_string) {
        WideCharToMultiByte(
            CP_UTF8, 0, packet->sid_string, -1, sidUtf8, sizeof(sidUtf8),
            NULL, NULL);
        sidUtf8[sizeof(sidUtf8) - 1] = 0;
    }

    int length = _snprintf_s(
        buffer, capacity, _TRUNCATE,
        "pid=%lu createTime=%llu box=%s sid=%s session=%lu",
        (unsigned long)packet->process_id,
        (unsigned long long)packet->process_create_time,
        boxUtf8,
        sidUtf8,
        (unsigned long)packet->session_id);
    if (length < 0)
        return 0;
    return (ULONG)length;
}


static BOOL Pcapng_WriteCommentOption(
    PCAPNG_WRITER *writer, const char *comment, ULONG commentLength)
{
    if (! Pcapng_WriteU16(writer, PCAPNG_OPT_COMMENT) ||
            ! Pcapng_WriteU16(writer, (USHORT)commentLength) ||
            ! Pcapng_WriteRaw(writer, comment, commentLength) ||
            ! Pcapng_WritePadding(writer, commentLength) ||
            ! Pcapng_WriteU16(writer, PCAPNG_OPT_END) ||
            ! Pcapng_WriteU16(writer, 0)) {
        return FALSE;
    }
    return TRUE;
}


static BOOL Pcapng_WriteHeaders(PCAPNG_WRITER *writer)
{
    if (! Pcapng_WriteU32(writer, PCAPNG_SHB_TYPE) ||
            ! Pcapng_WriteU32(writer, 28) ||
            ! Pcapng_WriteU32(writer, PCAPNG_BOM_LE) ||
            ! Pcapng_WriteU16(writer, 1) ||
            ! Pcapng_WriteU16(writer, 0) ||
            ! Pcapng_WriteU64(writer, 0xFFFFFFFFFFFFFFFFull) ||
            ! Pcapng_WriteU32(writer, 28)) {
        return FALSE;
    }

    if (! Pcapng_WriteU32(writer, PCAPNG_IDB_TYPE) ||
            ! Pcapng_WriteU32(writer, 20) ||
            ! Pcapng_WriteU16(writer, PCAPNG_LINKTYPE_RAW) ||
            ! Pcapng_WriteU16(writer, 0) ||
            ! Pcapng_WriteU32(writer, writer->snaplen) ||
            ! Pcapng_WriteU32(writer, 20)) {
        return FALSE;
    }

    return TRUE;
}


static HANDLE Pcapng_CreateFile(const WCHAR *path)
{
    return CreateFileW(
        path,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
}


static BOOL Pcapng_MakeRotatedPath(
    WCHAR *buffer, ULONG capacity, const WCHAR *base, ULONG index)
{
    if (wcscpy_s(buffer, capacity, base) != 0)
        return FALSE;
    if (index == 0)
        return TRUE;

    WCHAR *dot = wcsrchr(buffer, L'.');
    WCHAR *slash = wcsrchr(buffer, L'\\');
    if (! dot || (slash && dot < slash)) {
        return swprintf_s(buffer, capacity, L"%s.%lu.pcapng", base, index) > 0;
    }

    WCHAR suffix[32];
    if (swprintf_s(suffix, ARRAYSIZE(suffix), L".%lu", index) < 0)
        return FALSE;

    WCHAR tail[MAX_PATH];
    if (wcscpy_s(tail, ARRAYSIZE(tail), dot) != 0)
        return FALSE;
    *dot = 0;
    if (wcscat_s(buffer, capacity, suffix) != 0)
        return FALSE;
    return wcscat_s(buffer, capacity, tail) == 0;
}


static BOOL Pcapng_OpenIndex(PCAPNG_WRITER *writer, ULONG index)
{
    WCHAR path[MAX_PATH];
    if (! Pcapng_MakeRotatedPath(path, ARRAYSIZE(path), writer->path, index))
        return FALSE;

    if (writer->file != INVALID_HANDLE_VALUE) {
        CloseHandle(writer->file);
        writer->file = INVALID_HANDLE_VALUE;
    }

    writer->file = Pcapng_CreateFile(path);
    if (writer->file == INVALID_HANDLE_VALUE)
        return FALSE;

    writer->file_index = index;
    writer->file_bytes = 0;
    if (! Pcapng_WriteHeaders(writer))
        return FALSE;

    if (writer->rotate_count != 0 && index >= writer->rotate_count) {
        WCHAR stale[MAX_PATH];
        if (Pcapng_MakeRotatedPath(
                stale, ARRAYSIZE(stale), writer->path,
                index - writer->rotate_count)) {
            DeleteFileW(stale);
        }
    }

    return TRUE;
}


PCAPNG_WRITER *PcapngWriter_OpenPath(
    const WCHAR *path,
    ULONG snaplen,
    ULONG max_file_bytes,
    ULONG rotate_count)
{
    if (! path || ! path[0])
        return NULL;

    if (snaplen == 0)
        snaplen = PCAPNG_DEFAULT_SNAPLEN;
    if (snaplen > PCAPNG_MAX_SNAPLEN)
        snaplen = PCAPNG_MAX_SNAPLEN;
    if (max_file_bytes == 0)
        max_file_bytes = PCAPNG_DEFAULT_MAX_FILE_BYTES;

    PCAPNG_WRITER *writer = (PCAPNG_WRITER *)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*writer));
    if (! writer)
        return NULL;

    writer->file = INVALID_HANDLE_VALUE;
    writer->snaplen = snaplen;
    writer->max_file_bytes = max_file_bytes;
    writer->rotate_count = rotate_count;
    if (wcscpy_s(writer->path, ARRAYSIZE(writer->path), path) != 0) {
        HeapFree(GetProcessHeap(), 0, writer);
        return NULL;
    }

    if (! Pcapng_OpenIndex(writer, 0)) {
        PcapngWriter_Close(writer);
        return NULL;
    }

    return writer;
}


void PcapngWriter_Close(PCAPNG_WRITER *writer)
{
    if (! writer)
        return;
    if (writer->file != INVALID_HANDLE_VALUE)
        CloseHandle(writer->file);
    HeapFree(GetProcessHeap(), 0, writer);
}


int PcapngWriter_Write(PCAPNG_WRITER *writer, const PCAPNG_PACKET *packet)
{
    if (! writer || ! packet || ! packet->data)
        return PCAPNG_ERROR;
    if (writer->stopped)
        return PCAPNG_STOPPED;

    BOOL rotated = FALSE;
    ULONG captured = packet->captured_length;
    ULONG original = packet->original_length;
    if (captured > writer->snaplen)
        captured = writer->snaplen;
    if (original < captured)
        original = captured;

    ULONG padded = Pcapng_Pad4(captured);
    char comment[512];
    ULONG commentLength = Pcapng_FormatComment(
        packet, comment, sizeof(comment));
    ULONG optionBytes = 4 + Pcapng_Pad4(commentLength) + 4;
    ULONG blockLength = 28 + padded + optionBytes + 4;

    if (writer->file_bytes + blockLength > writer->max_file_bytes) {
        if (writer->rotate_count == 0) {
            writer->stopped = TRUE;
            return PCAPNG_STOPPED;
        }
        if (! Pcapng_OpenIndex(writer, writer->file_index + 1)) {
            writer->stopped = TRUE;
            return PCAPNG_ERROR;
        }
        if (writer->file_bytes + blockLength > writer->max_file_bytes) {
            writer->stopped = TRUE;
            return PCAPNG_STOPPED;
        }
        rotated = TRUE;
    }

    ULONG64 timestamp = 0;
    if (packet->timestamp_filetime >= FILETIME_UNIX_EPOCH)
        timestamp = (packet->timestamp_filetime - FILETIME_UNIX_EPOCH) / 10ull;

    if (! Pcapng_WriteU32(writer, PCAPNG_EPB_TYPE) ||
            ! Pcapng_WriteU32(writer, blockLength) ||
            ! Pcapng_WriteU32(writer, 0) ||
            ! Pcapng_WriteU32(writer, (ULONG)(timestamp >> 32)) ||
            ! Pcapng_WriteU32(writer, (ULONG)timestamp) ||
            ! Pcapng_WriteU32(writer, captured) ||
            ! Pcapng_WriteU32(writer, original) ||
            ! Pcapng_WriteRaw(writer, packet->data, captured) ||
            ! Pcapng_WritePadding(writer, captured) ||
            ! Pcapng_WriteCommentOption(writer, comment, commentLength) ||
            ! Pcapng_WriteU32(writer, blockLength)) {
        return PCAPNG_ERROR;
    }

    writer->packet_count += 1;
    writer->byte_count += captured;
    return rotated ? PCAPNG_ROTATED : PCAPNG_OK;
}


ULONG64 PcapngWriter_PacketCount(const PCAPNG_WRITER *writer)
{
    return writer ? writer->packet_count : 0;
}


ULONG64 PcapngWriter_ByteCount(const PCAPNG_WRITER *writer)
{
    return writer ? writer->byte_count : 0;
}


ULONG PcapngWriter_FileIndex(const PCAPNG_WRITER *writer)
{
    return writer ? writer->file_index : 0;
}


BOOL PcapngWriter_IsStopped(const PCAPNG_WRITER *writer)
{
    return writer ? writer->stopped : TRUE;
}
