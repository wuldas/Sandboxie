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

#ifndef _MY_PCAPNG_H
#define _MY_PCAPNG_H

#include <windows.h>

#define PCAPNG_LINKTYPE_RAW                 101
#define PCAPNG_DEFAULT_SNAPLEN              256
#define PCAPNG_MAX_SNAPLEN                  1514
#define PCAPNG_DEFAULT_MAX_FILE_BYTES       (64u * 1024u * 1024u)

#define PCAPNG_OK                           0
#define PCAPNG_ROTATED                      1
#define PCAPNG_STOPPED                      2
#define PCAPNG_ERROR                        (-1)

typedef struct _PCAPNG_PACKET {

    ULONG64 timestamp_filetime;
    ULONG original_length;
    ULONG captured_length;
    ULONG process_id;
    ULONG session_id;
    ULONG64 process_create_time;
    const UCHAR *data;
    const WCHAR *box_name;
    const WCHAR *sid_string;

} PCAPNG_PACKET;

typedef struct _PCAPNG_WRITER PCAPNG_WRITER;

#ifdef __cplusplus
extern "C" {
#endif

PCAPNG_WRITER *PcapngWriter_OpenPath(
    const WCHAR *path,
    ULONG snaplen,
    ULONG max_file_bytes,
    ULONG rotate_count);

PCAPNG_WRITER *PcapngWriter_OpenHandle(
    HANDLE file,
    const WCHAR *rotation_path,
    ULONG snaplen,
    ULONG max_file_bytes,
    ULONG rotate_count);

void PcapngWriter_Close(PCAPNG_WRITER *writer);

int PcapngWriter_Write(PCAPNG_WRITER *writer, const PCAPNG_PACKET *packet);

ULONG64 PcapngWriter_PacketCount(const PCAPNG_WRITER *writer);
ULONG64 PcapngWriter_ByteCount(const PCAPNG_WRITER *writer);
ULONG PcapngWriter_FileIndex(const PCAPNG_WRITER *writer);
BOOL PcapngWriter_IsStopped(const PCAPNG_WRITER *writer);

#ifdef __cplusplus
}
#endif

#endif /* _MY_PCAPNG_H */
