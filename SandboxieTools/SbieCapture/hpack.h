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
// HPACK (RFC 7541) header compression -- encode + decode
//---------------------------------------------------------------------------

#ifndef _MY_HPACK_H
#define _MY_HPACK_H

#include <windows.h>

#define HPACK_OK                    0
#define HPACK_ERROR                (-1)

#define HPACK_MAX_NAME              256
#define HPACK_MAX_VALUE             4096
#define HPACK_MAX_HEADERS           128
#define HPACK_DEFAULT_TABLE_SIZE    4096
#define HPACK_MAX_TABLE_BYTES       16384
#define HPACK_MAX_DYNAMIC_ENTRIES   512

typedef struct _HPACK_HEADER {

    char name[HPACK_MAX_NAME];
    char value[HPACK_MAX_VALUE];

} HPACK_HEADER;

typedef struct _HPACK_ENTRY {

    ULONG name_off;
    ULONG name_len;
    ULONG value_off;
    ULONG value_len;

} HPACK_ENTRY;

typedef struct _HPACK_TABLE {

    UCHAR arena[HPACK_MAX_TABLE_BYTES];
    ULONG arena_used;
    HPACK_ENTRY entries[HPACK_MAX_DYNAMIC_ENTRIES]; /* [0] = newest */
    ULONG count;
    ULONG size;      /* sum of (name_len + value_len + 32) */
    ULONG capacity;  /* current max table size */

} HPACK_TABLE;

typedef struct _HPACK_DECODER {

    HPACK_TABLE table;

} HPACK_DECODER;

typedef struct _HPACK_ENCODER {

    HPACK_TABLE table;
    BOOL huffman;

} HPACK_ENCODER;

#ifdef __cplusplus
extern "C" {
#endif

void Hpack_DecoderInit(HPACK_DECODER *dec, ULONG capacity);
int  Hpack_DecodeBlock(
        HPACK_DECODER *dec,
        const UCHAR *data,
        ULONG size,
        HPACK_HEADER *out,
        ULONG out_capacity,
        ULONG *out_count,
        ULONG *consumed);

void Hpack_EncoderInit(HPACK_ENCODER *enc, ULONG capacity, BOOL huffman);
int  Hpack_EncodeHeader(
        HPACK_ENCODER *enc,
        const char *name,
        const char *value,
        UCHAR *out,
        ULONG out_capacity,
        ULONG *out_len);

int Hpack_HuffmanEncode(
        const UCHAR *in,
        ULONG in_len,
        UCHAR *out,
        ULONG out_capacity,
        ULONG *out_len);

int Hpack_HuffmanDecode(
        const UCHAR *in,
        ULONG in_len,
        UCHAR *out,
        ULONG out_capacity,
        ULONG *out_len);

/* RFC 7541 5.1 integer primitives (exposed for tests; prefix is the number of
   significant low bits in the first byte, high_bits holds the leading bits). */
int Hpack_EncodeInt(
        UCHAR *out,
        ULONG out_capacity,
        ULONG *out_len,
        ULONG value,
        UCHAR prefix,
        UCHAR high_bits);

int Hpack_DecodeInt(
        const UCHAR *data,
        ULONG size,
        ULONG *pos,
        UCHAR prefix,
        ULONG *value);

#ifdef __cplusplus
}
#endif

#endif /* _MY_HPACK_H */
