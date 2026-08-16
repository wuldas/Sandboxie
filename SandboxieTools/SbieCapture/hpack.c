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

#include "hpack.h"
#include "hpack_huffman.h"
#include "hpack_static.h"

#include <string.h>


//---------------------------------------------------------------------------
// Integer representation (RFC 7541 5.1)
//---------------------------------------------------------------------------

static int Hpack_DecodeIntLocal(
    const UCHAR *data,
    ULONG size,
    ULONG *pos,
    UCHAR prefix,
    ULONG *value)
{
    ULONG prefix_max = (1u << prefix) - 1;
    ULONG v;
    ULONG shift = 0;

    if (*pos >= size)
        return HPACK_ERROR;
    v = data[*pos] & prefix_max;
    ++*pos;
    if (v < prefix_max) {
        *value = v;
        return HPACK_OK;
    }
    for (;;) {
        UCHAR b;
        if (*pos >= size)
            return HPACK_ERROR;
        b = data[*pos];
        ++*pos;
        v += (ULONG)(b & 0x7f) << shift;
        if ((b & 0x80) == 0)
            break;
        shift += 7;
        if (shift > 28)
            return HPACK_ERROR;
    }
    *value = v;
    return HPACK_OK;
}


int Hpack_DecodeInt(
    const UCHAR *data,
    ULONG size,
    ULONG *pos,
    UCHAR prefix,
    ULONG *value)
{
    return Hpack_DecodeIntLocal(data, size, pos, prefix, value);
}


static int Hpack_EncodeIntLocal(
    UCHAR *out,
    ULONG out_capacity,
    ULONG *out_len,
    ULONG value,
    UCHAR prefix,
    UCHAR high_bits)
{
    ULONG prefix_max = (1u << prefix) - 1;
    ULONG pos = 0;

    if (value < prefix_max) {
        if (out_capacity < 1)
            return HPACK_ERROR;
        out[pos++] = (UCHAR)(high_bits | (value & prefix_max));
        *out_len = pos;
        return HPACK_OK;
    }
    if (out_capacity < 1)
        return HPACK_ERROR;
    out[pos++] = (UCHAR)(high_bits | prefix_max);
    value -= prefix_max;
    while (value >= 128) {
        if (pos >= out_capacity)
            return HPACK_ERROR;
        out[pos++] = (UCHAR)((value & 0x7f) | 0x80);
        value >>= 7;
    }
    if (pos >= out_capacity)
        return HPACK_ERROR;
    out[pos++] = (UCHAR)(value & 0x7f);
    *out_len = pos;
    return HPACK_OK;
}


int Hpack_EncodeInt(
    UCHAR *out,
    ULONG out_capacity,
    ULONG *out_len,
    ULONG value,
    UCHAR prefix,
    UCHAR high_bits)
{
    return Hpack_EncodeIntLocal(out, out_capacity, out_len, value, prefix, high_bits);
}


//---------------------------------------------------------------------------
// Huffman (RFC 7541 Appendix B)
//---------------------------------------------------------------------------

int Hpack_HuffmanDecode(
    const UCHAR *in,
    ULONG in_len,
    UCHAR *out,
    ULONG out_capacity,
    ULONG *out_len)
{
    ULONG o = 0;
    int node = 0;
    ULONG i;

    if (! in || ! out || ! out_len)
        return HPACK_ERROR;
    for (i = 0; i < in_len; ++i) {
        UCHAR b = in[i];
        int bit;
        for (bit = 7; bit >= 0; --bit) {
            int branch = (b >> bit) & 1;
            node = (branch == 0)
                ? HpackHuffTrie[node].left
                : HpackHuffTrie[node].right;
            if (node < 0)
                return HPACK_ERROR;
            if (HpackHuffTrie[node].symbol >= 0) {
                int sym = HpackHuffTrie[node].symbol;
                if (sym == 256) {   /* EOS = padding */
                    *out_len = o;
                    return HPACK_OK;
                }
                if (o >= out_capacity)
                    return HPACK_ERROR;
                out[o++] = (UCHAR)sym;
                node = 0;
            }
        }
    }
    *out_len = o;
    return HPACK_OK;
}


int Hpack_HuffmanEncode(
    const UCHAR *in,
    ULONG in_len,
    UCHAR *out,
    ULONG out_capacity,
    ULONG *out_len)
{
    ULONG64 acc = 0;
    int nbits = 0;
    ULONG o = 0;
    ULONG i;

    if (! in || ! out || ! out_len)
        return HPACK_ERROR;
    for (i = 0; i < in_len; ++i) {
        const HPACK_HUFF_CODE *c = &HpackHuffCode[in[i]];
        acc = (acc << c->bits) | c->code;
        nbits += c->bits;
        while (nbits >= 8) {
            nbits -= 8;
            if (o >= out_capacity)
                return HPACK_ERROR;
            out[o++] = (UCHAR)((acc >> nbits) & 0xff);
        }
    }
    if (nbits > 0) {
        ULONG pad = 8 - nbits;
        acc = (acc << pad) | ((1u << pad) - 1);
        if (o >= out_capacity)
            return HPACK_ERROR;
        out[o++] = (UCHAR)(acc & 0xff);
    }
    *out_len = o;
    return HPACK_OK;
}


//---------------------------------------------------------------------------
// Static + dynamic table (RFC 7541 2.3 / Appendix A)
//---------------------------------------------------------------------------

static int Hpack_EntryAtIndex(
    const HPACK_TABLE *table,
    ULONG index,
    const char **name,
    ULONG *name_len,
    const char **value,
    ULONG *value_len)
{
    if (index == 0)
        return HPACK_ERROR;
    if (index <= HPACK_STATIC_COUNT) {
        const HPACK_STATIC_ENTRY *e = &HpackStatic[index - 1];
        if (name) {
            *name = e->name;
            *name_len = (ULONG)strlen(e->name);
        }
        if (value) {
            *value = e->value;
            *value_len = (ULONG)strlen(e->value);
        }
        return HPACK_OK;
    }
    {
        ULONG d = index - HPACK_STATIC_COUNT - 1;
        const HPACK_ENTRY *e;
        if (d >= table->count)
            return HPACK_ERROR;
        e = &table->entries[d];
        if (name) {
            *name = (const char *)(table->arena + e->name_off);
            *name_len = e->name_len;
        }
        if (value) {
            *value = (const char *)(table->arena + e->value_off);
            *value_len = e->value_len;
        }
        return HPACK_OK;
    }
}


static void Hpack_TableSetCapacity(HPACK_TABLE *table, ULONG capacity)
{
    table->capacity = capacity;
    while (table->count > 0 && table->size > table->capacity) {
        const HPACK_ENTRY *e = &table->entries[table->count - 1];
        table->size -= e->name_len + e->value_len + 32;
        table->count--;
    }
}


static void Hpack_TableCompact(HPACK_TABLE *table)
{
    UCHAR *src = table->arena;
    ULONG used = 0;
    ULONG i;

    for (i = table->count; i > 0; --i) {
        HPACK_ENTRY *e = &table->entries[i - 1];
        memmove(table->arena + used, src + e->name_off, e->name_len);
        e->name_off = used;
        used += e->name_len;
        memmove(table->arena + used, src + e->value_off, e->value_len);
        e->value_off = used;
        used += e->value_len;
    }
    table->arena_used = used;
}


static int Hpack_TableAdd(
    HPACK_TABLE *table,
    const char *name,
    ULONG name_len,
    const char *value,
    ULONG value_len)
{
    ULONG entry_size = name_len + value_len + 32;
    HPACK_ENTRY *e;

    if (entry_size > table->capacity) {
        table->count = 0;
        table->size = 0;
        table->arena_used = 0;
        return HPACK_OK;
    }
    while (table->count > 0 && table->size + entry_size > table->capacity) {
        const HPACK_ENTRY *last = &table->entries[table->count - 1];
        table->size -= last->name_len + last->value_len + 32;
        table->count--;
    }
    if (table->arena_used + name_len + value_len > HPACK_MAX_TABLE_BYTES)
        Hpack_TableCompact(table);
    if (table->arena_used + name_len + value_len > HPACK_MAX_TABLE_BYTES)
        return HPACK_ERROR;
    if (table->count >= HPACK_MAX_DYNAMIC_ENTRIES) {
        const HPACK_ENTRY *last = &table->entries[table->count - 1];
        table->size -= last->name_len + last->value_len + 32;
        table->count--;
    }
    memmove(&table->entries[1], &table->entries[0],
            table->count * sizeof(HPACK_ENTRY));
    e = &table->entries[0];
    memcpy(table->arena + table->arena_used, name, name_len);
    e->name_off = table->arena_used;
    e->name_len = name_len;
    table->arena_used += name_len;
    memcpy(table->arena + table->arena_used, value, value_len);
    e->value_off = table->arena_used;
    e->value_len = value_len;
    table->arena_used += value_len;
    table->count++;
    table->size += entry_size;
    return HPACK_OK;
}


static int Hpack_FindExact(
    const HPACK_TABLE *table,
    const char *name,
    ULONG name_len,
    const char *value,
    ULONG value_len)
{
    int i;
    for (i = 0; i < HPACK_STATIC_COUNT; ++i) {
        const HPACK_STATIC_ENTRY *e = &HpackStatic[i];
        if ((ULONG)strlen(e->name) == name_len &&
                (ULONG)strlen(e->value) == value_len &&
                memcmp(e->name, name, name_len) == 0 &&
                memcmp(e->value, value, value_len) == 0)
            return i + 1;
    }
    for (i = 0; (ULONG)i < table->count; ++i) {
        const HPACK_ENTRY *e = &table->entries[i];
        if (e->name_len == name_len && e->value_len == value_len &&
                memcmp(table->arena + e->name_off, name, name_len) == 0 &&
                memcmp(table->arena + e->value_off, value, value_len) == 0)
            return HPACK_STATIC_COUNT + 1 + i;
    }
    return 0;
}


static int Hpack_FindName(
    const HPACK_TABLE *table,
    const char *name,
    ULONG name_len)
{
    int i;
    for (i = 0; i < HPACK_STATIC_COUNT; ++i) {
        const HPACK_STATIC_ENTRY *e = &HpackStatic[i];
        if ((ULONG)strlen(e->name) == name_len &&
                memcmp(e->name, name, name_len) == 0)
            return i + 1;
    }
    for (i = 0; (ULONG)i < table->count; ++i) {
        const HPACK_ENTRY *e = &table->entries[i];
        if (e->name_len == name_len &&
                memcmp(table->arena + e->name_off, name, name_len) == 0)
            return HPACK_STATIC_COUNT + 1 + i;
    }
    return 0;
}


//---------------------------------------------------------------------------
// String literal (RFC 7541 5.2)
//---------------------------------------------------------------------------

static int Hpack_DecodeString(
    const UCHAR *data,
    ULONG size,
    ULONG *pos,
    char *out,
    ULONG out_capacity,
    ULONG *out_len)
{
    ULONG str_len = 0;
    int huffman;

    if (*pos >= size)
        return HPACK_ERROR;
    huffman = (data[*pos] & 0x80) != 0;
    if (Hpack_DecodeInt(data, size, pos, 7, &str_len) != HPACK_OK)
        return HPACK_ERROR;
    if (str_len > size - *pos)
        return HPACK_ERROR;
    if (huffman) {
        ULONG decoded = 0;
        if (out_capacity == 0)
            return HPACK_ERROR;
        if (Hpack_HuffmanDecode(data + *pos, str_len, (UCHAR *)out,
                out_capacity - 1, &decoded) != HPACK_OK)
            return HPACK_ERROR;
        out[decoded] = 0;
        *out_len = decoded;
    }
    else {
        if (str_len >= out_capacity)
            return HPACK_ERROR;
        memcpy(out, data + *pos, str_len);
        out[str_len] = 0;
        *out_len = str_len;
    }
    *pos += str_len;
    return HPACK_OK;
}


static int Hpack_EncodeString(
    HPACK_ENCODER *enc,
    const char *str,
    ULONG str_len,
    UCHAR *out,
    ULONG out_capacity,
    ULONG *out_len)
{
    ULONG n = 0;

    if (enc->huffman) {
        UCHAR tmp[HPACK_MAX_VALUE * 4 + 32];
        ULONG hlen = 0;
        if (str_len > HPACK_MAX_VALUE)
            return HPACK_ERROR;
        if (Hpack_HuffmanEncode((const UCHAR *)str, str_len,
                tmp, sizeof(tmp), &hlen) != HPACK_OK)
            return HPACK_ERROR;
        if (Hpack_EncodeInt(out, out_capacity, &n, hlen, 7, 0x80) != HPACK_OK)
            return HPACK_ERROR;
        if (out_capacity - n < hlen)
            return HPACK_ERROR;
        memcpy(out + n, tmp, hlen);
        *out_len = n + hlen;
        return HPACK_OK;
    }
    else {
        if (Hpack_EncodeInt(out, out_capacity, &n, str_len, 7, 0x00) != HPACK_OK)
            return HPACK_ERROR;
        if (out_capacity - n < str_len)
            return HPACK_ERROR;
        memcpy(out + n, str, str_len);
        *out_len = n + str_len;
        return HPACK_OK;
    }
}


//---------------------------------------------------------------------------
// Public API
//---------------------------------------------------------------------------

void Hpack_DecoderInit(HPACK_DECODER *dec, ULONG capacity)
{
    if (! dec)
        return;
    memset(dec, 0, sizeof(*dec));
    if (capacity > HPACK_MAX_TABLE_BYTES)
        capacity = HPACK_MAX_TABLE_BYTES;
    dec->table.capacity = capacity;
}


int Hpack_DecodeBlock(
    HPACK_DECODER *dec,
    const UCHAR *data,
    ULONG size,
    HPACK_HEADER *out,
    ULONG out_capacity,
    ULONG *out_count,
    ULONG *consumed)
{
    ULONG pos = 0;
    ULONG count = 0;

    if (! dec || ! data || ! out || ! out_count || ! consumed)
        return HPACK_ERROR;

    while (pos < size) {
        UCHAR b = data[pos];
        char name_buf[HPACK_MAX_NAME];
        char value_buf[HPACK_MAX_VALUE];
        const char *name = NULL;
        const char *value = NULL;
        ULONG name_len = 0;
        ULONG value_len = 0;
        ULONG idx = 0;

        if (b & 0x80) {
            /* 6.1 indexed header field */
            if (Hpack_DecodeInt(data, size, &pos, 7, &idx) != HPACK_OK)
                return HPACK_ERROR;
            if (Hpack_EntryAtIndex(&dec->table, idx,
                    &name, &name_len, &value, &value_len) != HPACK_OK)
                return HPACK_ERROR;
        }
        else if (b & 0x40) {
            /* 6.2.1 literal with incremental indexing */
            if (Hpack_DecodeInt(data, size, &pos, 6, &idx) != HPACK_OK)
                return HPACK_ERROR;
            if (idx == 0) {
                if (Hpack_DecodeString(data, size, &pos, name_buf,
                        sizeof(name_buf), &name_len) != HPACK_OK)
                    return HPACK_ERROR;
            }
            else {
                const char *src = NULL;
                if (Hpack_EntryAtIndex(&dec->table, idx,
                        &src, &name_len, NULL, NULL) != HPACK_OK)
                    return HPACK_ERROR;
                if (name_len >= sizeof(name_buf))
                    return HPACK_ERROR;
                memcpy(name_buf, src, name_len);
                name_buf[name_len] = 0;
            }
            name = name_buf;
            if (Hpack_DecodeString(data, size, &pos, value_buf,
                    sizeof(value_buf), &value_len) != HPACK_OK)
                return HPACK_ERROR;
            value = value_buf;
            Hpack_TableAdd(&dec->table, name, name_len, value, value_len);
        }
        else if (b & 0x20) {
            /* 6.3 dynamic table size update */
            ULONG new_capacity;
            if (Hpack_DecodeInt(data, size, &pos, 5, &new_capacity) != HPACK_OK)
                return HPACK_ERROR;
            Hpack_TableSetCapacity(&dec->table, new_capacity);
            continue;
        }
        else {
            /* 6.2.2 without indexing (0000) / 6.2.3 never indexed (0001) */
            if (Hpack_DecodeInt(data, size, &pos, 4, &idx) != HPACK_OK)
                return HPACK_ERROR;
            if (idx == 0) {
                if (Hpack_DecodeString(data, size, &pos, name_buf,
                        sizeof(name_buf), &name_len) != HPACK_OK)
                    return HPACK_ERROR;
                name = name_buf;
            }
            else {
                const char *src = NULL;
                if (Hpack_EntryAtIndex(&dec->table, idx,
                        &src, &name_len, NULL, NULL) != HPACK_OK)
                    return HPACK_ERROR;
                if (name_len >= sizeof(name_buf))
                    return HPACK_ERROR;
                memcpy(name_buf, src, name_len);
                name_buf[name_len] = 0;
                name = name_buf;
            }
            if (Hpack_DecodeString(data, size, &pos, value_buf,
                    sizeof(value_buf), &value_len) != HPACK_OK)
                return HPACK_ERROR;
            value = value_buf;
        }

        if (count >= out_capacity)
            return HPACK_ERROR;
        if (name_len >= HPACK_MAX_NAME || value_len >= HPACK_MAX_VALUE)
            return HPACK_ERROR;
        memcpy(out[count].name, name, name_len);
        out[count].name[name_len] = 0;
        memcpy(out[count].value, value, value_len);
        out[count].value[value_len] = 0;
        count++;
    }
    *out_count = count;
    *consumed = pos;
    return HPACK_OK;
}


void Hpack_EncoderInit(HPACK_ENCODER *enc, ULONG capacity, BOOL huffman)
{
    if (! enc)
        return;
    memset(enc, 0, sizeof(*enc));
    if (capacity > HPACK_MAX_TABLE_BYTES)
        capacity = HPACK_MAX_TABLE_BYTES;
    enc->table.capacity = capacity;
    enc->huffman = huffman;
}


/* name/value must not alias the encoder's dynamic-table arena. */
int Hpack_EncodeHeader(
    HPACK_ENCODER *enc,
    const char *name,
    const char *value,
    UCHAR *out,
    ULONG out_capacity,
    ULONG *out_len)
{
    ULONG name_len;
    ULONG value_len;
    ULONG pos = 0;
    ULONG n = 0;
    int idx;
    int name_idx;

    if (! enc || ! name || ! value || ! out || ! out_len)
        return HPACK_ERROR;
    name_len = (ULONG)strlen(name);
    value_len = (ULONG)strlen(value);

    /* 1. indexed header field (exact name + value match) */
    idx = Hpack_FindExact(&enc->table, name, name_len, value, value_len);
    if (idx > 0) {
        if (Hpack_EncodeInt(out, out_capacity, &n, (ULONG)idx, 7, 0x80) != HPACK_OK)
            return HPACK_ERROR;
        *out_len = n;
        return HPACK_OK;
    }

    /* 2. literal with incremental indexing */
    name_idx = Hpack_FindName(&enc->table, name, name_len);
    if (Hpack_EncodeInt(out + pos, out_capacity - pos, &n,
            (ULONG)(name_idx < 0 ? 0 : name_idx), 6, 0x40) != HPACK_OK)
        return HPACK_ERROR;
    pos += n;
    if (name_idx <= 0) {
        if (Hpack_EncodeString(enc, name, name_len,
                out + pos, out_capacity - pos, &n) != HPACK_OK)
            return HPACK_ERROR;
        pos += n;
    }
    if (Hpack_EncodeString(enc, value, value_len,
            out + pos, out_capacity - pos, &n) != HPACK_OK)
        return HPACK_ERROR;
    pos += n;
    Hpack_TableAdd(&enc->table, name, name_len, value, value_len);
    *out_len = pos;
    return HPACK_OK;
}
