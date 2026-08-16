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
// HPACK codec tests (RFC 7541 Appendix C vectors + integer/Huffman primitives)
//---------------------------------------------------------------------------

#include "../SbieCapture/hpack.h"
#include "hpack_tests_data.h"

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


static int BytesEqual(const UCHAR *left, ULONG left_len,
                      const UCHAR *right, ULONG right_len)
{
    if (left_len != right_len)
        return 0;
    return memcmp(left, right, left_len) == 0;
}


//---------------------------------------------------------------------------
// C.1 integer representation
//---------------------------------------------------------------------------

static void TestInteger(void)
{
    UCHAR buf[16];
    ULONG len = 0;
    ULONG value = 0;
    ULONG pos = 0;
    static const UCHAR enc10[] = { 0x0a };
    static const UCHAR enc1337[] = { 0x1f, 0x9a, 0x0a };
    static const UCHAR enc42[] = { 0x2a };

    /* encode 10 with 5-bit prefix */
    Require(Hpack_EncodeInt(buf, sizeof(buf), &len, 10, 5, 0x00) == HPACK_OK,
            "encode 10 (5-bit)");
    Require(BytesEqual(buf, len, enc10, sizeof(enc10)), "encode 10 bytes");

    /* encode 1337 with 5-bit prefix */
    Require(Hpack_EncodeInt(buf, sizeof(buf), &len, 1337, 5, 0x00) == HPACK_OK,
            "encode 1337 (5-bit)");
    Require(BytesEqual(buf, len, enc1337, sizeof(enc1337)), "encode 1337 bytes");

    /* encode 42 with 8-bit prefix */
    Require(Hpack_EncodeInt(buf, sizeof(buf), &len, 42, 8, 0x00) == HPACK_OK,
            "encode 42 (8-bit)");
    Require(BytesEqual(buf, len, enc42, sizeof(enc42)), "encode 42 bytes");

    /* decode round-trip: 1337 */
    pos = 0;
    Require(Hpack_DecodeInt(enc1337, sizeof(enc1337), &pos, 5, &value) == HPACK_OK,
            "decode 1337");
    Require(value == 1337, "decode 1337 value");
    Require(pos == sizeof(enc1337), "decode 1337 consumed");

    /* decode round-trip: 10 */
    pos = 0;
    Require(Hpack_DecodeInt(enc10, sizeof(enc10), &pos, 5, &value) == HPACK_OK,
            "decode 10");
    Require(value == 10 && pos == 1, "decode 10 value");
}


//---------------------------------------------------------------------------
// Huffman (Appendix B)
//---------------------------------------------------------------------------

static void TestHuffman(void)
{
    UCHAR buf[256];
    ULONG len = 0;
    static const UCHAR wwwEnc[] = {
        0xf1,0xe3,0xc2,0xe5,0xf2,0x3a,0x6b,0xa0,0xab,0x90,0xf4,0xff
    };
    static const UCHAR noCacheEnc[] = {
        0xa8,0xeb,0x10,0x64,0x9c,0xbf
    };
    static const char *roundtrip[] = {
        "", "a", "GET", "custom-header", ":authority: www.example.com",
        "gzip, deflate", "0123456789", "!@#$%^&*()"
    };
    int i;

    /* encode "www.example.com" (RFC C.4.1) */
    Require(Hpack_HuffmanEncode((const UCHAR *)"www.example.com", 15,
            buf, sizeof(buf), &len) == HPACK_OK, "huffman encode www.example.com");
    Require(BytesEqual(buf, len, wwwEnc, sizeof(wwwEnc)),
            "huffman encode www.example.com bytes");

    /* encode "no-cache" (RFC C.4.2) */
    Require(Hpack_HuffmanEncode((const UCHAR *)"no-cache", 8,
            buf, sizeof(buf), &len) == HPACK_OK, "huffman encode no-cache");
    Require(BytesEqual(buf, len, noCacheEnc, sizeof(noCacheEnc)),
            "huffman encode no-cache bytes");

    /* decode "www.example.com" */
    {
        UCHAR out[64];
        ULONG out_len = 0;
        Require(Hpack_HuffmanDecode(wwwEnc, sizeof(wwwEnc),
                out, sizeof(out), &out_len) == HPACK_OK,
                "huffman decode www.example.com");
        Require(out_len == 15 && memcmp(out, "www.example.com", 15) == 0,
                "huffman decode www.example.com value");
    }

    /* round-trip */
    for (i = 0; i < (int)(sizeof(roundtrip) / sizeof(roundtrip[0])); ++i) {
        UCHAR out[256];
        ULONG out_len = 0;
        ULONG in_len = (ULONG)strlen(roundtrip[i]);
        char msg[128];
        Require(Hpack_HuffmanEncode((const UCHAR *)roundtrip[i], in_len,
                buf, sizeof(buf), &len) == HPACK_OK, "huffman roundtrip encode");
        Require(Hpack_HuffmanDecode(buf, len, out, sizeof(out), &out_len) == HPACK_OK,
                "huffman roundtrip decode");
        sprintf_s(msg, sizeof(msg), "huffman roundtrip #%d", i);
        Require(out_len == in_len && memcmp(out, roundtrip[i], in_len) == 0, msg);
    }
}


//---------------------------------------------------------------------------
// Appendix C decode vectors
//---------------------------------------------------------------------------

static int DecodeAndCompare(
    HPACK_DECODER *dec,
    const HPACK_TEST_VECTOR *v)
{
    HPACK_HEADER headers[32];
    ULONG count = 0;
    ULONG consumed = 0;
    ULONG i;
    char msg[160];

    if (Hpack_DecodeBlock(dec, v->data, v->data_len,
            headers, 32, &count, &consumed) != HPACK_OK) {
        fprintf(stderr, "FAIL: C.%d.%d decode error\n", v->series, v->sub);
        return 0;
    }
    if (consumed != v->data_len) {
        fprintf(stderr, "FAIL: C.%d.%d consumed %lu != %lu\n",
                v->series, v->sub, consumed, v->data_len);
        return 0;
    }
    if (count != v->header_count) {
        fprintf(stderr, "FAIL: C.%d.%d header count %lu != %lu\n",
                v->series, v->sub, count, v->header_count);
        return 0;
    }
    for (i = 0; i < count; ++i) {
        sprintf_s(msg, sizeof(msg), "C.%d.%d header[%lu] name",
                  v->series, v->sub, i);
        if (strcmp(headers[i].name, v->headers[i].name) != 0) {
            fprintf(stderr, "FAIL: %s got '%s' want '%s'\n",
                    msg, headers[i].name, v->headers[i].name);
            return 0;
        }
        sprintf_s(msg, sizeof(msg), "C.%d.%d header[%lu] value",
                  v->series, v->sub, i);
        if (strcmp(headers[i].value, v->headers[i].value) != 0) {
            fprintf(stderr, "FAIL: %s got '%s' want '%s'\n",
                    msg, headers[i].value, v->headers[i].value);
            return 0;
        }
    }
    return 1;
}


static void TestAppendixCVectors(void)
{
    HPACK_DECODER series_dec;
    int current_series = 0;
    BOOL have_series = FALSE;
    int i;

    for (i = 0; i < HPACK_TEST_VECTOR_COUNT; ++i) {
        const HPACK_TEST_VECTOR *v = &HpackTestVectors[i];
        if (v->series == 2) {
            /* each C.2.x is an independent example */
            HPACK_DECODER dec;
            Hpack_DecoderInit(&dec, HPACK_DEFAULT_TABLE_SIZE);
            if (DecodeAndCompare(&dec, v))
                ++g_checks;
            else
                ++g_failures;
        }
        else {
            /* C.3.x / C.4.x / C.5.x / C.6.x share a table within a series */
            if (! have_series || v->series != current_series) {
                Hpack_DecoderInit(&series_dec, HPACK_DEFAULT_TABLE_SIZE);
                current_series = v->series;
                have_series = TRUE;
            }
            if (DecodeAndCompare(&series_dec, v))
                ++g_checks;
            else
                ++g_failures;
        }
    }
}


//---------------------------------------------------------------------------
// Encode (byte-exact against RFC)
//---------------------------------------------------------------------------

static int EncodeList(
    HPACK_ENCODER *enc,
    const HPACK_TEST_HEADER *headers,
    ULONG count,
    UCHAR *out,
    ULONG out_capacity,
    ULONG *out_len)
{
    ULONG pos = 0;
    ULONG i;
    for (i = 0; i < count; ++i) {
        ULONG n = 0;
        if (Hpack_EncodeHeader(enc, headers[i].name, headers[i].value,
                out + pos, out_capacity - pos, &n) != HPACK_OK)
            return 0;
        pos += n;
    }
    *out_len = pos;
    return 1;
}


static void TestEncode(void)
{
    UCHAR buf[256];
    ULONG len = 0;
    HPACK_ENCODER enc;
    static const HPACK_TEST_HEADER c21[] = {
        { "custom-key", "custom-header" }
    };
    static const UCHAR c21Expected[] = {
        0x40,0x0a,0x63,0x75,0x73,0x74,0x6f,0x6d,0x2d,0x6b,0x65,0x79,
        0x0d,0x63,0x75,0x73,0x74,0x6f,0x6d,0x2d,0x68,0x65,0x61,0x64,0x65,0x72
    };
    static const UCHAR c24Expected[] = { 0x82 };

    /* C.2.4: :method: GET -> indexed 2 */
    Hpack_EncoderInit(&enc, HPACK_DEFAULT_TABLE_SIZE, FALSE);
    Require(EncodeList(&enc, &HpackVec3Headers[0], 1,
            buf, sizeof(buf), &len), "encode C.2.4");
    Require(BytesEqual(buf, len, c24Expected, sizeof(c24Expected)),
            "encode C.2.4 bytes");

    /* C.2.1: custom-key: custom-header -> literal with indexing, no Huffman */
    Hpack_EncoderInit(&enc, HPACK_DEFAULT_TABLE_SIZE, FALSE);
    Require(EncodeList(&enc, c21, 1, buf, sizeof(buf), &len),
            "encode C.2.1");
    Require(BytesEqual(buf, len, c21Expected, sizeof(c21Expected)),
            "encode C.2.1 bytes");

    /* C.3.1: full request list, no Huffman */
    Hpack_EncoderInit(&enc, HPACK_DEFAULT_TABLE_SIZE, FALSE);
    Require(EncodeList(&enc, HpackVec4Headers, 4,
            buf, sizeof(buf), &len), "encode C.3.1");
    Require(BytesEqual(buf, len, HpackVec4Data, 20), "encode C.3.1 bytes");

    /* C.4.1: full request list, Huffman */
    Hpack_EncoderInit(&enc, HPACK_DEFAULT_TABLE_SIZE, TRUE);
    Require(EncodeList(&enc, HpackVec7Headers, 4,
            buf, sizeof(buf), &len), "encode C.4.1");
    Require(BytesEqual(buf, len, HpackVec7Data, 17), "encode C.4.1 bytes");

    /* encode -> decode consistency: C.3.1 header list re-decodes identically */
    {
        HPACK_DECODER dec;
        HPACK_HEADER headers[16];
        ULONG count = 0, consumed = 0;
        Hpack_EncoderInit(&enc, HPACK_DEFAULT_TABLE_SIZE, FALSE);
        Require(EncodeList(&enc, HpackVec4Headers, 4,
                buf, sizeof(buf), &len), "roundtrip encode C.3.1");
        Hpack_DecoderInit(&dec, HPACK_DEFAULT_TABLE_SIZE);
        Require(Hpack_DecodeBlock(&dec, buf, len, headers, 16,
                &count, &consumed) == HPACK_OK, "roundtrip decode C.3.1");
        Require(count == 4, "roundtrip C.3.1 count");
        Require(strcmp(headers[0].name, ":method") == 0 &&
                strcmp(headers[0].value, "GET") == 0, "roundtrip C.3.1 [0]");
        Require(strcmp(headers[3].name, ":authority") == 0 &&
                strcmp(headers[3].value, "www.example.com") == 0,
                "roundtrip C.3.1 [3]");
    }
}


//---------------------------------------------------------------------------
// Dynamic table size update (RFC 7541 6.3)
//---------------------------------------------------------------------------

static void TestTableSizeUpdate(void)
{
    HPACK_DECODER dec;
    HPACK_HEADER headers[4];
    ULONG count = 0, consumed = 0;
    static const UCHAR update0[] = { 0x20 };             /* size -> 0 */
    static const UCHAR update1337[] = { 0x3f, 0x9a, 0x0a };

    Hpack_DecoderInit(&dec, HPACK_DEFAULT_TABLE_SIZE);
    Require(Hpack_DecodeBlock(&dec, update0, sizeof(update0), headers, 4,
            &count, &consumed) == HPACK_OK, "size update 0 decode");
    Require(count == 0 && consumed == 1, "size update 0 empty");
    Require(dec.table.capacity == 0, "size update 0 capacity");

    Hpack_DecoderInit(&dec, HPACK_DEFAULT_TABLE_SIZE);
    Require(Hpack_DecodeBlock(&dec, update1337, sizeof(update1337), headers, 4,
            &count, &consumed) == HPACK_OK, "size update 1337 decode");
    Require(count == 0 && consumed == 3, "size update 1337 empty");
    Require(dec.table.capacity == 1337, "size update 1337 capacity");
}


//---------------------------------------------------------------------------
// Malformed-input rejection
//---------------------------------------------------------------------------

static void TestMalformed(void)
{
    HPACK_DECODER dec;
    HPACK_HEADER headers[4];
    ULONG count = 0, consumed = 0;
    static const UCHAR badIndex[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }; /* idx overflow */
    static const UCHAR truncated[] = { 0x0a, 0x05, 'h', 'e' }; /* literal name len 5, only 2 bytes */

    Hpack_DecoderInit(&dec, HPACK_DEFAULT_TABLE_SIZE);
    Require(Hpack_DecodeBlock(&dec, badIndex, sizeof(badIndex), headers, 4,
            &count, &consumed) == HPACK_ERROR, "malformed index rejected");

    Hpack_DecoderInit(&dec, HPACK_DEFAULT_TABLE_SIZE);
    Require(Hpack_DecodeBlock(&dec, truncated, sizeof(truncated), headers, 4,
            &count, &consumed) == HPACK_ERROR, "truncated string rejected");
}


//---------------------------------------------------------------------------
// helper to read vector counts (avoids manual constants)
//---------------------------------------------------------------------------

int main(void)
{
    TestInteger();
    TestHuffman();
    TestAppendixCVectors();
    TestEncode();
    TestTableSizeUpdate();
    TestMalformed();

    if (g_failures == 0) {
        printf("hpack tests passed (%d checks)\n", g_checks);
        return 0;
    }
    fprintf(stderr, "hpack tests FAILED: %d/%d checks failed\n",
            g_failures, g_checks);
    return 1;
}
