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
// PCAPNG writer tests
//---------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../SbieCapture/pcapng.h"

#define PCAPNG_SHB_TYPE     0x0A0D0D0Au
#define PCAPNG_IDB_TYPE     0x00000001u
#define PCAPNG_EPB_TYPE     0x00000006u
#define PCAPNG_BOM_LE       0x1A2B3C4Du
#define PCAPNG_OPT_COMMENT  1


static int Require(int condition, const char *message)
{
    if (! condition) {
        fprintf(stderr, "FAILED: %s\n", message);
        return 0;
    }
    return 1;
}


static void MakeTempPath(WCHAR *buffer, size_t capacity, const WCHAR *name)
{
    DWORD length = GetTempPathW((DWORD)capacity, buffer);
    if (length == 0 || length >= capacity)
        wcscpy_s(buffer, capacity, L".\\");
    wcscat_s(buffer, capacity, name);
}


static int ReadAll(const WCHAR *path, UCHAR **bytes, DWORD *size)
{
    HANDLE file = CreateFileW(
        path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return 0;

    DWORD fileSize = GetFileSize(file, NULL);
    UCHAR *buffer = (UCHAR *)malloc(fileSize);
    DWORD read = 0;
    BOOL ok = buffer &&
        ReadFile(file, buffer, fileSize, &read, NULL) && read == fileSize;
    CloseHandle(file);
    if (! ok) {
        free(buffer);
        return 0;
    }
    *bytes = buffer;
    *size = fileSize;
    return 1;
}


static ULONG ReadU32(const UCHAR *bytes, DWORD offset)
{
    ULONG value;
    memcpy(&value, bytes + offset, 4);
    return value;
}


static ULONG ReadU16(const UCHAR *bytes, DWORD offset)
{
    USHORT value;
    memcpy(&value, bytes + offset, 2);
    return value;
}


static void BuildIpv4TcpSyn(UCHAR *packet)
{
    memset(packet, 0, 40);
    packet[0] = 0x45;
    packet[2] = 0;
    packet[3] = 40;
    packet[8] = 64;
    packet[9] = 6;
    packet[12] = 10;
    packet[13] = 0;
    packet[14] = 0;
    packet[15] = 1;
    packet[16] = 1;
    packet[17] = 1;
    packet[18] = 1;
    packet[19] = 1;
    packet[20] = 0x30;
    packet[21] = 0x39;
    packet[22] = 0;
    packet[23] = 80;
    packet[33] = 0x02;
    packet[34] = 0xFF;
    packet[35] = 0xFF;
}


static int TestWritesShbIdbAndOneEpb(void)
{
    WCHAR path[MAX_PATH];
    MakeTempPath(path, MAX_PATH, L"sbie-pcapng-one.pcapng");
    DeleteFileW(path);

    PCAPNG_WRITER *writer = PcapngWriter_OpenPath(path, 256, 1024 * 1024, 0);
    if (! Require(writer != NULL, "open writer"))
        return 0;

    UCHAR packet[40];
    BuildIpv4TcpSyn(packet);

    PCAPNG_PACKET record;
    memset(&record, 0, sizeof(record));
    record.timestamp_filetime = 133000000000000000ull;
    record.original_length = 40;
    record.captured_length = 40;
    record.process_id = 4242;
    record.session_id = 1;
    record.process_create_time = 133000000000000001ull;
    record.data = packet;
    record.box_name = L"DefaultBox";
    record.sid_string = L"S-1-5-21-1-2-3-1001";

    int status = PcapngWriter_Write(writer, &record);
    PcapngWriter_Close(writer);
    if (! Require(status == PCAPNG_OK, "write one packet")) {
        DeleteFileW(path);
        return 0;
    }

    UCHAR *bytes = NULL;
    DWORD size = 0;
    if (! Require(ReadAll(path, &bytes, &size), "read output file")) {
        DeleteFileW(path);
        return 0;
    }

    int ok = 1;
    if (! Require(size >= 32, "file too small for SHB") ||
            ! Require(ReadU32(bytes, 0) == PCAPNG_SHB_TYPE, "SHB type") ||
            ! Require(ReadU32(bytes, 8) == PCAPNG_BOM_LE, "little-endian BOM")) {
        ok = 0;
    }

    DWORD offset = 0;
    if (ok) {
        ULONG shbLen = ReadU32(bytes, 4);
        if (! Require(shbLen >= 28 && shbLen <= size && (shbLen % 4) == 0,
                      "SHB length") ||
                ! Require(ReadU32(bytes, shbLen - 4) == shbLen,
                          "SHB trailing length")) {
            ok = 0;
        }
        else {
            offset = shbLen;
        }
    }

    ULONG snaplen = 0;
    if (ok) {
        if (! Require(offset + 20 <= size, "IDB header") ||
                ! Require(ReadU32(bytes, offset) == PCAPNG_IDB_TYPE,
                          "IDB type") ||
                ! Require(ReadU16(bytes, offset + 8) == PCAPNG_LINKTYPE_RAW,
                          "LINKTYPE_RAW")) {
            ok = 0;
        }
        else {
            snaplen = ReadU32(bytes, offset + 12);
            ULONG idbLen = ReadU32(bytes, offset + 4);
            if (! Require(snaplen == 256, "IDB snaplen") ||
                    ! Require(idbLen >= 20 && offset + idbLen <= size,
                              "IDB length")) {
                ok = 0;
            }
            else {
                offset += idbLen;
            }
        }
    }

    if (ok) {
        if (! Require(offset + 32 <= size, "EPB header") ||
                ! Require(ReadU32(bytes, offset) == PCAPNG_EPB_TYPE,
                          "EPB type")) {
            ok = 0;
        }
        else {
            ULONG captured = ReadU32(bytes, offset + 20);
            ULONG original = ReadU32(bytes, offset + 24);
            if (! Require(captured == 40, "EPB captured length") ||
                    ! Require(original == 40, "EPB original length") ||
                    ! Require(offset + 28 + 40 <= size, "EPB packet bytes") ||
                    ! Require(memcmp(bytes + offset + 28, packet, 40) == 0,
                              "EPB packet payload")) {
                ok = 0;
            }
        }
    }

    free(bytes);
    DeleteFileW(path);
    return ok;
}


static int SkipToEpb(const UCHAR *bytes, DWORD size, DWORD *offset)
{
    if (size < 32 || ReadU32(bytes, 0) != PCAPNG_SHB_TYPE)
        return 0;
    DWORD cursor = ReadU32(bytes, 4);
    if (cursor < 28 || cursor >= size || ReadU32(bytes, cursor) != PCAPNG_IDB_TYPE)
        return 0;
    cursor += ReadU32(bytes, cursor + 4);
    if (cursor + 32 > size || ReadU32(bytes, cursor) != PCAPNG_EPB_TYPE)
        return 0;
    *offset = cursor;
    return 1;
}


static int TestEpbCommentContainsProcessMetadata(void)
{
    WCHAR path[MAX_PATH];
    MakeTempPath(path, MAX_PATH, L"sbie-pcapng-meta.pcapng");
    DeleteFileW(path);

    PCAPNG_WRITER *writer = PcapngWriter_OpenPath(path, 256, 1024 * 1024, 0);
    if (! Require(writer != NULL, "open writer for metadata"))
        return 0;

    UCHAR packet[40];
    BuildIpv4TcpSyn(packet);

    PCAPNG_PACKET record;
    memset(&record, 0, sizeof(record));
    record.original_length = 40;
    record.captured_length = 40;
    record.process_id = 4242;
    record.session_id = 1;
    record.process_create_time = 133000000000000001ull;
    record.data = packet;
    record.box_name = L"DefaultBox";
    record.sid_string = L"S-1-5-21-1-2-3-1001";

    int status = PcapngWriter_Write(writer, &record);
    PcapngWriter_Close(writer);
    if (! Require(status == PCAPNG_OK, "write metadata packet")) {
        DeleteFileW(path);
        return 0;
    }

    UCHAR *bytes = NULL;
    DWORD size = 0;
    if (! Require(ReadAll(path, &bytes, &size), "read metadata file")) {
        DeleteFileW(path);
        return 0;
    }

    DWORD offset = 0;
    int ok = SkipToEpb(bytes, size, &offset);
    if (! Require(ok, "find EPB for metadata")) {
        free(bytes);
        DeleteFileW(path);
        return 0;
    }

    ULONG blockLength = ReadU32(bytes, offset + 4);
    ULONG captured = ReadU32(bytes, offset + 20);
    DWORD optionOffset = offset + 28 + ((captured + 3u) & ~3u);
    DWORD optionEnd = offset + blockLength - 4;
    int found = 0;
    if (Require(optionOffset < optionEnd && optionEnd <= size,
                "EPB option range")) {
        while (optionOffset + 4 <= optionEnd) {
            USHORT code = (USHORT)ReadU16(bytes, optionOffset);
            USHORT length = (USHORT)ReadU16(bytes, optionOffset + 2);
            if (code == 0)
                break;
            if (code == PCAPNG_OPT_COMMENT &&
                    optionOffset + 4 + length <= optionEnd) {
                char comment[512];
                ULONG copy = length < sizeof(comment) - 1 ? length :
                    (ULONG)sizeof(comment) - 1;
                memcpy(comment, bytes + optionOffset + 4, copy);
                comment[copy] = 0;
                found = strstr(comment, "pid=4242") &&
                    strstr(comment, "createTime=133000000000000001") &&
                    strstr(comment, "box=DefaultBox") &&
                    strstr(comment, "sid=S-1-5-21-1-2-3-1001") &&
                    strstr(comment, "session=1");
                break;
            }
            optionOffset += 4 + ((length + 3u) & ~3u);
        }
    }
    if (! Require(found, "EPB comment contains process metadata"))
        ok = 0;

    free(bytes);
    DeleteFileW(path);
    return ok;
}


static int TestSnaplenClampsCapturedButKeepsOriginal(void)
{
    WCHAR path[MAX_PATH];
    MakeTempPath(path, MAX_PATH, L"sbie-pcapng-snap.pcapng");
    DeleteFileW(path);

    PCAPNG_WRITER *writer = PcapngWriter_OpenPath(path, 20, 1024 * 1024, 0);
    if (! Require(writer != NULL, "open writer for snaplen"))
        return 0;

    UCHAR packet[40];
    BuildIpv4TcpSyn(packet);

    PCAPNG_PACKET record;
    memset(&record, 0, sizeof(record));
    record.original_length = 40;
    record.captured_length = 40;
    record.data = packet;

    int status = PcapngWriter_Write(writer, &record);
    PcapngWriter_Close(writer);
    if (! Require(status == PCAPNG_OK, "write snaplen packet")) {
        DeleteFileW(path);
        return 0;
    }

    UCHAR *bytes = NULL;
    DWORD size = 0;
    if (! Require(ReadAll(path, &bytes, &size), "read snaplen file")) {
        DeleteFileW(path);
        return 0;
    }

    DWORD offset = 0;
    int ok = SkipToEpb(bytes, size, &offset);
    if (! Require(ok, "find EPB for snaplen")) {
        free(bytes);
        DeleteFileW(path);
        return 0;
    }

    ULONG captured = ReadU32(bytes, offset + 20);
    ULONG original = ReadU32(bytes, offset + 24);
    if (! Require(captured == 20, "snaplen captured length") ||
            ! Require(original == 40, "original length preserved") ||
            ! Require(memcmp(bytes + offset + 28, packet, 20) == 0,
                      "truncated packet prefix")) {
        ok = 0;
    }

    free(bytes);
    DeleteFileW(path);
    return ok;
}


static void RotatedPath(WCHAR *buffer, size_t capacity, const WCHAR *base, ULONG index)
{
    wcscpy_s(buffer, capacity, base);
    if (index == 0)
        return;

    WCHAR *dot = wcsrchr(buffer, L'.');
    WCHAR *slash = wcsrchr(buffer, L'\\');
    if (! dot || (slash && dot < slash)) {
        swprintf_s(buffer, capacity, L"%s.%lu.pcapng", base, index);
        return;
    }

    WCHAR suffix[32];
    swprintf_s(suffix, ARRAYSIZE(suffix), L".%lu", index);
    WCHAR tail[MAX_PATH];
    wcscpy_s(tail, ARRAYSIZE(tail), dot);
    *dot = 0;
    wcscat_s(buffer, capacity, suffix);
    wcscat_s(buffer, capacity, tail);
}


static int WriteMinimalPacket(PCAPNG_WRITER *writer)
{
    UCHAR packet[40];
    BuildIpv4TcpSyn(packet);
    PCAPNG_PACKET record;
    memset(&record, 0, sizeof(record));
    record.original_length = 40;
    record.captured_length = 40;
    record.data = packet;
    return PcapngWriter_Write(writer, &record);
}


static int TestSizeLimitStopsWhenRotationDisabled(void)
{
    WCHAR path[MAX_PATH];
    MakeTempPath(path, MAX_PATH, L"sbie-pcapng-stop.pcapng");
    DeleteFileW(path);

    PCAPNG_WRITER *writer = PcapngWriter_OpenPath(path, 256, 200, 0);
    if (! Require(writer != NULL, "open writer for stop"))
        return 0;

    int first = WriteMinimalPacket(writer);
    int second = WriteMinimalPacket(writer);
    BOOL stopped = PcapngWriter_IsStopped(writer);
    ULONG64 packets = PcapngWriter_PacketCount(writer);
    PcapngWriter_Close(writer);

    int ok = Require(first == PCAPNG_OK, "first packet before stop") &&
        Require(second == PCAPNG_STOPPED, "second packet stops") &&
        Require(stopped, "writer marked stopped") &&
        Require(packets == 1, "only one packet retained");

    WCHAR rotated[MAX_PATH];
    RotatedPath(rotated, MAX_PATH, path, 1);
    if (! Require(GetFileAttributesW(rotated) == INVALID_FILE_ATTRIBUTES,
                  "no rotated file when rotate_count is 0"))
        ok = 0;

    DeleteFileW(path);
    DeleteFileW(rotated);
    return ok;
}


static int TestRotationWritesFreshShbIdb(void)
{
    WCHAR path[MAX_PATH];
    WCHAR rotated[MAX_PATH];
    MakeTempPath(path, MAX_PATH, L"sbie-pcapng-rot.pcapng");
    RotatedPath(rotated, MAX_PATH, path, 1);
    DeleteFileW(path);
    DeleteFileW(rotated);

    PCAPNG_WRITER *writer = PcapngWriter_OpenPath(path, 256, 200, 2);
    if (! Require(writer != NULL, "open writer for rotate"))
        return 0;

    int first = WriteMinimalPacket(writer);
    int second = WriteMinimalPacket(writer);
    ULONG fileIndex = PcapngWriter_FileIndex(writer);
    ULONG64 packets = PcapngWriter_PacketCount(writer);
    PcapngWriter_Close(writer);

    int ok = Require(first == PCAPNG_OK, "first packet before rotate") &&
        Require(second == PCAPNG_ROTATED, "second packet rotates") &&
        Require(fileIndex == 1, "file index after rotate") &&
        Require(packets == 2, "both packets written");

    UCHAR *bytes = NULL;
    DWORD size = 0;
    if (! Require(GetFileAttributesW(rotated) != INVALID_FILE_ATTRIBUTES,
                  "rotated file exists") ||
            ! Require(ReadAll(rotated, &bytes, &size), "read rotated file")) {
        DeleteFileW(path);
        DeleteFileW(rotated);
        return 0;
    }

    if (! Require(size >= 32, "rotated file has SHB") ||
            ! Require(ReadU32(bytes, 0) == PCAPNG_SHB_TYPE,
                      "rotated SHB type") ||
            ! Require(ReadU32(bytes, 8) == PCAPNG_BOM_LE,
                      "rotated BOM")) {
        ok = 0;
    }
    else {
        DWORD offset = 0;
        if (! Require(SkipToEpb(bytes, size, &offset),
                      "rotated file has EPB"))
            ok = 0;
    }

    free(bytes);
    DeleteFileW(path);
    DeleteFileW(rotated);
    return ok;
}


static int TestOpenHandleUsesCallerFile(void)
{
    WCHAR path[MAX_PATH];
    MakeTempPath(path, MAX_PATH, L"sbie-pcapng-handle.pcapng");
    DeleteFileW(path);

    HANDLE file = CreateFileW(
        path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (! Require(file != INVALID_HANDLE_VALUE, "open caller output handle"))
        return 0;

    PCAPNG_WRITER *writer = PcapngWriter_OpenHandle(
        file, path, 256, 1024 * 1024, 0);
    if (! Require(writer != NULL, "open writer from caller handle")) {
        CloseHandle(file);
        DeleteFileW(path);
        return 0;
    }

    int status = WriteMinimalPacket(writer);
    PcapngWriter_Close(writer);
    if (! Require(status == PCAPNG_OK, "write through caller handle")) {
        DeleteFileW(path);
        return 0;
    }

    UCHAR *bytes = NULL;
    DWORD size = 0;
    int ok = Require(ReadAll(path, &bytes, &size), "read caller-handle output");
    if (ok)
        ok = Require(size >= 32 && ReadU32(bytes, 0) == PCAPNG_SHB_TYPE,
                     "caller-handle output has SHB");

    free(bytes);
    DeleteFileW(path);
    return ok;
}


int main(int argc, char **argv)
{
    if (argc >= 3 && strcmp(argv[1], "--write") == 0) {
        WCHAR path[MAX_PATH];
        if (MultiByteToWideChar(CP_UTF8, 0, argv[2], -1, path, MAX_PATH) <= 0)
            return 2;
        PCAPNG_WRITER *writer = PcapngWriter_OpenPath(
            path, 256, 1024 * 1024, 0);
        if (! writer)
            return 2;
        int status = WriteMinimalPacket(writer);
        PcapngWriter_Close(writer);
        return status == PCAPNG_OK ? 0 : 3;
    }

    if (! TestWritesShbIdbAndOneEpb() ||
            ! TestEpbCommentContainsProcessMetadata() ||
            ! TestSnaplenClampsCapturedButKeepsOriginal() ||
            ! TestSizeLimitStopsWhenRotationDisabled() ||
            ! TestRotationWritesFreshShbIdb() ||
            ! TestOpenHandleUsesCallerFile())
        return 1;

    printf("pcapng tests passed\n");
    return 0;
}
