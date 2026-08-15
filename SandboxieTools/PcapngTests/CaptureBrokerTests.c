/*
 * Copyright 2026 David Xanatos, xanasoft.com
 *
 * This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

//---------------------------------------------------------------------------
// SbieCapture broker tests -- fake mapped ring, no driver
//---------------------------------------------------------------------------

#include <windows.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../SbieCapture/capture_broker.h"


static int g_keep_outputs = 0;


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


static CAPTURE_BROKER_SECTION *CreateSection(ULONG capacity)
{
    (void)capacity;
    capacity = CAPTURE_BROKER_MAX_RECORD_CAPACITY;
    size_t size = offsetof(CAPTURE_BROKER_SECTION, records) +
        (size_t)capacity * sizeof(CAPTURE_PACKET_RECORD);
    CAPTURE_BROKER_SECTION *section =
        (CAPTURE_BROKER_SECTION *)calloc(1, size);
    if (! section)
        return NULL;
    section->magic = CAPTURE_BROKER_SECTION_MAGIC;
    section->version = CAPTURE_BROKER_SECTION_VERSION;
    section->size = (ULONG)size;
    section->record_capacity = capacity;
    section->capture_id_high = 0x1111111111111111ull;
    section->capture_id_low = 0x2222222222222222ull;
    section->generation = CaptureBroker_CalculateGeneration(
        section->capture_id_high, section->capture_id_low);
    wcscpy_s(section->box_name, ARRAYSIZE(section->box_name), L"DefaultBox");
    wcscpy_s(section->sid_string, ARRAYSIZE(section->sid_string),
             L"S-1-5-21-1-2-3-1001");
    return section;
}


static void FillRecord(CAPTURE_PACKET_RECORD *record, ULONG processId, UCHAR value)
{
    memset(record, 0, sizeof(*record));
    record->sequence = processId;
    record->timestamp = 133000000000000000ull;
    record->process_create_time = 133000000000000001ull;
    record->process_id = processId;
    record->session_id = 1;
    record->address_family = AF_INET;
    record->protocol = 6;
    record->direction = CAPTURE_PACKET_DIRECTION_OUTBOUND;
    record->layer = CAPTURE_PACKET_LAYER_TRANSPORT;
    record->original_length = 40;
    record->captured_length = 40;
    record->local_address[0] = 10;
    record->local_address[3] = 1;
    record->remote_address[0] = 1;
    record->remote_address[1] = 1;
    record->remote_address[2] = 1;
    record->remote_address[3] = 1;
    record->local_port = 40000;
    record->remote_port = 80;
    memset(record->data, value, record->captured_length);
}


static int FileHasBytes(const WCHAR *path)
{
    HANDLE file = CreateFileW(
        path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return 0;
    DWORD size = GetFileSize(file, NULL);
    CloseHandle(file);
    return size > 32;
}


static int TestBrokerDrainsRingAndWritesPcapng(void)
{
    WCHAR path[MAX_PATH];
    MakeTempPath(path, MAX_PATH, L"sbie-broker-test.pcapng");
    DeleteFileW(path);

    CAPTURE_BROKER_SECTION *section = CreateSection(4);
    if (! Require(section != NULL, "allocate broker section"))
        return 0;
    FillRecord(&section->records[0], 4242, 0x11);
    FillRecord(&section->records[1], 4343, 0x22);
    section->write_index = 2;
    section->stop_requested = 1;

    HANDLE file = CreateFileW(
        path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (! Require(file != INVALID_HANDLE_VALUE, "open broker output")) {
        free(section);
        return 0;
    }

    CAPTURE_BROKER_OPTIONS options;
    memset(&options, 0, sizeof(options));
    options.output_file = file;
    options.rotation_path = path;
    options.snap_length = 256;
    options.max_file_bytes = 1024 * 1024;
    options.max_seconds = 5;

    int status = CaptureBroker_Run(section, &options);
    int ok = Require(status == CAPTURE_BROKER_OK, "broker run status") &&
        Require(section->read_index == 2, "broker drains all records") &&
        Require(section->packet_count == 2, "broker packet count") &&
        Require(section->byte_count == 120, "broker byte count") &&
        Require(section->broker_status == CAPTURE_BROKER_STATE_STOPPED,
                "broker stopped state") &&
        Require(FileHasBytes(path), "broker writes pcapng bytes");

    if (! g_keep_outputs)
        DeleteFileW(path);
    free(section);
    return ok;
}


static int TestBrokerReportsRingOverflow(void)
{
    WCHAR path[MAX_PATH];
    MakeTempPath(path, MAX_PATH, L"sbie-broker-overflow.pcapng");
    DeleteFileW(path);

    CAPTURE_BROKER_SECTION *section = CreateSection(
        CAPTURE_BROKER_MAX_RECORD_CAPACITY);
    if (! Require(section != NULL, "allocate overflow section"))
        return 0;

    const ULONG writeCount = CAPTURE_BROKER_MAX_RECORD_CAPACITY + 904;
    for (ULONG index = writeCount - CAPTURE_BROKER_MAX_RECORD_CAPACITY;
            index < writeCount; ++index) {
        CAPTURE_PACKET_RECORD *record = &section->records[
            index % CAPTURE_BROKER_MAX_RECORD_CAPACITY];
        FillRecord(record, index + 1, (UCHAR)index);
        record->sequence = (ULONG64)index + 1;
    }
    section->write_index = writeCount;
    section->dropped_count = 904;
    section->stop_requested = 1;

    HANDLE file = CreateFileW(
        path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (! Require(file != INVALID_HANDLE_VALUE, "open overflow output")) {
        free(section);
        return 0;
    }

    CAPTURE_BROKER_OPTIONS options;
    memset(&options, 0, sizeof(options));
    options.output_file = file;
    options.rotation_path = path;
    options.snap_length = 256;
    options.max_file_bytes = 16 * 1024 * 1024;
    options.max_seconds = 5;

    int status = CaptureBroker_Run(section, &options);
    int ok = Require(status == CAPTURE_BROKER_OK,
                     "overflow broker run status") &&
        Require(section->read_index == writeCount,
                "overflow broker advances read index") &&
        Require(section->packet_count == CAPTURE_BROKER_MAX_RECORD_CAPACITY,
                "overflow broker retains ring capacity") &&
        Require(section->dropped_count == 904,
                "overflow broker reports skipped records") &&
        Require(section->broker_status == CAPTURE_BROKER_STATE_STOPPED,
                "overflow broker stopped state") &&
        Require(FileHasBytes(path), "overflow broker writes pcapng bytes");

    if (! g_keep_outputs)
        DeleteFileW(path);
    free(section);
    return ok;
}


static int TestBrokerRotatesAtFileLimit(void)
{
    WCHAR path[MAX_PATH];
    WCHAR rotated[MAX_PATH];
    MakeTempPath(path, MAX_PATH, L"sbie-broker-rotate.pcapng");
    wcscpy_s(rotated, ARRAYSIZE(rotated), path);
    WCHAR *dot = wcsrchr(rotated, L'.');
    WCHAR tail[MAX_PATH];
    wcscpy_s(tail, ARRAYSIZE(tail), dot ? dot : L"");
    if (dot) {
        *dot = L'\0';
        wcscat_s(rotated, ARRAYSIZE(rotated), L".1");
        wcscat_s(rotated, ARRAYSIZE(rotated), tail);
    }
    else {
        wcscat_s(rotated, ARRAYSIZE(rotated), L".1.pcapng");
    }
    DeleteFileW(path);
    DeleteFileW(rotated);

    CAPTURE_BROKER_SECTION *section = CreateSection(4);
    if (! Require(section != NULL, "allocate rotate section"))
        return 0;
    FillRecord(&section->records[0], 5001, 0x33);
    FillRecord(&section->records[1], 5002, 0x44);
    section->write_index = 2;
    section->stop_requested = 1;

    HANDLE file = CreateFileW(
        path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (! Require(file != INVALID_HANDLE_VALUE, "open rotate output")) {
        free(section);
        return 0;
    }

    CAPTURE_BROKER_OPTIONS options;
    memset(&options, 0, sizeof(options));
    options.output_file = file;
    options.rotation_path = path;
    options.snap_length = 256;
    options.max_file_bytes = 300;
    options.max_seconds = 5;
    options.rotate_count = 2;

    int status = CaptureBroker_Run(section, &options);
    int ok = Require(status == CAPTURE_BROKER_OK, "rotate broker status") &&
        Require(section->packet_count == 2, "rotate packet count") &&
        Require(section->current_file_index == 1, "rotate file index") &&
        Require(FileHasBytes(rotated), "rotated broker file exists");

    if (! g_keep_outputs) {
        DeleteFileW(path);
        DeleteFileW(rotated);
    }
    free(section);
    return ok;
}


static int TestBrokerRejectsMalformedSection(void)
{
    WCHAR path[MAX_PATH];
    MakeTempPath(path, MAX_PATH, L"sbie-broker-invalid.pcapng");
    DeleteFileW(path);

    CAPTURE_BROKER_SECTION *section = CreateSection(4);
    if (! Require(section != NULL, "allocate invalid section"))
        return 0;
    section->size = CAPTURE_BROKER_SECTION_BASE_SIZE;

    HANDLE file = CreateFileW(
        path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (! Require(file != INVALID_HANDLE_VALUE, "open invalid output")) {
        free(section);
        return 0;
    }

    CAPTURE_BROKER_OPTIONS options;
    memset(&options, 0, sizeof(options));
    options.output_file = file;
    options.snap_length = 256;

    int status = CaptureBroker_Run(section, &options);
    int ok = Require(status == CAPTURE_BROKER_INVALID,
                     "malformed section status") &&
        Require(section->broker_status == CAPTURE_BROKER_STATE_FAILED,
                "malformed section failed state") &&
        Require(section->error_status == ERROR_INVALID_DATA,
                "malformed section error status");

    DeleteFileW(path);
    free(section);
    return ok;
}


static int TestBrokerRejectsForeignBinding(void)
{
    WCHAR path[MAX_PATH];
    MakeTempPath(path, MAX_PATH, L"sbie-broker-foreign.pcapng");
    DeleteFileW(path);

    CAPTURE_BROKER_SECTION *section = CreateSection(4);
    if (! Require(section != NULL, "allocate foreign section"))
        return 0;

    HANDLE file = CreateFileW(
        path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (! Require(file != INVALID_HANDLE_VALUE, "open foreign output")) {
        free(section);
        return 0;
    }

    CAPTURE_BROKER_OPTIONS options;
    memset(&options, 0, sizeof(options));
    options.output_file = file;
    options.expected_capture_id_high = section->capture_id_high + 1;
    options.expected_capture_id_low = section->capture_id_low;
    options.expected_generation = CaptureBroker_CalculateGeneration(
        options.expected_capture_id_high, options.expected_capture_id_low);

    int status = CaptureBroker_Run(section, &options);
    int ok = Require(status == CAPTURE_BROKER_INVALID,
                     "foreign binding status") &&
        Require(section->broker_status == CAPTURE_BROKER_STATE_FAILED,
                "foreign binding failed state") &&
        Require(section->error_status == ERROR_INVALID_DATA,
                "foreign binding error status");

    DeleteFileW(path);
    free(section);
    return ok;
}


static int TestBrokerRejectsMalformedRecord(void)
{
    WCHAR path[MAX_PATH];
    MakeTempPath(path, MAX_PATH, L"sbie-broker-invalid-record.pcapng");
    DeleteFileW(path);

    CAPTURE_BROKER_SECTION *section = CreateSection(4);
    if (! Require(section != NULL, "allocate invalid record section"))
        return 0;
    FillRecord(&section->records[0], 6001, 0x55);
    section->records[0].captured_length =
        CAPTURE_PACKET_SNAPLEN_MAX + 1;
    section->write_index = 1;
    section->stop_requested = 1;

    HANDLE file = CreateFileW(
        path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (! Require(file != INVALID_HANDLE_VALUE, "open invalid record output")) {
        free(section);
        return 0;
    }

    CAPTURE_BROKER_OPTIONS options;
    memset(&options, 0, sizeof(options));
    options.output_file = file;
    options.snap_length = 256;

    int status = CaptureBroker_Run(section, &options);
    int ok = Require(status == CAPTURE_BROKER_ERROR,
                     "malformed record status") &&
        Require(section->broker_status == CAPTURE_BROKER_STATE_FAILED,
                "malformed record failed state") &&
        Require(section->error_status == ERROR_INVALID_DATA,
                "malformed record error status");

    DeleteFileW(path);
    free(section);
    return ok;
}


static int TestBuildRawIpv4Packet(void)
{
    CAPTURE_PACKET_RECORD record;
    FillRecord(&record, 7001, 0x5a);
    record.original_length = 20;
    record.captured_length = 20;

    UCHAR packet[CAPTURE_BROKER_RAW_PACKET_MAX];
    ULONG capturedLength = 0;
    ULONG originalLength = 0;
    int ok = Require(CaptureBroker_BuildRawPacket(
            &record, packet, sizeof(packet),
            &capturedLength, &originalLength),
            "build outbound IPv4 packet") &&
        Require(capturedLength == 40, "outbound IPv4 captured length") &&
        Require(originalLength == 40, "outbound IPv4 original length") &&
        Require(packet[0] == 0x45, "outbound IPv4 version and IHL") &&
        Require(packet[2] == 0 && packet[3] == 40,
                "outbound IPv4 total length") &&
        Require(packet[9] == IPPROTO_TCP, "outbound IPv4 protocol") &&
        Require(memcmp(packet + 12, record.local_address, 4) == 0,
                "outbound IPv4 source") &&
        Require(memcmp(packet + 16, record.remote_address, 4) == 0,
                "outbound IPv4 destination") &&
        Require(memcmp(packet + 20, record.data, 20) == 0,
                "outbound IPv4 transport payload");

    record.direction = CAPTURE_PACKET_DIRECTION_INBOUND;
    ok = Require(CaptureBroker_BuildRawPacket(
            &record, packet, sizeof(packet),
            &capturedLength, &originalLength),
            "build inbound IPv4 packet") &&
        Require(memcmp(packet + 12, record.remote_address, 4) == 0,
                "inbound IPv4 source") &&
        Require(memcmp(packet + 16, record.local_address, 4) == 0,
                "inbound IPv4 destination") && ok;
    return ok;
}


static int TestBuildRawIpv6Packet(void)
{
    CAPTURE_PACKET_RECORD record;
    FillRecord(&record, 7002, 0x6b);
    record.address_family = CAPTURE_ADDRESS_FAMILY_IPV6;
    memset(record.local_address, 0, sizeof(record.local_address));
    memset(record.remote_address, 0, sizeof(record.remote_address));
    record.local_address[0] = 0x20;
    record.local_address[1] = 0x01;
    record.local_address[2] = 0x0d;
    record.local_address[3] = 0xb8;
    record.local_address[15] = 1;
    record.remote_address[0] = 0x20;
    record.remote_address[1] = 0x01;
    record.remote_address[2] = 0x0d;
    record.remote_address[3] = 0xb8;
    record.remote_address[15] = 2;
    record.original_length = 20;
    record.captured_length = 20;

    UCHAR packet[CAPTURE_BROKER_RAW_PACKET_MAX];
    ULONG capturedLength = 0;
    ULONG originalLength = 0;
    return Require(CaptureBroker_BuildRawPacket(
            &record, packet, sizeof(packet),
            &capturedLength, &originalLength),
            "build outbound IPv6 packet") &&
        Require(capturedLength == 60, "outbound IPv6 captured length") &&
        Require(originalLength == 60, "outbound IPv6 original length") &&
        Require(packet[0] == 0x60, "outbound IPv6 version") &&
        Require(packet[4] == 0 && packet[5] == 20,
                "outbound IPv6 payload length") &&
        Require(packet[6] == IPPROTO_TCP, "outbound IPv6 next header") &&
        Require(memcmp(packet + 8, record.local_address, 16) == 0,
                "outbound IPv6 source") &&
        Require(memcmp(packet + 24, record.remote_address, 16) == 0,
                "outbound IPv6 destination") &&
        Require(memcmp(packet + 40, record.data, 20) == 0,
                "outbound IPv6 transport payload");
}


int main(int argc, char **argv)
{
    g_keep_outputs = argc == 2 && strcmp(argv[1], "--keep") == 0;
    if (! TestBuildRawIpv4Packet() ||
            ! TestBuildRawIpv6Packet() ||
            ! TestBrokerDrainsRingAndWritesPcapng() ||
            ! TestBrokerReportsRingOverflow() ||
            ! TestBrokerRotatesAtFileLimit() ||
            ! TestBrokerRejectsMalformedSection() ||
            ! TestBrokerRejectsForeignBinding() ||
            ! TestBrokerRejectsMalformedRecord())
        return 1;

    printf("capture broker tests passed\n");
    return 0;
}
