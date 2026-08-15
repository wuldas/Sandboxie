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
// SbieCapture broker -- bounded user-mode packet drain
//---------------------------------------------------------------------------

#include "capture_broker.h"

#include <stddef.h>
#include <string.h>


static BOOL CaptureBroker_StringTerminated(
    const WCHAR *value, ULONG capacity)
{
    ULONG index;
    for (index = 0; index < capacity; ++index) {
        if (value[index] == L'\0')
            return index != 0;
    }
    return FALSE;
}


static BOOL CaptureBroker_ValidateSection(
    const CAPTURE_BROKER_SECTION *section)
{
    if (! section ||
            section->magic != CAPTURE_BROKER_SECTION_MAGIC ||
            section->version != CAPTURE_BROKER_SECTION_VERSION ||
            section->record_capacity == 0 ||
            section->record_capacity > CAPTURE_BROKER_MAX_RECORD_CAPACITY ||
            section->size != CAPTURE_BROKER_SECTION_SIZE(
                section->record_capacity) ||
            section->reserved != 0 ||
            section->capture_id_high == 0 ||
            section->capture_id_low == 0 ||
            section->generation != CaptureBroker_CalculateGeneration(
                section->capture_id_high, section->capture_id_low) ||
            ! CaptureBroker_StringTerminated(
                section->box_name, ARRAYSIZE(section->box_name)) ||
            ! CaptureBroker_StringTerminated(
                section->sid_string, ARRAYSIZE(section->sid_string))) {
        return FALSE;
    }
    return TRUE;
}


static BOOL CaptureBroker_ValidateBinding(
    const CAPTURE_BROKER_SECTION *section,
    const CAPTURE_BROKER_OPTIONS *options)
{
    if (! options)
        return FALSE;

    if (! options->expected_capture_id_high &&
            ! options->expected_capture_id_low &&
            ! options->expected_generation) {
        return TRUE;
    }

    return options->expected_capture_id_high != 0 &&
        options->expected_capture_id_low != 0 &&
        options->expected_generation != 0 &&
        section->capture_id_high == options->expected_capture_id_high &&
        section->capture_id_low == options->expected_capture_id_low &&
        section->generation == options->expected_generation;
}


static BOOL CaptureBroker_StopEventSignaled(HANDLE stopEvent)
{
    if (! stopEvent)
        return FALSE;
    return WaitForSingleObject(stopEvent, 0) == WAIT_OBJECT_0;
}


static void CaptureBroker_AddDrops(
    CAPTURE_BROKER_SECTION *section, ULONG64 count)
{
    ULONG64 maximum = (ULONG64)-1;
    if (maximum - section->dropped_count < count)
        section->dropped_count = maximum;
    else
        section->dropped_count += count;
}


static BOOL CaptureBroker_ValidateRuntimeSection(
    const CAPTURE_BROKER_SECTION *section)
{
    return section &&
        section->magic == CAPTURE_BROKER_SECTION_MAGIC &&
        section->version == CAPTURE_BROKER_SECTION_VERSION &&
        section->size == CAPTURE_BROKER_SECTION_SIZE(
            CAPTURE_BROKER_MAX_RECORD_CAPACITY) &&
        section->record_capacity == CAPTURE_BROKER_MAX_RECORD_CAPACITY &&
        section->capture_id_high != 0 &&
        section->capture_id_low != 0 &&
        section->generation == CaptureBroker_CalculateGeneration(
            section->capture_id_high, section->capture_id_low) &&
        section->reserved == 0 &&
        CaptureBroker_StringTerminated(
            section->box_name, ARRAYSIZE(section->box_name)) &&
        CaptureBroker_StringTerminated(
            section->sid_string, ARRAYSIZE(section->sid_string));
}


static BOOL CaptureBroker_ValidateRecord(
    const CAPTURE_PACKET_RECORD *record)
{
    if (! record || record->sequence == 0 ||
            (record->layer != CAPTURE_PACKET_LAYER_TRANSPORT &&
             record->layer != CAPTURE_PACKET_LAYER_DATAGRAM) ||
            (record->direction != CAPTURE_PACKET_DIRECTION_OUTBOUND &&
             record->direction != CAPTURE_PACKET_DIRECTION_INBOUND) ||
            (record->address_family != CAPTURE_ADDRESS_FAMILY_IPV4 &&
             record->address_family != CAPTURE_ADDRESS_FAMILY_IPV6) ||
            record->loopback > 1 ||
            record->captured_length > sizeof(record->data) ||
            record->captured_length > CAPTURE_PACKET_SNAPLEN_MAX ||
            record->original_length < record->captured_length ||
            record->reserved1 || record->reserved2[0] ||
            record->reserved2[1]) {
        return FALSE;
    }
    return TRUE;
}


static void CaptureBroker_WriteBe16(UCHAR *output, ULONG value)
{
    output[0] = (UCHAR)(value >> 8);
    output[1] = (UCHAR)value;
}


static USHORT CaptureBroker_Ipv4Checksum(const UCHAR *header)
{
    ULONG sum = 0;
    for (ULONG index = 0; index < 20; index += 2)
        sum += ((ULONG)header[index] << 8) | header[index + 1];
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (USHORT)~sum;
}


BOOL CaptureBroker_BuildRawPacket(
    const CAPTURE_PACKET_RECORD *record,
    UCHAR *buffer,
    ULONG capacity,
    ULONG *capturedLength,
    ULONG *originalLength)
{
    if (! record || ! buffer || ! capturedLength || ! originalLength ||
            record->captured_length > sizeof(record->data) ||
            record->original_length < record->captured_length ||
            (record->direction != CAPTURE_PACKET_DIRECTION_OUTBOUND &&
             record->direction != CAPTURE_PACKET_DIRECTION_INBOUND)) {
        return FALSE;
    }

    ULONG headerLength;
    if (record->address_family == CAPTURE_ADDRESS_FAMILY_IPV4)
        headerLength = 20;
    else if (record->address_family == CAPTURE_ADDRESS_FAMILY_IPV6)
        headerLength = 40;
    else
        return FALSE;

    if (capacity < headerLength ||
            record->captured_length > capacity - headerLength)
        return FALSE;

    const UCHAR *source = record->direction ==
            CAPTURE_PACKET_DIRECTION_OUTBOUND ?
        record->local_address : record->remote_address;
    const UCHAR *destination = record->direction ==
            CAPTURE_PACKET_DIRECTION_OUTBOUND ?
        record->remote_address : record->local_address;
    memset(buffer, 0, headerLength);

    if (record->address_family == CAPTURE_ADDRESS_FAMILY_IPV4) {
        ULONG totalLength = record->original_length > 0xffff - headerLength ?
            0xffff : record->original_length + headerLength;
        buffer[0] = 0x45;
        CaptureBroker_WriteBe16(buffer + 2, totalLength);
        buffer[8] = 128;
        buffer[9] = record->protocol;
        memcpy(buffer + 12, source, 4);
        memcpy(buffer + 16, destination, 4);
        CaptureBroker_WriteBe16(
            buffer + 10, CaptureBroker_Ipv4Checksum(buffer));
    }
    else {
        ULONG payloadLength = record->original_length > 0xffff ?
            0xffff : record->original_length;
        buffer[0] = 0x60;
        CaptureBroker_WriteBe16(buffer + 4, payloadLength);
        buffer[6] = record->protocol;
        buffer[7] = 128;
        memcpy(buffer + 8, source, 16);
        memcpy(buffer + 24, destination, 16);
    }

    if (record->captured_length) {
        memcpy(
            buffer + headerLength,
            record->data,
            record->captured_length);
    }
    *capturedLength = headerLength + record->captured_length;
    *originalLength = record->original_length > (ULONG)-1 - headerLength ?
        (ULONG)-1 : headerLength + record->original_length;
    return TRUE;
}


static int CaptureBroker_DrainAvailable(
    CAPTURE_BROKER_SECTION *section,
    PCAPNG_WRITER *writer,
    BOOL *writerStopped)
{
    const ULONG capacity = CAPTURE_BROKER_MAX_RECORD_CAPACITY;
    ULONG writeIndex;
    ULONG readIndex;

    *writerStopped = FALSE;
    if (! CaptureBroker_ValidateRuntimeSection(section))
        return CAPTURE_BROKER_INVALID;
    MemoryBarrier();
    writeIndex = section->write_index;
    readIndex = section->read_index;

    ULONG pending = writeIndex - readIndex;
    if (pending > capacity) {
        readIndex = writeIndex - capacity;
        section->read_index = readIndex;
        pending = capacity;
    }

    while (pending != 0) {
        CAPTURE_PACKET_RECORD record = { 0 };
        CAPTURE_PACKET_RECORD *slot =
            &section->records[readIndex % capacity];
        ULONG64 publishedSequence = 0;
        BOOL stable = FALSE;
        PCAPNG_PACKET packet;
        int status;

        for (int attempt = 0; attempt != 3; ++attempt) {
            MemoryBarrier();
            publishedSequence = slot->sequence;
            if (!publishedSequence)
                continue;
            memcpy(&record, slot, sizeof(record));
            MemoryBarrier();
            if (publishedSequence == slot->sequence &&
                    record.sequence == publishedSequence) {
                stable = TRUE;
                break;
            }
        }
        ++readIndex;
        section->read_index = readIndex;
        --pending;
        if (!stable) {
            CaptureBroker_AddDrops(section, 1);
            continue;
        }
        if (! CaptureBroker_ValidateRecord(&record)) {
            CaptureBroker_AddDrops(section, 1);
            return CAPTURE_BROKER_INVALID;
        }

        UCHAR rawPacket[CAPTURE_BROKER_RAW_PACKET_MAX];
        ULONG rawCapturedLength = 0;
        ULONG rawOriginalLength = 0;
        if (! CaptureBroker_BuildRawPacket(
                &record,
                rawPacket,
                sizeof(rawPacket),
                &rawCapturedLength,
                &rawOriginalLength)) {
            CaptureBroker_AddDrops(section, 1);
            return CAPTURE_BROKER_INVALID;
        }
        memset(&packet, 0, sizeof(packet));
        packet.timestamp_filetime = record.timestamp;
        packet.original_length = rawOriginalLength;
        packet.captured_length = rawCapturedLength;
        packet.process_id = record.process_id;
        packet.session_id = record.session_id;
        packet.process_create_time = record.process_create_time;
        packet.data = rawPacket;
        packet.box_name = section->box_name;
        packet.sid_string = section->sid_string;

        status = PcapngWriter_Write(writer, &packet);
        section->packet_count = PcapngWriter_PacketCount(writer);
        section->byte_count = PcapngWriter_ByteCount(writer);
        section->current_file_index = PcapngWriter_FileIndex(writer);

        if (status == PCAPNG_STOPPED) {
            *writerStopped = TRUE;
            return CAPTURE_BROKER_OK;
        }
        if (status != PCAPNG_OK && status != PCAPNG_ROTATED)
            return CAPTURE_BROKER_ERROR;
    }

    return CAPTURE_BROKER_OK;
}


int CaptureBroker_Run(
    CAPTURE_BROKER_SECTION *section,
    const CAPTURE_BROKER_OPTIONS *options)
{
    if (! section || ! CaptureBroker_ValidateSection(section)) {
        if (section) {
            section->broker_status = CAPTURE_BROKER_STATE_FAILED;
            section->error_status = ERROR_INVALID_DATA;
        }
        if (options && options->output_file &&
                options->output_file != INVALID_HANDLE_VALUE) {
            CloseHandle(options->output_file);
        }
        return CAPTURE_BROKER_INVALID;
    }

    if (! options || options->output_file == NULL ||
            options->output_file == INVALID_HANDLE_VALUE) {
        section->broker_status = CAPTURE_BROKER_STATE_FAILED;
        section->error_status = ERROR_INVALID_PARAMETER;
        return CAPTURE_BROKER_INVALID;
    }

    if (! CaptureBroker_ValidateBinding(section, options)) {
        CloseHandle(options->output_file);
        section->broker_status = CAPTURE_BROKER_STATE_FAILED;
        section->error_status = ERROR_INVALID_DATA;
        return CAPTURE_BROKER_INVALID;
    }

    if ((options->snap_length != 0 &&
            (options->snap_length < CAPTURE_BROKER_SNAP_LENGTH_MIN ||
             options->snap_length > CAPTURE_BROKER_SNAP_LENGTH_MAX)) ||
            options->max_seconds > CAPTURE_BROKER_MAX_SECONDS ||
            options->rotate_count > CAPTURE_BROKER_MAX_ROTATE_COUNT) {
        CloseHandle(options->output_file);
        section->broker_status = CAPTURE_BROKER_STATE_FAILED;
        section->error_status = ERROR_INVALID_PARAMETER;
        return CAPTURE_BROKER_INVALID;
    }

    section->broker_status = CAPTURE_BROKER_STATE_STARTING;
    section->error_status = ERROR_SUCCESS;

    PCAPNG_WRITER *writer = PcapngWriter_OpenHandle(
        options->output_file,
        options->rotation_path,
        options->snap_length,
        options->max_file_bytes,
        options->rotate_count);
    if (! writer) {
        section->broker_status = CAPTURE_BROKER_STATE_FAILED;
        section->error_status = GetLastError();
        CloseHandle(options->output_file);
        return CAPTURE_BROKER_ERROR;
    }

    section->broker_status = CAPTURE_BROKER_STATE_RUNNING;
    const ULONG maxSeconds = options->max_seconds != 0 ?
        options->max_seconds : 300;
    const ULONGLONG startTick = GetTickCount64();
    int result = CAPTURE_BROKER_OK;

    for (;;) {
        BOOL writerStopped = FALSE;
        int drainStatus = CaptureBroker_DrainAvailable(
            section, writer, &writerStopped);
        if (drainStatus != CAPTURE_BROKER_OK) {
            section->broker_status = CAPTURE_BROKER_STATE_FAILED;
            section->error_status = drainStatus == CAPTURE_BROKER_INVALID ?
                ERROR_INVALID_DATA : ERROR_WRITE_FAULT;
            result = CAPTURE_BROKER_ERROR;
            break;
        }
        if (writerStopped || section->stop_requested ||
                CaptureBroker_StopEventSignaled(options->stop_event)) {
            break;
        }

        if (GetTickCount64() - startTick >=
                (ULONGLONG)maxSeconds * 1000ull) {
            InterlockedExchange(&section->stop_requested, 1);
            break;
        }

        Sleep(1);
    }

    section->packet_count = PcapngWriter_PacketCount(writer);
    section->byte_count = PcapngWriter_ByteCount(writer);
    section->current_file_index = PcapngWriter_FileIndex(writer);
    PcapngWriter_Close(writer);

    if (result == CAPTURE_BROKER_OK)
        section->broker_status = CAPTURE_BROKER_STATE_STOPPED;
    return result;
}
