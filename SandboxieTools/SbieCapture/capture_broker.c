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
            section->reserved2 != 0 ||
            ! CaptureBroker_StringTerminated(
                section->box_name, ARRAYSIZE(section->box_name)) ||
            ! CaptureBroker_StringTerminated(
                section->sid_string, ARRAYSIZE(section->sid_string))) {
        return FALSE;
    }
    return TRUE;
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


static int CaptureBroker_DrainAvailable(
    CAPTURE_BROKER_SECTION *section,
    PCAPNG_WRITER *writer,
    BOOL *writerStopped)
{
    ULONG capacity = section->record_capacity;
    ULONG writeIndex;
    ULONG readIndex;

    *writerStopped = FALSE;
    MemoryBarrier();
    writeIndex = section->write_index;
    readIndex = section->read_index;

    ULONG pending = writeIndex - readIndex;
    if (pending > capacity) {
        ULONG skipped = pending - capacity;
        CaptureBroker_AddDrops(section, skipped);
        readIndex = writeIndex - capacity;
        section->read_index = readIndex;
        pending = capacity;
    }

    while (pending != 0) {
        CAPTURE_PACKET_RECORD record;
        PCAPNG_PACKET packet;
        int status;

        MemoryBarrier();
        memcpy(&record, &section->records[readIndex % capacity],
               sizeof(record));
        ++readIndex;
        section->read_index = readIndex;
        --pending;

        memset(&packet, 0, sizeof(packet));
        packet.timestamp_filetime = record.timestamp;
        packet.original_length = record.original_length;
        packet.captured_length = record.captured_length;
        packet.process_id = record.process_id;
        packet.session_id = record.session_id;
        packet.process_create_time = record.process_create_time;
        packet.data = record.data;
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
            section->error_status = ERROR_WRITE_FAULT;
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
