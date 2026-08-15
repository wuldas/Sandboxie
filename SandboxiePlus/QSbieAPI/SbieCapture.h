/*
 * Copyright (c) 2026, David Xanatos
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once


#include <QString>
#include <QList>
#include <QByteArray>

#include "qsbieapi_global.h"


struct QSBIEAPI_EXPORT SSbieCaptureId
{
    quint64 High = 0;
    quint64 Low = 0;

    bool IsNull() const { return High == 0 && Low == 0; }
};


struct QSBIEAPI_EXPORT SSbieCaptureCapabilities
{
    enum EFlags
    {
        eControl = 0x00000001,
        eConnectionAudit = 0x00000002,
        ePacketCapture = 0x00000004,
        eHttpsInspection = 0x00000008,
        ePcapngExport = 0x00000010,
        eHarExport = 0x00000020,
    };

    quint32 WireVersion = 0;
    quint32 MinWireVersion = 0;
    quint32 MaxWireVersion = 0;
    quint32 Flags = 0;
    quint32 MaxSessionsPerOwner = 0;
    quint32 MaxListEntries = 0;
    quint32 MaxEventEntries = 0;
};


struct QSBIEAPI_EXPORT SSbieCaptureStart
{
    enum EScope
    {
        eBox = 1,
        eProcess = 2,
    };

    enum EMode
    {
        eConnections = 0x00000001,
        ePackets = 0x00000002,
        eHttps = 0x00000004,
    };

    enum EFlags
    {
        eIncludeFutureProcesses = 0x00000001,
        eIncludeLoopback = 0x00000002,
    };

    quint32 Scope = eBox;
    quint32 Mode = eConnections;
    quint32 Flags = eIncludeFutureProcesses;
    quint32 ProcessId = 0;
    QString BoxName;
    quint32 SnapLength = 0;
    quint32 MaxFileBytes = 0;
    quint32 MaxSeconds = 0;
    quint32 RotateCount = 0;
};


struct QSBIEAPI_EXPORT SSbieCaptureSession
{
    enum EState
    {
        eStarting = 1,
        eWaitingForBackend = 2,
        eRunning = 3,
        eStopped = 4,
        eFailed = 5,
    };

    SSbieCaptureId Id;
    quint32 State = 0;
    quint32 Scope = 0;
    quint32 Mode = 0;
    quint32 Flags = 0;
    quint32 TargetProcessId = 0;
    quint32 TargetSessionId = 0;
    quint64 TargetProcessCreateTime = 0;
    quint64 StartedTime = 0;
    quint64 StoppedTime = 0;
    quint64 EventCount = 0;
    quint64 PacketCount = 0;
    quint64 ByteCount = 0;
    quint64 DroppedCount = 0;
    quint32 BackendStatus = 0;
    QString BoxName;
};


struct QSBIEAPI_EXPORT SSbieCaptureList
{
    quint32 TotalCount = 0;
    quint32 NextIndex = 0;
    QList<SSbieCaptureSession> Sessions;
};


struct QSBIEAPI_EXPORT SSbieCaptureEvent
{
    enum EType
    {
        eConnectAttempt = 1,
        eAcceptAttempt = 2,
    };

    enum EDirection
    {
        eOutbound = 1,
        eInbound = 2,
    };

    quint64 Sequence = 0;
    quint64 Timestamp = 0;
    quint64 ProcessCreateTime = 0;
    quint32 ProcessId = 0;
    quint32 SessionId = 0;
    quint16 AddressFamily = 0;
    quint8 Protocol = 0;
    quint8 Type = 0;
    quint8 Direction = 0;
    bool Blocked = false;
    bool Loopback = false;
    quint16 LocalPort = 0;
    quint16 RemotePort = 0;
    QByteArray LocalAddress;
    QByteArray RemoteAddress;
};


struct QSBIEAPI_EXPORT SSbieCaptureEvents
{
    SSbieCaptureId Id;
    quint64 NextSequence = 0;
    quint64 OldestSequence = 0;
    quint64 NewestSequence = 0;
    quint64 DroppedCount = 0;
    quint32 RemainingEvents = 0;
    QList<SSbieCaptureEvent> Events;
};


struct QSBIEAPI_EXPORT SSbieCaptureRecord
{
    enum EAddressFamily
    {
        eIPv4 = 2,
        eIPv6 = 23,
    };

    enum ELayer
    {
        eTransport = 1,
        eStream = 2,
        eDatagram = 3,
    };

    quint64 Sequence = 0;
    quint64 Timestamp = 0;
    quint64 ProcessCreateTime = 0;
    quint32 ProcessId = 0;
    quint32 SessionId = 0;
    quint16 AddressFamily = 0;
    quint8 Protocol = 0;
    quint8 Direction = 0;
    quint8 Layer = 0;
    bool Loopback = false;
    quint16 LocalPort = 0;
    quint16 RemotePort = 0;
    quint32 OriginalLength = 0;
    quint32 CapturedLength = 0;
    QByteArray LocalAddress;
    QByteArray RemoteAddress;
    QByteArray Data;
};


struct QSBIEAPI_EXPORT SSbieCaptureRecords
{
    SSbieCaptureId Id;
    quint64 NextSequence = 0;
    quint64 OldestSequence = 0;
    quint64 NewestSequence = 0;
    quint64 DroppedCount = 0;
    quint32 RemainingRecords = 0;
    QList<SSbieCaptureRecord> Records;
};

using SSbieCapturePackets = SSbieCaptureRecords;
using SSbieCaptureStreams = SSbieCaptureRecords;
