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
// Capture Server -- using PipeServer
//---------------------------------------------------------------------------

#ifndef _MY_CAPTURESERVER_H
#define _MY_CAPTURESERVER_H


#include "PipeServer.h"


class CaptureServer
{

public:

    CaptureServer(PipeServer *pipeServer);
    ~CaptureServer();

protected:

    static MSG_HEADER *Handler(void *_this, MSG_HEADER *msg);

    MSG_HEADER *QueryCapsHandler(MSG_HEADER *msg);
    MSG_HEADER *StartHandler(MSG_HEADER *msg);
    MSG_HEADER *StopHandler(MSG_HEADER *msg);
    MSG_HEADER *GetStatusHandler(MSG_HEADER *msg);
    MSG_HEADER *ListHandler(MSG_HEADER *msg);
    MSG_HEADER *ReadEventsHandler(MSG_HEADER *msg);
    MSG_HEADER *SetExportHandler(MSG_HEADER *msg);
    void NotifyHandler(HANDLE idProcess, ULONG64 ownerCreateTime);

    struct _CAPTURE_SESSION_OBJ *FindSession(
        const struct _CAPTURE_SESSION_ID *captureId,
        ULONG ownerPid,
        ULONG64 ownerCreateTime,
        const WCHAR *ownerSid);

    void DeleteSession(struct _CAPTURE_SESSION_OBJ *session);
    ULONG StopBackend(
        struct _CAPTURE_SESSION_OBJ *session, BOOLEAN preserveEvents);
    void TrimStoppedSessions(
        ULONG ownerPid, ULONG64 ownerCreateTime, const WCHAR *ownerSid);

protected:

    HANDLE m_heap;
    CRITICAL_SECTION m_lock;
    LIST m_sessions;
};


#endif /* _MY_CAPTURESERVER_H */
