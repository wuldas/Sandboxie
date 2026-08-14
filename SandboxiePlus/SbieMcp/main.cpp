/*
 * Copyright 2026 David Xanatos, xanasoft.com
 *
 * Sandboxie-Plus can be used under the restrictions and obligations in
 * SandboxiePlus/SandMan/LICENSE.
 */

//---------------------------------------------------------------------------
// SbieMcp - local stdio Model Context Protocol server
//---------------------------------------------------------------------------

#include <QCoreApplication>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QSet>
#include <QStringList>

#include <cmath>

#include "../QSbieAPI/SbieAPI.h"


#define MCP_PROTOCOL_VERSION "2025-06-18"
#define MCP_MAX_MESSAGE_SIZE  (1024 * 1024)
#define MCP_MAX_TOOL_RESULT_SIZE (256 * 1024)
#define MCP_DEFAULT_LIST_LIMIT 100


struct SMcpResult
{
    bool IsError = false;
    QJsonObject Value;
};


static SMcpResult McpResult(const QJsonObject& Value)
{
    SMcpResult Result;
    Result.Value = Value;
    return Result;
}


static SMcpResult McpError(
    int Code, const QString& Message, const QJsonValue& Data = QJsonValue())
{
    SMcpResult Result;
    Result.IsError = true;
    Result.Value["code"] = Code;
    Result.Value["message"] = Message;
    if (!Data.isUndefined())
        Result.Value["data"] = Data;
    return Result;
}


static QString CaptureIdToString(const SSbieCaptureId& Id)
{
    return QString("%1%2")
        .arg(Id.High, 16, 16, QLatin1Char('0'))
        .arg(Id.Low, 16, 16, QLatin1Char('0'));
}


static bool CaptureIdFromString(const QString& Value, SSbieCaptureId *Id)
{
    if (Value.length() != 32)
        return false;

    for (const QChar Character : Value) {
        const ushort Code = Character.unicode();
        if (!((Code >= '0' && Code <= '9') ||
              (Code >= 'a' && Code <= 'f') ||
              (Code >= 'A' && Code <= 'F'))) {
            return false;
        }
    }

    bool highOk = false;
    bool lowOk = false;
    Id->High = Value.left(16).toULongLong(&highOk, 16);
    Id->Low = Value.mid(16).toULongLong(&lowOk, 16);
    return highOk && lowOk && !Id->IsNull();
}


static QJsonValue JsonUInt32(quint32 Value)
{
    return QJsonValue((double)Value);
}


static QJsonObject StatusError(const SB_STATUS& Status)
{
    QJsonObject Error;
    Error["ntstatus"] = QString("0x%1")
        .arg((quint32)Status.GetStatus(), 8, 16, QLatin1Char('0'));
    Error["message"] = CSbieAPI__FormatNtStatus(Status.GetStatus());
    return Error;
}


static QJsonObject CaptureSessionToJson(const SSbieCaptureSession& Session)
{
    QJsonObject Result;
    Result["captureId"] = CaptureIdToString(Session.Id);
    Result["box"] = Session.BoxName;
    Result["state"] = JsonUInt32(Session.State);
    Result["scope"] = JsonUInt32(Session.Scope);
    Result["mode"] = JsonUInt32(Session.Mode);
    Result["flags"] = JsonUInt32(Session.Flags);
    Result["targetProcessId"] = JsonUInt32(Session.TargetProcessId);
    Result["targetSessionId"] = JsonUInt32(Session.TargetSessionId);
    Result["targetProcessCreateTime"] =
        QString::number(Session.TargetProcessCreateTime);
    Result["startedTime"] = QString::number(Session.StartedTime);
    Result["stoppedTime"] = QString::number(Session.StoppedTime);
    Result["eventCount"] = QString::number(Session.EventCount);
    Result["packetCount"] = QString::number(Session.PacketCount);
    Result["byteCount"] = QString::number(Session.ByteCount);
    Result["droppedCount"] = QString::number(Session.DroppedCount);
    Result["backendStatus"] = QString("0x%1")
        .arg(Session.BackendStatus, 8, 16, QLatin1Char('0'));
    return Result;
}


static QString CaptureAddressToString(
    const QByteArray& Address, quint16 AddressFamily)
{
    if (AddressFamily == 2 && Address.size() == 4) {
        return QString("%1.%2.%3.%4")
            .arg((unsigned int)(quint8)Address[0])
            .arg((unsigned int)(quint8)Address[1])
            .arg((unsigned int)(quint8)Address[2])
            .arg((unsigned int)(quint8)Address[3]);
    }

    if (AddressFamily == 23 && Address.size() == 16) {
        QStringList Groups;
        for (int Index = 0; Index < 16; Index += 2) {
            quint16 Group = ((quint8)Address[Index] << 8) |
                            (quint8)Address[Index + 1];
            Groups.append(QString::number(Group, 16));
        }
        return Groups.join(':');
    }

    return QString::fromLatin1(Address.toHex());
}


static QJsonObject CaptureEventToJson(const SSbieCaptureEvent& Event)
{
    QJsonObject Result;
    Result["sequence"] = QString::number(Event.Sequence);
    Result["timestamp"] = QString::number(Event.Timestamp);
    Result["processId"] = JsonUInt32(Event.ProcessId);
    Result["processCreateTime"] = QString::number(Event.ProcessCreateTime);
    Result["sessionId"] = JsonUInt32(Event.SessionId);
    Result["addressFamily"] = JsonUInt32(Event.AddressFamily);
    Result["protocol"] = JsonUInt32(Event.Protocol);
    Result["event"] = Event.Type == SSbieCaptureEvent::eConnectAttempt ?
        "connect_attempt" : "accept_attempt";
    Result["direction"] = Event.Direction == SSbieCaptureEvent::eOutbound ?
        "outbound" : "inbound";
    Result["blocked"] = Event.Blocked;
    Result["loopback"] = Event.Loopback;
    Result["localAddress"] = CaptureAddressToString(
        Event.LocalAddress, Event.AddressFamily);
    Result["remoteAddress"] = CaptureAddressToString(
        Event.RemoteAddress, Event.AddressFamily);
    Result["localPort"] = JsonUInt32(Event.LocalPort);
    Result["remotePort"] = JsonUInt32(Event.RemotePort);
    return Result;
}


static QJsonObject TextToolResult(const QJsonValue& Value, bool IsError = false)
{
    QJsonObject Result;
    QJsonObject Content;
    Content["type"] = "text";
    QByteArray Json = QJsonDocument(
        Value.isObject() ? Value.toObject() :
                           QJsonObject{{"value", Value}})
        .toJson(QJsonDocument::Compact);
    if (Json.size() > MCP_MAX_TOOL_RESULT_SIZE) {
        IsError = true;
        Json = QJsonDocument(QJsonObject{
            {"error", QJsonObject{
                {"message", "Tool result exceeds the bounded output limit"},
                {"maxBytes", MCP_MAX_TOOL_RESULT_SIZE}
            }}
        }).toJson(QJsonDocument::Compact);
    }
    Content["text"] = QString::fromUtf8(Json);
    Result["content"] = QJsonArray{Content};
    Result["isError"] = IsError;
    if (!IsError)
        Result["structuredContent"] = Value;
    return Result;
}


static QJsonObject ToolAnnotations(
    bool ReadOnly, bool Destructive, bool Idempotent)
{
    return QJsonObject{
        {"readOnlyHint", ReadOnly},
        {"destructiveHint", Destructive},
        {"idempotentHint", Idempotent},
        {"openWorldHint", false}
    };
}


static QJsonObject ToolDefinition(
    const QString& Name, const QString& Description,
    const QJsonObject& Schema, const QJsonObject& Annotations)
{
    QJsonObject Tool;
    Tool["name"] = Name;
    Tool["description"] = Description;
    Tool["inputSchema"] = Schema;
    Tool["annotations"] = Annotations;
    return Tool;
}


static QJsonObject EmptyObjectSchema()
{
    return QJsonObject{
        {"type", "object"},
        {"properties", QJsonObject()},
        {"additionalProperties", false}
    };
}


static bool HasOnlyProperties(
    const QJsonObject& Object, const QSet<QString>& Allowed)
{
    for (auto It = Object.constBegin(); It != Object.constEnd(); ++It) {
        if (!Allowed.contains(It.key()))
            return false;
    }
    return true;
}


static bool ReadOptionalBool(
    const QJsonObject& Object, const QString& Name, bool DefaultValue,
    bool *Value)
{
    if (!Object.contains(Name)) {
        *Value = DefaultValue;
        return true;
    }

    const QJsonValue JsonValue = Object.value(Name);
    if (!JsonValue.isBool())
        return false;
    *Value = JsonValue.toBool();
    return true;
}


static bool ReadOptionalUInt32(
    const QJsonObject& Object, const QString& Name, quint32 *Value,
    bool *Present)
{
    *Present = Object.contains(Name);
    if (!*Present) {
        *Value = 0;
        return true;
    }

    const QJsonValue JsonValue = Object.value(Name);
    if (!JsonValue.isDouble())
        return false;

    const double Number = JsonValue.toDouble();
    if (!std::isfinite(Number) || Number < 1 || Number > 4294967295.0 ||
            std::floor(Number) != Number)
        return false;

    *Value = (quint32)Number;
    return true;
}


class SbieMcpServer
{
public:
    SbieMcpServer()
    {
        m_Connected = m_Api.Connect(false, false);
        if (m_Connected)
            m_Api.ReloadBoxes();
    }

    ~SbieMcpServer()
    {
        if (m_Connected)
            m_Api.Disconnect();
    }

    SMcpResult Handle(const QJsonObject& Request)
    {
        const QString Method = Request.value("method").toString();
        const QJsonObject Params = Request.value("params").toObject();

        const bool IsNotification = Method.startsWith("notifications/");
        if (IsNotification && Request.contains("id"))
            return McpError(-32600, "Notifications must not contain an id");
        if (!IsNotification && !Request.contains("id"))
            return McpError(-32600, "Requests must contain an id");

        if (Method == "initialize")
            return Initialize(Params);

        if (Method == "notifications/initialized") {
            if (!Params.isEmpty())
                return McpError(-32602,
                                "initialized notification takes no parameters");
            if (m_State != eInitializeReplied)
                return McpError(-32600, "Unexpected initialized notification");
            m_State = eInitialized;
            return McpResult(QJsonObject());
        }

        if (Method == "notifications/cancelled")
            return McpResult(QJsonObject());

        if (Method == "ping") {
            if (!Params.isEmpty())
                return McpError(-32602, "ping takes no parameters");
            return McpResult(QJsonObject());
        }

        if (m_State != eInitialized)
            return McpError(-32002, "Server is not initialized");

        if (Method == "tools/list") {
            if (!Params.isEmpty())
                return McpError(-32602, "tools/list takes no parameters");
            return McpResult(ListTools());
        }
        if (Method == "tools/call")
            return CallTool(Params);
        if (Method == "resources/list") {
            if (!Params.isEmpty())
                return McpError(-32602, "resources/list takes no parameters");
            return McpResult(ListResources());
        }
        if (Method == "resources/read")
            return ReadResource(Params);

        return McpError(-32601, "Method not found");
    }

private:
    enum EState
    {
        eUninitialized,
        eInitializeReplied,
        eInitialized,
    };

    SMcpResult Initialize(const QJsonObject& Params)
    {
        if (m_State != eUninitialized)
            return McpError(-32600, "Server is already initialized");
        if (!HasOnlyProperties(
                Params, QSet<QString>{"protocolVersion", "capabilities",
                                      "clientInfo", "_meta"}) ||
                !Params.value("protocolVersion").isString() ||
                !Params.value("capabilities").isObject() ||
                !Params.value("clientInfo").isObject()) {
            return McpError(-32602, "Invalid initialize parameters");
        }

        const QJsonObject ClientInfo = Params.value("clientInfo").toObject();
        if (!ClientInfo.value("name").isString() ||
                !ClientInfo.value("version").isString()) {
            return McpError(-32602, "Invalid clientInfo");
        }

        m_State = eInitializeReplied;

        QJsonObject Result;
        Result["protocolVersion"] = MCP_PROTOCOL_VERSION;
        Result["capabilities"] = QJsonObject{
            {"tools", QJsonObject()},
            {"resources", QJsonObject()}
        };
        Result["serverInfo"] = QJsonObject{
            {"name", "sandboxie-capture"},
            {"title", "Sandboxie Capture"},
            {"version", "0.1.0"}
        };
        Result["instructions"] =
            "Capture-changing tools are owner-scoped by SbieSvc. Packet and "
            "HTTPS capture are unavailable unless capability flags explicitly "
            "advertise their backends.";
        return McpResult(Result);
    }

    QJsonObject ListTools() const
    {
        QJsonArray Tools;
        Tools.append(ToolDefinition(
            "sandboxie_list_boxes",
            "List sandboxes visible to the current user.",
            EmptyObjectSchema(), ToolAnnotations(true, false, true)));

        Tools.append(ToolDefinition(
            "sandboxie_list_processes",
            "List active processes in one sandbox.",
            QJsonObject{
                {"type", "object"},
                {"properties", QJsonObject{
                    {"box", QJsonObject{{"type", "string"}, {"minLength", 1}}}
                }},
                {"required", QJsonArray{"box"}},
                {"additionalProperties", false}
            }, ToolAnnotations(true, false, true)));

        Tools.append(ToolDefinition(
            "capture_capabilities",
            "Return capture control and backend capabilities.",
            EmptyObjectSchema(), ToolAnnotations(true, false, true)));

        Tools.append(ToolDefinition(
            "capture_start",
            "Create an owner-scoped capture session. The returned state reports whether a backend is available.",
            QJsonObject{
                {"type", "object"},
                {"properties", QJsonObject{
                    {"box", QJsonObject{{"type", "string"}, {"minLength", 1}}},
                    {"processId", QJsonObject{{"type", "integer"}, {"minimum", 1}, {"maximum", 4294967295.0}}},
                    {"mode", QJsonObject{{"type", "string"}, {"enum", QJsonArray{"connections", "packets", "https"}}}},
                    {"includeFutureProcesses", QJsonObject{{"type", "boolean"}}},
                    {"includeLoopback", QJsonObject{{"type", "boolean"}}}
                }},
                {"required", QJsonArray{"box"}},
                {"additionalProperties", false}
            }, ToolAnnotations(false, false, false)));

        Tools.append(ToolDefinition(
            "capture_stop", "Stop an owned capture session.",
            CaptureIdSchema(), ToolAnnotations(false, true, true)));

        Tools.append(ToolDefinition(
            "capture_status", "Get the status of an owned capture session.",
            CaptureIdSchema(), ToolAnnotations(true, false, true)));

        Tools.append(ToolDefinition(
            "capture_read_events",
            "Drain a bounded batch of connection-attempt metadata from an owned capture session. This never returns packet payloads or TLS plaintext.",
            QJsonObject{
                {"type", "object"},
                {"properties", QJsonObject{
                    {"captureId", QJsonObject{
                        {"type", "string"},
                        {"pattern", "^[0-9a-fA-F]{32}$"}
                    }},
                    {"maxEvents", QJsonObject{
                        {"type", "integer"},
                        {"minimum", 1},
                        {"maximum", 32}
                    }}
                }},
                {"required", QJsonArray{"captureId"}},
                {"additionalProperties", false}
            }, ToolAnnotations(false, false, false)));

        return QJsonObject{{"tools", Tools}};
    }

    static QJsonObject CaptureIdSchema()
    {
        return QJsonObject{
            {"type", "object"},
            {"properties", QJsonObject{
                {"captureId", QJsonObject{
                    {"type", "string"},
                    {"pattern", "^[0-9a-fA-F]{32}$"}
                }}
            }},
            {"required", QJsonArray{"captureId"}},
            {"additionalProperties", false}
        };
    }

    SMcpResult CallTool(const QJsonObject& Params)
    {
        if (!HasOnlyProperties(Params, QSet<QString>{"name", "arguments"}) ||
                !Params.value("name").isString() ||
                (Params.contains("arguments") &&
                 !Params.value("arguments").isObject())) {
            return McpError(-32602, "Invalid tools/call parameters");
        }

        const QString Name = Params.value("name").toString();
        const QJsonObject Arguments = Params.value("arguments").toObject();
        if (!m_Connected)
            return McpResult(TextToolResult(StatusError(m_Connected), true));

        if (Name == "sandboxie_list_boxes") {
            if (!Arguments.isEmpty())
                return McpError(-32602, "sandboxie_list_boxes takes no arguments");
            const QJsonObject Value = BoxesJson();
            return McpResult(TextToolResult(Value, Value.contains("error")));
        }

        if (Name == "sandboxie_list_processes") {
            if (!HasOnlyProperties(Arguments, QSet<QString>{"box"}) ||
                    !Arguments.value("box").isString() ||
                    Arguments.value("box").toString().isEmpty()) {
                return McpError(-32602, "box must be a non-empty string");
            }
            const QJsonObject Value =
                ProcessesJson(Arguments.value("box").toString());
            return McpResult(TextToolResult(Value, Value.contains("error")));
        }

        if (Name == "capture_capabilities") {
            if (!Arguments.isEmpty())
                return McpError(-32602, "capture_capabilities takes no arguments");

            auto Result = m_Api.QueryCaptureCapabilities();
            if (Result.IsError())
                return McpResult(TextToolResult(StatusError(Result), true));

            const SSbieCaptureCapabilities Caps = Result.GetValue();
            QJsonObject Value;
            Value["wireVersion"] = JsonUInt32(Caps.WireVersion);
            Value["minWireVersion"] = JsonUInt32(Caps.MinWireVersion);
            Value["maxWireVersion"] = JsonUInt32(Caps.MaxWireVersion);
            Value["flags"] = JsonUInt32(Caps.Flags);
            Value["control"] = (Caps.Flags & 0x00000001) != 0;
            Value["connectionAudit"] = (Caps.Flags & 0x00000002) != 0;
            Value["packetCapture"] = (Caps.Flags & 0x00000004) != 0;
            Value["httpsInspection"] = (Caps.Flags & 0x00000008) != 0;
            Value["maxSessionsPerOwner"] =
                JsonUInt32(Caps.MaxSessionsPerOwner);
            Value["maxListEntries"] = JsonUInt32(Caps.MaxListEntries);
            Value["maxEventEntries"] = JsonUInt32(Caps.MaxEventEntries);
            return McpResult(TextToolResult(Value));
        }

        if (Name == "capture_start")
            return StartCapture(Arguments);

        if (Name == "capture_stop" || Name == "capture_status")
            return CaptureById(Name, Arguments);

        if (Name == "capture_read_events")
            return ReadCaptureEvents(Arguments);

        return McpError(-32602, "Unknown tool: " + Name);
    }

    SMcpResult StartCapture(const QJsonObject& Arguments)
    {
        const QSet<QString> Allowed{
            "box", "processId", "mode", "includeFutureProcesses",
            "includeLoopback"
        };
        if (!HasOnlyProperties(Arguments, Allowed) ||
                !Arguments.value("box").isString() ||
                Arguments.value("box").toString().isEmpty()) {
            return McpError(-32602, "box must be a non-empty string");
        }

        quint32 ProcessId = 0;
        bool HasProcessId = false;
        if (!ReadOptionalUInt32(
                Arguments, "processId", &ProcessId, &HasProcessId)) {
            return McpError(-32602,
                            "processId must be an unsigned 32-bit integer");
        }

        QString Mode = "connections";
        if (Arguments.contains("mode")) {
            if (!Arguments.value("mode").isString())
                return McpError(-32602, "mode must be a string");
            Mode = Arguments.value("mode").toString();
            if (Mode != "connections" && Mode != "packets" && Mode != "https")
                return McpError(-32602, "Unsupported capture mode");
        }

        bool IncludeFutureProcesses = !HasProcessId;
        bool IncludeLoopback = false;
        if (!ReadOptionalBool(Arguments, "includeFutureProcesses",
                              IncludeFutureProcesses,
                              &IncludeFutureProcesses) ||
                !ReadOptionalBool(Arguments, "includeLoopback", false,
                                  &IncludeLoopback)) {
            return McpError(-32602, "Capture flags must be boolean");
        }
        if (HasProcessId && IncludeFutureProcesses)
            return McpError(-32602,
                            "process-scoped capture cannot include future processes");
        if (!HasProcessId && !IncludeFutureProcesses)
            return McpError(-32602,
                            "box capture currently requires includeFutureProcesses");

        SSbieCaptureStart Options;
        Options.BoxName = Arguments.value("box").toString();
        Options.ProcessId = ProcessId;
        Options.Scope = HasProcessId ? SSbieCaptureStart::eProcess :
                                       SSbieCaptureStart::eBox;
        if (Mode == "packets")
            Options.Mode = SSbieCaptureStart::ePackets;
        else if (Mode == "https")
            Options.Mode = SSbieCaptureStart::eHttps;
        else
            Options.Mode = SSbieCaptureStart::eConnections;

        Options.Flags = 0;
        if (IncludeFutureProcesses)
            Options.Flags |= SSbieCaptureStart::eIncludeFutureProcesses;
        if (IncludeLoopback)
            Options.Flags |= SSbieCaptureStart::eIncludeLoopback;

        auto Result = m_Api.StartCapture(Options);
        if (Result.IsError())
            return McpResult(TextToolResult(StatusError(Result), true));
        return McpResult(TextToolResult(
            CaptureSessionToJson(Result.GetValue())));
    }

    SMcpResult CaptureById(
        const QString& Name, const QJsonObject& Arguments)
    {
        if (!HasOnlyProperties(Arguments, QSet<QString>{"captureId"}) ||
                !Arguments.value("captureId").isString()) {
            return McpError(-32602, "captureId must be a string");
        }

        SSbieCaptureId Id;
        if (!CaptureIdFromString(
                Arguments.value("captureId").toString(), &Id)) {
            return McpError(
                -32602,
                "captureId must contain 32 hexadecimal characters");
        }

        auto Result = Name == "capture_stop" ? m_Api.StopCapture(Id) :
                                                m_Api.GetCaptureStatus(Id);
        if (Result.IsError())
            return McpResult(TextToolResult(StatusError(Result), true));
        return McpResult(TextToolResult(
            CaptureSessionToJson(Result.GetValue())));
    }

    SMcpResult ReadCaptureEvents(const QJsonObject& Arguments)
    {
        if (!HasOnlyProperties(
                Arguments, QSet<QString>{"captureId", "maxEvents"}) ||
                !Arguments.value("captureId").isString()) {
            return McpError(-32602, "Invalid capture event arguments");
        }

        SSbieCaptureId Id;
        if (!CaptureIdFromString(
                Arguments.value("captureId").toString(), &Id)) {
            return McpError(
                -32602,
                "captureId must contain 32 hexadecimal characters");
        }

        quint32 MaxEvents = 0;
        bool HasMaxEvents = false;
        if (!ReadOptionalUInt32(
                Arguments, "maxEvents", &MaxEvents, &HasMaxEvents) ||
                (HasMaxEvents && MaxEvents > 32)) {
            return McpError(-32602, "maxEvents must be an integer from 1 to 32");
        }

        auto Result = m_Api.ReadCaptureEvents(Id, MaxEvents);
        if (Result.IsError())
            return McpResult(TextToolResult(StatusError(Result), true));

        const SSbieCaptureEvents Events = Result.GetValue();
        QJsonArray Items;
        for (const SSbieCaptureEvent& Event : Events.Events)
            Items.append(CaptureEventToJson(Event));

        QJsonObject Value;
        Value["captureId"] = CaptureIdToString(Events.Id);
        Value["nextSequence"] = QString::number(Events.NextSequence);
        Value["oldestSequence"] = QString::number(Events.OldestSequence);
        Value["newestSequence"] = QString::number(Events.NewestSequence);
        Value["droppedCount"] = QString::number(Events.DroppedCount);
        Value["remainingEvents"] = JsonUInt32(Events.RemainingEvents);
        Value["events"] = Items;
        return McpResult(TextToolResult(Value));
    }

    QJsonObject ListResources() const
    {
        QJsonArray Resources;
        Resources.append(QJsonObject{
            {"uri", "sandboxie://boxes"},
            {"name", "Sandboxie boxes"},
            {"mimeType", "application/json"}
        });
        Resources.append(QJsonObject{
            {"uri", "capture://sessions"},
            {"name", "Owned capture sessions"},
            {"mimeType", "application/json"}
        });
        return QJsonObject{{"resources", Resources}};
    }

    SMcpResult ReadResource(const QJsonObject& Params)
    {
        if (!HasOnlyProperties(Params, QSet<QString>{"uri"}) ||
                !Params.value("uri").isString()) {
            return McpError(-32602, "uri must be a string");
        }

        const QString Uri = Params.value("uri").toString();
        QJsonValue Value;
        if (!m_Connected)
            Value = StatusError(m_Connected);
        else if (Uri == "sandboxie://boxes")
            Value = BoxesJson();
        else if (Uri == "capture://sessions")
            Value = CaptureSessionsJson();
        else
            return McpError(-32002, "Resource not found",
                            QJsonObject{{"uri", Uri}});

        const QByteArray Json = QJsonDocument(
            Value.isObject() ? Value.toObject() :
                               QJsonObject{{"value", Value}})
            .toJson(QJsonDocument::Compact);
        return McpResult(QJsonObject{{"contents", QJsonArray{
            QJsonObject{
                {"uri", Uri},
                {"mimeType", "application/json"},
                {"text", QString::fromUtf8(Json)}
            }
        }}});
    }

    QJsonObject BoxesJson()
    {
        const SB_STATUS Status = m_Api.ReloadBoxes();
        if (Status.IsError())
            return QJsonObject{{"error", StatusError(Status)}};

        QJsonArray Boxes;
        quint32 TotalCount = 0;
        const auto AllBoxes = m_Api.GetAllBoxes();
        for (const CSandBoxPtr& Box : AllBoxes) {
            if (!Box->IsEnabled())
                continue;
            ++TotalCount;
            if (Boxes.size() >= MCP_DEFAULT_LIST_LIMIT)
                continue;
            QJsonObject Value;
            Value["name"] = Box->GetName();
            Value["enabled"] = true;
            Value["activeProcessCount"] = Box->GetActiveProcessCount();
            Boxes.append(Value);
        }
        return QJsonObject{
            {"totalCount", JsonUInt32(TotalCount)},
            {"returnedCount", JsonUInt32((quint32)Boxes.size())},
            {"truncated", TotalCount > (quint32)Boxes.size()},
            {"boxes", Boxes}
        };
    }

    QJsonObject ProcessesJson(const QString& BoxName)
    {
        SB_STATUS Status = m_Api.ReloadBoxes();
        if (Status.IsError())
            return QJsonObject{{"error", StatusError(Status)}};

        const CSandBoxPtr Box = m_Api.GetBoxByName(BoxName);
        if (!Box || !Box->IsEnabled())
            return QJsonObject{{"error", QJsonObject{
                {"message", "Sandbox is unavailable to the current user"},
                {"box", BoxName}
            }}};

        Status = m_Api.UpdateProcesses(0, false);
        if (Status.IsError())
            return QJsonObject{{"error", StatusError(Status)}};

        QJsonArray Processes;
        quint32 TotalCount = 0;
        const auto AllProcesses = m_Api.GetAllProcesses();
        for (const CBoxedProcessPtr& Process : AllProcesses) {
            if (Process->GetBoxName().compare(
                    BoxName, Qt::CaseInsensitive) != 0 ||
                    Process->IsTerminated())
                continue;

            ++TotalCount;
            if (Processes.size() >= MCP_DEFAULT_LIST_LIMIT)
                continue;

            QJsonObject Value;
            Value["processId"] = JsonUInt32(Process->GetProcessId());
            Value["parentProcessId"] = JsonUInt32(Process->GetParendPID());
            Value["box"] = Process->GetBoxName();
            Value["name"] = Process->GetProcessName();
            Value["path"] = Process->GetFileName();
            Processes.append(Value);
        }
        return QJsonObject{
            {"totalCount", JsonUInt32(TotalCount)},
            {"returnedCount", JsonUInt32((quint32)Processes.size())},
            {"truncated", TotalCount > (quint32)Processes.size()},
            {"processes", Processes}
        };
    }

    QJsonObject CaptureSessionsJson()
    {
        auto Result = m_Api.ListCaptures();
        if (Result.IsError())
            return QJsonObject{{"error", StatusError(Result)}};

        QJsonArray Sessions;
        for (const SSbieCaptureSession& Session : Result.GetValue().Sessions)
            Sessions.append(CaptureSessionToJson(Session));

        return QJsonObject{
            {"totalCount", JsonUInt32(Result.GetValue().TotalCount)},
            {"nextIndex", JsonUInt32(Result.GetValue().NextIndex)},
            {"sessions", Sessions}
        };
    }

private:
    EState m_State = eUninitialized;
    CSbieAPI m_Api;
    SB_STATUS m_Connected;
};


static bool IsValidId(const QJsonValue& Id)
{
    if (Id.isString())
        return true;
    if (!Id.isDouble())
        return false;

    const double Number = Id.toDouble();
    return std::isfinite(Number) && std::floor(Number) == Number &&
           std::fabs(Number) <= 9007199254740991.0;
}


static SMcpResult ValidateEnvelope(const QJsonObject& Request)
{
    if (Request.value("jsonrpc").toString() != "2.0" ||
            !Request.value("method").isString() ||
            Request.value("method").toString().isEmpty() ||
            (Request.contains("params") &&
             !Request.value("params").isObject()) ||
            (Request.contains("id") &&
             !IsValidId(Request.value("id")))) {
        return McpError(-32600, "Invalid Request");
    }

    return McpResult(QJsonObject());
}


static bool WriteMessage(QFile& Output, const QJsonObject& Message)
{
    const QByteArray Data =
        QJsonDocument(Message).toJson(QJsonDocument::Compact) + '\n';
    return Output.write(Data) == Data.size() && Output.flush();
}


static QJsonObject MakeReply(
    const QJsonValue& Id, const SMcpResult& Result)
{
    QJsonObject Reply;
    Reply["jsonrpc"] = "2.0";
    Reply["id"] = Id;
    Reply[Result.IsError ? "error" : "result"] = Result.Value;
    return Reply;
}


int main(int argc, char *argv[])
{
    QCoreApplication Application(argc, argv);
    Q_UNUSED(Application);

    QFile Input;
    QFile Output;
    if (!Input.open(stdin, QIODevice::ReadOnly) ||
            !Output.open(stdout, QIODevice::WriteOnly)) {
        return 1;
    }

    SbieMcpServer Server;
    for (;;) {
        QByteArray Line = Input.readLine(MCP_MAX_MESSAGE_SIZE + 2);
        if (Line.isEmpty()) {
            if (Input.atEnd())
                break;
            return 1;
        }
        if (Line.size() > MCP_MAX_MESSAGE_SIZE ||
                (!Line.endsWith('\n') && !Input.atEnd())) {
            while (!Line.endsWith('\n') && !Input.atEnd())
                Line = Input.readLine(MCP_MAX_MESSAGE_SIZE + 2);
            if (!WriteMessage(Output, MakeReply(
                    QJsonValue::Null,
                    McpError(-32600, "Message exceeds size limit")))) {
                return 1;
            }
            continue;
        }

        Line = Line.trimmed();
        if (Line.isEmpty())
            continue;

        QJsonParseError ParseError;
        const QJsonDocument Document =
            QJsonDocument::fromJson(Line, &ParseError);
        if (ParseError.error != QJsonParseError::NoError) {
            if (!WriteMessage(Output, MakeReply(
                    QJsonValue::Null, McpError(-32700, "Parse error")))) {
                return 1;
            }
            continue;
        }

        if (!Document.isObject()) {
            if (!WriteMessage(Output, MakeReply(
                    QJsonValue::Null, McpError(-32600, "Invalid Request")))) {
                return 1;
            }
            continue;
        }

        const QJsonObject Request = Document.object();
        const bool IsNotification = !Request.contains("id");
        SMcpResult Result = ValidateEnvelope(Request);
        if (!Result.IsError)
            Result = Server.Handle(Request);

        if (IsNotification)
            continue;

        if (!WriteMessage(Output, MakeReply(Request.value("id"), Result)))
            return 1;
    }

    return 0;
}
