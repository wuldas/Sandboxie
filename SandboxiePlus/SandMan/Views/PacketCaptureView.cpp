#include "stdafx.h"
#include <windows.h>
#include "PacketCaptureView.h"
#include "..\\SandMan.h"
#include "SbieView.h"
#include "../QSbieAPI/SbieAPI.h"

#include <QComboBox>
#include <QDateTime>
#include <QDesktopServices>
#include <QDialog>
#include <QDir>
#include <QFileInfo>
#include <QFontDatabase>
#include <QGridLayout>
#include <QHostAddress>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QPlainTextEdit>
#include <QSpinBox>
#include <QTableWidget>
#include <QHeaderView>
#include <QVBoxLayout>


static const int PACKET_CAPTURE_MAX_ROWS = 2000;


static int PacketCapture_FindHarEntry(
    const QByteArray& Text, int From, int* End)
{
    int start = Text.indexOf("\"startedDateTime\"", From);
    if (start < 0)
        return -1;
    int open = Text.lastIndexOf('{', start);
    if (open < 0)
        return -1;
    int depth = 0;
    for (int index = open; index < Text.size(); ++index) {
        char value = Text.at(index);
        if (value == '{')
            ++depth;
        else if (value == '}') {
            --depth;
            if (depth == 0) {
                if (End)
                    *End = index + 1;
                return open;
            }
        }
    }
    return -1;
}


static QString PacketCapture_FormatAddress(
    quint16 AddressFamily, const QByteArray& Address)
{
    if (AddressFamily == SSbieCaptureRecord::eIPv4 && Address.size() >= 4) {
        const uchar* p = (const uchar*)Address.constData();
        return QStringLiteral("%1.%2.%3.%4")
            .arg((quint8)Address[0])
            .arg((quint8)Address[1])
            .arg((quint8)Address[2])
            .arg((quint8)Address[3]);
    }

    if (AddressFamily == SSbieCaptureRecord::eIPv6 && Address.size() >= 16) {
        Q_IPV6ADDR Value;
        memcpy(Value.c, Address.constData(), sizeof(Value.c));
        return QHostAddress(Value).toString();
    }

    return Address.toHex();
}


static QString PacketCapture_FormatEndpoint(
    quint16 AddressFamily,
    const QByteArray& Address,
    quint16 Port)
{
    const QString Host = PacketCapture_FormatAddress(AddressFamily, Address);
    if (AddressFamily == SSbieCaptureRecord::eIPv6)
        return QStringLiteral("[%1]:%2").arg(Host).arg(Port);
    return QStringLiteral("%1:%2").arg(Host).arg(Port);
}


static QString PacketCapture_FormatTime(quint64 Timestamp)
{
    static const quint64 UnixEpochFileTime = 116444736000000000ULL;
    if (Timestamp < UnixEpochFileTime)
        return QString::number(Timestamp);
    return QDateTime::fromMSecsSinceEpoch(
        (Timestamp - UnixEpochFileTime) / 10000ULL).toString(
            Qt::ISODateWithMs);
}


static QString PacketCapture_HexDump(const QByteArray& Data)
{
    QString Out;
    const int Count = Data.size();
    for (int Offset = 0; Offset < Count; Offset += 16) {
        QString Line = QStringLiteral("%1  ").arg(Offset, 8, 16, QLatin1Char('0'));
        QString Ascii;
        for (int i = 0; i < 16; ++i) {
            if (Offset + i < Count) {
                const uchar Byte = (uchar)Data.at(Offset + i);
                Line += QStringLiteral("%1 ").arg(Byte, 2, 16, QLatin1Char('0'));
                Ascii += QChar((Byte >= 0x20 && Byte < 0x7F) ? Byte : '.');
            } else {
                Line += QStringLiteral("   ");
            }
            if (i == 7)
                Line += QLatin1Char(' ');
        }
        Out += Line + QLatin1String("  ") + Ascii + QLatin1Char('\n');
    }
    if (Out.isEmpty())
        Out = QObject::tr("(no payload captured)");
    return Out;
}


CPacketCaptureView::CPacketCaptureView(bool bStandAlone, QWidget* parent)
    : QWidget(parent),
      m_uTimerID(0),
      m_CapabilityFlags(0),
      m_PcapHandle(0),
      m_HarHandle(0),
      m_PacketCount(0),
      m_ByteCount(0),
      m_DroppedCount(0),
      m_HarOffset(0),
      m_TargetScope(SSbieCaptureStart::eBox),
      m_TargetProcessId(0)
{
    Q_UNUSED(bStandAlone);

    m_uTimerID = startTimer(500);

    QVBoxLayout* pMainLayout = new QVBoxLayout(this);
    pMainLayout->setContentsMargins(0, 0, 0, 0);
    pMainLayout->setSpacing(2);

    QGridLayout* pOptions = new QGridLayout();
    pOptions->setContentsMargins(4, 4, 4, 0);
    pOptions->setHorizontalSpacing(6);
    pOptions->setVerticalSpacing(4);

    pOptions->addWidget(new QLabel(tr("Box")), 0, 0);
    m_pBoxCombo = new QComboBox();
    m_pBoxCombo->setMinimumWidth(150);
    pOptions->addWidget(m_pBoxCombo, 0, 1);

    pOptions->addWidget(new QLabel(tr("Snaplen")), 0, 2);
    m_pSnapLength = new QSpinBox();
    m_pSnapLength->setRange(64, 1514);
    m_pSnapLength->setValue(256);
    m_pSnapLength->setSuffix(tr(" bytes"));
    pOptions->addWidget(m_pSnapLength, 0, 3);

    pOptions->addWidget(new QLabel(tr("Max time")), 0, 4);
    m_pMaxSeconds = new QSpinBox();
    m_pMaxSeconds->setRange(0, 86400);
    m_pMaxSeconds->setValue(300);
    m_pMaxSeconds->setSuffix(tr(" s"));
    pOptions->addWidget(m_pMaxSeconds, 0, 5);

    pOptions->addWidget(new QLabel(tr("Max file")), 1, 0);
    m_pMaxFileBytes = new QSpinBox();
    m_pMaxFileBytes->setRange(1, 0x7fffffff);
    m_pMaxFileBytes->setValue(64 * 1024 * 1024);
    m_pMaxFileBytes->setSuffix(tr(" bytes"));
    pOptions->addWidget(m_pMaxFileBytes, 1, 1, 1, 2);

    pOptions->addWidget(new QLabel(tr("Rotate")), 1, 3);
    m_pRotateCount = new QSpinBox();
    m_pRotateCount->setRange(0, 64);
    m_pRotateCount->setValue(0);
    pOptions->addWidget(m_pRotateCount, 1, 4);

    m_pLoopback = new QCheckBox(tr("Include loopback"));
    pOptions->addWidget(m_pLoopback, 1, 5);
    m_pIncludeBodies = new QCheckBox(tr("Include bodies"));
    m_pIncludeBodies->setChecked(false);
    pOptions->addWidget(m_pIncludeBodies, 2, 1);
    m_pDisableRedaction = new QCheckBox(tr("Disable redaction"));
    m_pDisableRedaction->setChecked(false);
    m_pDisableRedaction->setToolTip(tr(
        "Leaves Authorization, Cookie, Set-Cookie and X-Api-Key in the HAR. Off by default."));
    pOptions->addWidget(m_pDisableRedaction, 2, 2, 1, 2);
    pOptions->setColumnStretch(6, 1);
    pMainLayout->addLayout(pOptions);

    QHBoxLayout* pButtons = new QHBoxLayout();
    pButtons->setContentsMargins(4, 0, 4, 0);
    m_pStart = new QPushButton(tr("Start"));
    m_pStop = new QPushButton(tr("Stop"));
    m_pClear = new QPushButton(tr("Clear"));
    m_pOpenFolder = new QPushButton(tr("Open Folder"));
    pButtons->addWidget(m_pStart);
    pButtons->addWidget(m_pStop);
    pButtons->addWidget(m_pClear);
    pButtons->addWidget(m_pOpenFolder);
    pButtons->addStretch(1);
    pMainLayout->addLayout(pButtons);

    m_pStatus = new QLabel();
    m_pStatus->setWordWrap(true);
    m_pStatus->setContentsMargins(4, 0, 4, 0);
    pMainLayout->addWidget(m_pStatus);

    m_pPackets = new QTableWidget(0, 7);
    m_pPackets->setHorizontalHeaderLabels(
        tr("Time|PID|Process|Info|Source|Destination|Length").split("|"));
    m_pPackets->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_pPackets->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_pPackets->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_pPackets->setAlternatingRowColors(true);
    m_pPackets->setSortingEnabled(false);
    m_pPackets->horizontalHeader()->setStretchLastSection(true);
    m_pPackets->verticalHeader()->setVisible(false);
    pMainLayout->addWidget(m_pPackets, 1);

    connect(m_pOpenFolder, &QPushButton::clicked, this, &CPacketCaptureView::OnOpenFolder);
    connect(m_pStart, &QPushButton::clicked, this, &CPacketCaptureView::OnStart);
    connect(m_pStop, &QPushButton::clicked, this, &CPacketCaptureView::OnStop);
    connect(m_pClear, &QPushButton::clicked, this, &CPacketCaptureView::OnClear);
    connect(m_pPackets, &QTableWidget::cellDoubleClicked,
        this, &CPacketCaptureView::OnRowDoubleClicked);

    if (theAPI)
        connect(theAPI, SIGNAL(StatusChanged()), this, SLOT(RefreshCapabilities()));
    RefreshBoxes();
    RefreshCapabilities();
}


CPacketCaptureView::~CPacketCaptureView()
{
    killTimer(m_uTimerID);
    OnStop();
}


void CPacketCaptureView::SetPreferredBox(const QString& BoxName)
{
    m_TargetScope = SSbieCaptureStart::eBox;
    m_TargetProcessId = 0;
    if (BoxName.isEmpty())
        return;
    int index = m_pBoxCombo->findText(BoxName, Qt::MatchFixedString);
    if (index >= 0)
        m_pBoxCombo->setCurrentIndex(index);
}


void CPacketCaptureView::SetPreferredProcess(
    const QString& BoxName, quint32 ProcessId)
{
    m_TargetScope = SSbieCaptureStart::eProcess;
    m_TargetProcessId = ProcessId;
    if (!BoxName.isEmpty()) {
        int index = m_pBoxCombo->findText(BoxName, Qt::MatchFixedString);
        if (index >= 0)
            m_pBoxCombo->setCurrentIndex(index);
    }
}


void CPacketCaptureView::RefreshBoxes()
{
    if (!theAPI || !theAPI->IsConnected())
        return;

    QString current = m_pBoxCombo->currentText();
    if (current.isEmpty())
        current = PreferredBoxName();

    m_pBoxCombo->blockSignals(true);
    m_pBoxCombo->clear();
    QMap<QString, CSandBoxPtr> boxes = theAPI->GetAllBoxes();
    for (auto I = boxes.begin(); I != boxes.end(); ++I) {
        if (I.value() && I.value()->IsEnabled())
            m_pBoxCombo->addItem(I.value()->GetName());
    }

    int index = m_pBoxCombo->findText(current, Qt::MatchFixedString);
    if (index < 0)
        index = m_pBoxCombo->findText(QStringLiteral("DefaultBox"), Qt::MatchFixedString);
    if (index < 0 && m_pBoxCombo->count() > 0)
        index = 0;
    if (index >= 0)
        m_pBoxCombo->setCurrentIndex(index);
    m_pBoxCombo->blockSignals(false);
}


void CPacketCaptureView::RefreshCapabilities()
{
    m_CapabilityFlags = 0;
    if (theAPI && theAPI->IsConnected()) {
        auto result = theAPI->QueryCaptureCapabilities();
        if (!result.IsError())
            m_CapabilityFlags = result.GetValue().Flags;
    }
    UpdateControls();
}


bool CPacketCaptureView::PacketBackendReady() const
{
    const quint32 required =
        SSbieCaptureCapabilities::ePacketCapture |
        SSbieCaptureCapabilities::ePcapngExport;
    return (m_CapabilityFlags & required) == required;
}


bool CPacketCaptureView::HttpsBackendReady() const
{
    const quint32 required =
        SSbieCaptureCapabilities::eHttpsInspection |
        SSbieCaptureCapabilities::eHarExport;
    return (m_CapabilityFlags & required) == required;
}


QString CPacketCaptureView::PreferredBoxName() const
{
    if (theGUI && theGUI->GetBoxView()) {
        QList<CSandBoxPtr> selected = theGUI->GetBoxView()->GetSelectedBoxes();
        if (selected.count() == 1 && !selected.first().isNull())
            return selected.first()->GetName();
    }
    return QStringLiteral("DefaultBox");
}


void CPacketCaptureView::UpdateControls()
{
    const bool capturing = IsCapturing();
    const bool ready = PacketBackendReady();
    m_pStart->setEnabled(ready && !capturing);
    m_pStop->setEnabled(capturing);
    m_pOpenFolder->setEnabled(true);
    m_pBoxCombo->setEnabled(!capturing);
    m_pSnapLength->setEnabled(!capturing);
    m_pMaxFileBytes->setEnabled(!capturing);
    m_pMaxSeconds->setEnabled(!capturing);
    m_pRotateCount->setEnabled(!capturing);
    m_pLoopback->setEnabled(!capturing);
    m_pIncludeBodies->setEnabled(!capturing);
    m_pDisableRedaction->setEnabled(!capturing);

    if (!capturing && !ready)
        m_pStatus->setText(tr("Packet capture is disabled until live isolation and churn verification pass. The Start action remains unavailable."));
}


void CPacketCaptureView::UpdateStatus(const QString& Message)
{
    if (!Message.isEmpty()) {
        m_pStatus->setText(Message);
        return;
    }

    if (!IsCapturing()) {
        UpdateControls();
        return;
    }

    m_pStatus->setText(tr("Packets: %1 | Bytes: %2 | Dropped: %3 | File: %4")
        .arg(m_PacketCount)
        .arg(m_ByteCount)
        .arg(m_DroppedCount)
        .arg(m_OutputPath));
}


QString CPacketCaptureView::CaptureOutputDir()
{
    QString Dir = theConf->GetString("Options/CaptureOutputDir");
    if (Dir.isEmpty())
        Dir = QStandardPaths::writableLocation(
            QStandardPaths::DocumentsLocation) + "/Sandboxie-Plus/Captures";
    QDir().mkpath(Dir);
    return Dir;
}


void CPacketCaptureView::OnOpenFolder()
{
    const QString Dir = m_OutputPath.isEmpty() ? CaptureOutputDir() :
        QFileInfo(m_OutputPath).absolutePath();
    QDesktopServices::openUrl(QUrl::fromLocalFile(Dir));
}


void CPacketCaptureView::CloseOutputFiles()
{
    if (m_PcapHandle) {
        CloseHandle((HANDLE)m_PcapHandle);
        m_PcapHandle = 0;
    }
    if (m_HarHandle) {
        CloseHandle((HANDLE)m_HarHandle);
        m_HarHandle = 0;
    }
}


void CPacketCaptureView::OnStart()
{
    if (!PacketBackendReady()) {
        UpdateControls();
        return;
    }
    if (!theAPI || !theAPI->IsConnected()) {
        UpdateStatus(tr("Not connected to Sandboxie."));
        return;
    }
    if (m_pBoxCombo->currentText().isEmpty()) {
        UpdateStatus(tr("Choose a sandbox first."));
        return;
    }

    const bool httpsReady = HttpsBackendReady();

    QString BoxName = m_pBoxCombo->currentText();
    for (QChar c : QStringLiteral("<>:\"/\\|?*"))
        BoxName.replace(c, QLatin1Char('_'));
    const QString BaseName = QStringLiteral("capture_%1_%2")
        .arg(BoxName)
        .arg(QDateTime::currentDateTime().toString("yyyyMMdd-hhmmss"));
    m_OutputPath = CaptureOutputDir() + "/" + BaseName + ".pcapng";
    m_HarPath = httpsReady ?
        CaptureOutputDir() + "/" + BaseName + ".har" : QString();

    std::wstring pcapPath = m_OutputPath.toStdWString();
    HANDLE pcapFile = CreateFileW(
        pcapPath.c_str(), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (pcapFile == INVALID_HANDLE_VALUE) {
        UpdateStatus(tr("Failed to open the PCAPNG output file."));
        return;
    }
    m_PcapHandle = (quintptr)pcapFile;

    HANDLE harFile = INVALID_HANDLE_VALUE;
    if (httpsReady) {
        std::wstring harPath = m_HarPath.toStdWString();
        harFile = CreateFileW(
            harPath.c_str(), GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL, NULL);
        if (harFile == INVALID_HANDLE_VALUE) {
            CloseOutputFiles();
            UpdateStatus(tr("Failed to open the HAR output file."));
            return;
        }
        m_HarHandle = (quintptr)harFile;
    }

    SSbieCaptureStart options;
    options.BoxName = m_pBoxCombo->currentText();
    options.Scope = m_TargetScope;
    options.ProcessId = m_TargetProcessId;
    options.Mode = httpsReady ?
        SSbieCaptureStart::eHttps : SSbieCaptureStart::ePackets;
    options.Flags = m_TargetScope == SSbieCaptureStart::eBox ?
        SSbieCaptureStart::eIncludeFutureProcesses : 0;
    if (m_pLoopback->isChecked())
        options.Flags |= SSbieCaptureStart::eIncludeLoopback;
    if (httpsReady) {
        if (m_pIncludeBodies->isChecked())
            options.Flags |= SSbieCaptureStart::eIncludeBodies;
        if (m_pDisableRedaction->isChecked())
            options.Flags |= SSbieCaptureStart::eDisableRedaction;
    }
    options.SnapLength = m_pSnapLength->value();
    options.MaxFileBytes = m_pMaxFileBytes->value();
    options.MaxSeconds = m_pMaxSeconds->value();
    options.RotateCount = m_pRotateCount->value();

    auto start = theAPI->StartCapture(options);
    if (start.IsError()) {
        CloseOutputFiles();
        UpdateStatus(tr("Failed to start capture: 0x%1")
            .arg((quint32)start.GetStatus(), 8, 16, QChar('0')));
        return;
    }

    SSbieCaptureSession session = start.GetValue();
    auto exportResult = theAPI->SetCaptureExport(
        session.Id, (quint64)(ULONG_PTR)pcapFile);
    if (exportResult.IsError()) {
        if (!session.Id.IsNull())
            theAPI->StopCapture(session.Id);
        CloseOutputFiles();
        UpdateStatus(tr("Failed to attach the PCAPNG output: 0x%1")
            .arg((quint32)exportResult.GetStatus(), 8, 16, QChar('0')));
        return;
    }

    if (httpsReady) {
        auto harResult = theAPI->SetCaptureHarExport(
            session.Id, (quint64)(ULONG_PTR)harFile);
        if (harResult.IsError()) {
            if (!session.Id.IsNull())
                theAPI->StopCapture(session.Id);
            CloseOutputFiles();
            UpdateStatus(tr("Failed to attach the HAR output: 0x%1")
                .arg((quint32)harResult.GetStatus(), 8, 16, QChar('0')));
            return;
        }
        session = harResult.GetValue();
    }
    CloseOutputFiles();

    if (session.State != SSbieCaptureSession::eRunning) {
        if (!session.Id.IsNull())
            theAPI->StopCapture(session.Id);
        UpdateStatus(tr("Backend did not reach RUNNING (state=%1, status=0x%2).")
            .arg(session.State)
            .arg(session.BackendStatus, 8, 16, QChar('0')));
        return;
    }

    m_CaptureId = session.Id;
    m_PacketCount = session.PacketCount;
    m_ByteCount = session.ByteCount;
    m_DroppedCount = session.DroppedCount;
    m_HarOffset = 0;
    UpdateControls();
    UpdateStatus();
}


void CPacketCaptureView::OnStop()
{
    if (!m_CaptureId.IsNull() && theAPI && theAPI->IsConnected())
        theAPI->StopCapture(m_CaptureId);
    m_CaptureId = SSbieCaptureId();
    CloseOutputFiles();
    UpdateControls();
}


void CPacketCaptureView::OnClear()
{
    m_pPackets->setRowCount(0);
    m_RowData.clear();
}


QString CPacketCaptureView::PacketCapture_InfoText(
    const SSbieCaptureRecord& Record)
{
    if (Record.Layer == SSbieCaptureRecord::eStream)
        return QStringLiteral("TLS stream");

    const quint16 Port = Record.Direction == SSbieCaptureEvent::eOutbound ?
        Record.RemotePort : Record.LocalPort;

    if (Record.Protocol == 17) { // UDP
        if (Port == 53) return QStringLiteral("DNS");
        if (Port == 443) return QStringLiteral("QUIC");
        return QStringLiteral("UDP");
    }
    if (Record.Protocol == 6) { // TCP
        if (Port == 80) return QStringLiteral("HTTP");
        if (Port == 443) return QStringLiteral("HTTPS");
        if (Port == 22) return QStringLiteral("SSH");
        if (Port == 21) return QStringLiteral("FTP");
        if (Port == 25) return QStringLiteral("SMTP");
        if (Port == 110) return QStringLiteral("POP3");
        if (Port == 143) return QStringLiteral("IMAP");
        if (Port == 8080 || Port == 8443 || Port == 8888)
            return QStringLiteral("HTTP");
        return QStringLiteral("TCP");
    }
    if (Record.Protocol == 1) return QStringLiteral("ICMP");
    return QStringLiteral("IP #%1").arg(Record.Protocol);
}


void CPacketCaptureView::AppendRecord(const SSbieCaptureRecord& Record)
{
    const int Row = m_pPackets->rowCount();
    m_pPackets->insertRow(Row);

    QString ProcessName;
    if (theAPI) {
        CBoxedProcessPtr Process = theAPI->GetProcessById(Record.ProcessId);
        if (Process)
            ProcessName = Process->GetProcessName();
    }

    m_pPackets->setItem(Row, 0,
        new QTableWidgetItem(PacketCapture_FormatTime(Record.Timestamp)));
    m_pPackets->setItem(Row, 1,
        new QTableWidgetItem(QString::number(Record.ProcessId)));
    m_pPackets->setItem(Row, 2, new QTableWidgetItem(ProcessName));
    m_pPackets->setItem(Row, 3,
        new QTableWidgetItem(PacketCapture_InfoText(Record)));
    m_pPackets->setItem(Row, 4, new QTableWidgetItem(
        PacketCapture_FormatEndpoint(
            Record.AddressFamily, Record.LocalAddress, Record.LocalPort)));
    m_pPackets->setItem(Row, 5, new QTableWidgetItem(
        PacketCapture_FormatEndpoint(
            Record.AddressFamily, Record.RemoteAddress, Record.RemotePort)));
    m_pPackets->setItem(Row, 6,
        new QTableWidgetItem(QString::number(Record.OriginalLength)));

    SPacketCapture_RowData Data;
    Data.Kind = 0;
    Data.Payload = Record.Data;
    m_RowData.append(Data);

    TrimRows();
}


void CPacketCaptureView::AppendRecords(
    const QList<SSbieCaptureRecord>& Records)
{
    for (const SSbieCaptureRecord& Record : Records)
        AppendRecord(Record);
}


void CPacketCaptureView::AppendHarRow(const HTTPS_CAPTURE_ROW& Row)
{
    if (m_pPackets->rowCount() >= PACKET_CAPTURE_MAX_ROWS) {
        ++m_DroppedCount;
        return;
    }

    QString ProcessName;
    if (theAPI) {
        CBoxedProcessPtr Process = theAPI->GetProcessById(Row.pid);
        if (Process)
            ProcessName = Process->GetProcessName();
    }

    const QString Method = QString::fromUtf8(Row.method);
    const QString Host = QString::fromUtf8(Row.host);
    const QString Path = QString::fromUtf8(Row.path);
    const QString Tls = QString::fromUtf8(Row.tls);
    const QString Info = QStringLiteral("%1 %2 %3")
        .arg(Tls.isEmpty() ? QStringLiteral("HTTP") : QStringLiteral("HTTPS"))
        .arg(Method)
        .arg(Path);

    const int RowIndex = m_pPackets->rowCount();
    m_pPackets->insertRow(RowIndex);
    m_pPackets->setItem(RowIndex, 0,
        new QTableWidgetItem(QString::fromUtf8(Row.time)));
    m_pPackets->setItem(RowIndex, 1,
        new QTableWidgetItem(QString::number(Row.pid)));
    m_pPackets->setItem(RowIndex, 2, new QTableWidgetItem(ProcessName));
    m_pPackets->setItem(RowIndex, 3, new QTableWidgetItem(Info));
    m_pPackets->setItem(RowIndex, 4, new QTableWidgetItem(Host));
    m_pPackets->setItem(RowIndex, 5,
        new QTableWidgetItem(QString::number(Row.status)));
    m_pPackets->setItem(RowIndex, 6, new QTableWidgetItem(QLatin1String("-")));

    SPacketCapture_RowData Data;
    Data.Kind = 1;
    Data.Detail = tr("Method: %1\nStatus: %2\nHost: %3\nPath: %4\nTime: %5\nTLS: %6\nCertificate pinning: %7\n\nHAR file: %8")
        .arg(Method)
        .arg(Row.status)
        .arg(Host)
        .arg(Path)
        .arg(QString::fromUtf8(Row.time))
        .arg(Tls.isEmpty() ? tr("no") : Tls)
        .arg(Row.pinning_failed ? tr("failed") : tr("ok"))
        .arg(m_HarPath);
    m_RowData.append(Data);

    ++m_PacketCount;
    TrimRows();
}


void CPacketCaptureView::TrimRows()
{
    while (m_pPackets->rowCount() > PACKET_CAPTURE_MAX_ROWS) {
        m_pPackets->removeRow(0);
        if (!m_RowData.isEmpty())
            m_RowData.removeFirst();
    }
}


void CPacketCaptureView::ConsumeHarTail()
{
    if (m_HarPath.isEmpty())
        return;

    QFile file(m_HarPath);
    if (!file.open(QIODevice::ReadOnly))
        return;
    if (file.size() < m_HarOffset)
        m_HarOffset = 0;
    if (!file.seek(m_HarOffset)) {
        file.close();
        return;
    }
    const QByteArray chunk = file.readAll();
    file.close();
    if (chunk.isEmpty())
        return;

    int cursor = 0;
    int consumed = 0;
    while (cursor < chunk.size()) {
        int end = 0;
        int start = PacketCapture_FindHarEntry(chunk, cursor, &end);
        if (start < 0)
            break;
        HTTPS_CAPTURE_ROW row;
        QByteArray json = chunk.mid(start, end - start);
        if (HttpsCapture_ParseEntry(json.constData(), &row) == 0)
            AppendHarRow(row);
        cursor = end;
        consumed = end;
    }
    m_HarOffset += consumed;
}


void CPacketCaptureView::RefreshPacketRows()
{
    /* Metadata rows are fetched through SbieSvc LPC; only payload bytes
       stay in the PCAPNG file and are never drained through LPC. */
    if (!theAPI || m_CaptureId.IsNull())
        return;

    auto result = theAPI->ReadCapturePackets(m_CaptureId, 256);
    if (!result.IsError()) {
        const SSbieCaptureRecords Records = result.GetValue();
        if (!Records.Records.isEmpty())
            AppendRecords(Records.Records);
    }

    auto streams = theAPI->ReadCaptureStreams(m_CaptureId, 256);
    if (!streams.IsError()) {
        const SSbieCaptureRecords Records = streams.GetValue();
        if (!Records.Records.isEmpty())
            AppendRecords(Records.Records);
    }
}


void CPacketCaptureView::timerEvent(QTimerEvent* pEvent)
{
    if (pEvent->timerId() != m_uTimerID || m_CaptureId.IsNull())
        return;
    if (!theAPI || !theAPI->IsConnected()) {
        OnStop();
        UpdateStatus(tr("Sandboxie service disconnected."));
        return;
    }

    auto result = theAPI->GetCaptureStatus(m_CaptureId);
    if (result.IsError()) {
        OnStop();
        UpdateStatus(tr("Capture status failed: 0x%1")
            .arg((quint32)result.GetStatus(), 8, 16, QChar('0')));
        return;
    }

    const SSbieCaptureSession session = result.GetValue();
    m_PacketCount = session.PacketCount;
    m_ByteCount = session.ByteCount;
    m_DroppedCount = session.DroppedCount;
    ConsumeHarTail();
    if (session.State == SSbieCaptureSession::eFailed ||
            session.State == SSbieCaptureSession::eStopped) {
        m_CaptureId = SSbieCaptureId();
        CloseOutputFiles();
        UpdateStatus(tr("Capture ended (state=%1, status=0x%2).")
            .arg(session.State)
            .arg(session.BackendStatus, 8, 16, QChar('0')));
        UpdateControls();
        return;
    }
    RefreshPacketRows();
    UpdateStatus();
}


void CPacketCaptureView::OnRowDoubleClicked(int Row, int Column)
{
    Q_UNUSED(Column);
    if (Row < 0 || Row >= m_RowData.count())
        return;

    const SPacketCapture_RowData& Data = m_RowData.at(Row);

    QDialog dlg(this);
    dlg.setWindowTitle(tr("Capture Details"));
    dlg.setWindowFlag(Qt::WindowContextHelpButtonHint, false);
    dlg.resize(720, 480);

    QVBoxLayout* pLayout = new QVBoxLayout(&dlg);
    QPlainTextEdit* pView = new QPlainTextEdit(&dlg);
    pView->setReadOnly(true);
    pView->setLineWrapMode(QPlainTextEdit::NoWrap);
    if (Data.Kind == 1) {
        QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);
        pView->setFont(mono);
        pView->setPlainText(Data.Detail);
    } else {
        QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);
        pView->setFont(mono);
        pView->setPlainText(PacketCapture_HexDump(Data.Payload));
    }
    pLayout->addWidget(pView);
    dlg.exec();
}


void CPacketCaptureView::showEvent(QShowEvent* pEvent)
{
    QWidget::showEvent(pEvent);
    RefreshBoxes();
    RefreshCapabilities();
}


CPacketCaptureWindow::CPacketCaptureWindow(QWidget* parent)
    : QDialog(parent)
{
    Qt::WindowFlags flags = windowFlags();
    flags |= Qt::CustomizeWindowHint;
    flags &= ~Qt::WindowContextHelpButtonHint;
    setWindowFlags(flags);
    setWindowTitle(tr("Sandboxie-Plus - Packet Capture"));
    setWindowFlag(Qt::WindowStaysOnTopHint, theGUI->IsAlwaysOnTop());

    QGridLayout* pLayout = new QGridLayout();
    pLayout->setContentsMargins(3, 3, 3, 3);
    m_pView = new CPacketCaptureView(true, this);
    pLayout->addWidget(m_pView, 0, 0);
    setLayout(pLayout);
    restoreGeometry(theConf->GetBlob("PacketCaptureWindow/Window_Geometry"));
}


CPacketCaptureWindow::~CPacketCaptureWindow()
{
    theConf->SetBlob("PacketCaptureWindow/Window_Geometry", saveGeometry());
}


void CPacketCaptureWindow::closeEvent(QCloseEvent* e)
{
    Q_UNUSED(e);
    emit Closed();
    deleteLater();
}
