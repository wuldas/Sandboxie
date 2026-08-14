#include "stdafx.h"
#include <windows.h>
#include "PacketCaptureView.h"
#include "..\\SandMan.h"
#include "SbieView.h"
#include "../QSbieAPI/SbieAPI.h"

#include <QComboBox>
#include <QFileDialog>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QTableWidget>
#include <QHeaderView>


static const int PACKET_CAPTURE_MAX_ROWS = 2000;


CPacketCaptureView::CPacketCaptureView(bool bStandAlone, QWidget* parent)
    : QWidget(parent),
      m_uTimerID(0),
      m_CapabilityFlags(0),
      m_OutputHandle(0),
      m_PacketCount(0),
      m_ByteCount(0),
      m_DroppedCount(0)
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
    pOptions->setColumnStretch(6, 1);
    pMainLayout->addLayout(pOptions);

    QHBoxLayout* pOutputLayout = new QHBoxLayout();
    pOutputLayout->setContentsMargins(4, 0, 4, 0);
    pOutputLayout->addWidget(new QLabel(tr("Output")));
    m_pOutputPath = new QLineEdit();
    m_pOutputPath->setReadOnly(true);
    m_pOutputPath->setPlaceholderText(tr("Choose the PCAPNG output before starting"));
    pOutputLayout->addWidget(m_pOutputPath, 1);
    m_pBrowse = new QPushButton(tr("Browse..."));
    pOutputLayout->addWidget(m_pBrowse);
    pMainLayout->addLayout(pOutputLayout);

    QHBoxLayout* pButtons = new QHBoxLayout();
    pButtons->setContentsMargins(4, 0, 4, 0);
    m_pStart = new QPushButton(tr("Start"));
    m_pStop = new QPushButton(tr("Stop"));
    m_pClear = new QPushButton(tr("Clear"));
    pButtons->addWidget(m_pStart);
    pButtons->addWidget(m_pStop);
    pButtons->addWidget(m_pClear);
    pButtons->addStretch(1);
    pMainLayout->addLayout(pButtons);

    m_pStatus = new QLabel();
    m_pStatus->setWordWrap(true);
    m_pStatus->setContentsMargins(4, 0, 4, 0);
    pMainLayout->addWidget(m_pStatus);

    m_pPackets = new QTableWidget(0, 8);
    m_pPackets->setHorizontalHeaderLabels(
        tr("Time|PID|Process|Proto|Source|Destination|Original|Captured").split("|"));
    m_pPackets->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_pPackets->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_pPackets->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_pPackets->setAlternatingRowColors(true);
    m_pPackets->setSortingEnabled(false);
    m_pPackets->horizontalHeader()->setStretchLastSection(true);
    m_pPackets->verticalHeader()->setVisible(false);
    pMainLayout->addWidget(m_pPackets, 1);

    connect(m_pBrowse, &QPushButton::clicked, this, &CPacketCaptureView::OnBrowse);
    connect(m_pStart, &QPushButton::clicked, this, &CPacketCaptureView::OnStart);
    connect(m_pStop, &QPushButton::clicked, this, &CPacketCaptureView::OnStop);
    connect(m_pClear, &QPushButton::clicked, this, &CPacketCaptureView::OnClear);

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
    if (BoxName.isEmpty())
        return;
    int index = m_pBoxCombo->findText(BoxName, Qt::MatchFixedString);
    if (index >= 0)
        m_pBoxCombo->setCurrentIndex(index);
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
    m_pStart->setEnabled(ready && !capturing && !m_pOutputPath->text().isEmpty());
    m_pStop->setEnabled(capturing);
    m_pBrowse->setEnabled(!capturing);
    m_pBoxCombo->setEnabled(!capturing);
    m_pSnapLength->setEnabled(!capturing);
    m_pMaxFileBytes->setEnabled(!capturing);
    m_pMaxSeconds->setEnabled(!capturing);
    m_pRotateCount->setEnabled(!capturing);
    m_pLoopback->setEnabled(!capturing);

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


void CPacketCaptureView::OnBrowse()
{
    QString defaultName = m_OutputPath;
    if (defaultName.isEmpty())
        defaultName = QStringLiteral("packet-capture.pcapng");

    QString path = QFileDialog::getSaveFileName(
        this,
        tr("Choose PCAPNG output"),
        defaultName,
        tr("PCAPNG files (*.pcapng);;All files (*.*)"));
    if (path.isEmpty())
        return;

    m_OutputPath = path.replace('/', '\\');
    m_pOutputPath->setText(m_OutputPath);
    UpdateControls();
}


void CPacketCaptureView::CloseOutputFile()
{
    if (m_OutputHandle) {
        CloseHandle((HANDLE)m_OutputHandle);
        m_OutputHandle = 0;
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
    if (m_pBoxCombo->currentText().isEmpty() || m_OutputPath.isEmpty()) {
        UpdateStatus(tr("Choose a sandbox and PCAPNG output file first."));
        return;
    }

    std::wstring path = m_OutputPath.toStdWString();
    HANDLE file = CreateFileW(
        path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (file == INVALID_HANDLE_VALUE) {
        UpdateStatus(tr("Failed to open the PCAPNG output file."));
        return;
    }
    m_OutputHandle = (quintptr)file;

    SSbieCaptureStart options;
    options.BoxName = m_pBoxCombo->currentText();
    options.Scope = SSbieCaptureStart::eBox;
    options.Mode = SSbieCaptureStart::ePackets;
    options.Flags = SSbieCaptureStart::eIncludeFutureProcesses;
    if (m_pLoopback->isChecked())
        options.Flags |= SSbieCaptureStart::eIncludeLoopback;
    options.SnapLength = m_pSnapLength->value();
    options.MaxFileBytes = m_pMaxFileBytes->value();
    options.MaxSeconds = m_pMaxSeconds->value();
    options.RotateCount = m_pRotateCount->value();

    auto start = theAPI->StartCapture(options);
    if (start.IsError()) {
        CloseOutputFile();
        UpdateStatus(tr("Failed to start packet capture: 0x%1")
            .arg((quint32)start.GetStatus(), 8, 16, QChar('0')));
        return;
    }

    SSbieCaptureSession session = start.GetValue();
    auto exportResult = theAPI->SetCaptureExport(
        session.Id, (quint64)(ULONG_PTR)file);
    CloseOutputFile();
    if (exportResult.IsError()) {
        if (!session.Id.IsNull())
            theAPI->StopCapture(session.Id);
        UpdateStatus(tr("Failed to attach the PCAPNG output: 0x%1")
            .arg((quint32)exportResult.GetStatus(), 8, 16, QChar('0')));
        return;
    }

    session = exportResult.GetValue();
    if (session.State != SSbieCaptureSession::eRunning) {
        if (!session.Id.IsNull())
            theAPI->StopCapture(session.Id);
        UpdateStatus(tr("Packet backend did not reach RUNNING (state=%1, status=0x%2).")
            .arg(session.State)
            .arg(session.BackendStatus, 8, 16, QChar('0')));
        return;
    }

    m_CaptureId = session.Id;
    m_PacketCount = session.PacketCount;
    m_ByteCount = session.ByteCount;
    m_DroppedCount = session.DroppedCount;
    UpdateControls();
    UpdateStatus();
}


void CPacketCaptureView::OnStop()
{
    if (!m_CaptureId.IsNull() && theAPI && theAPI->IsConnected())
        theAPI->StopCapture(m_CaptureId);
    m_CaptureId = SSbieCaptureId();
    CloseOutputFile();
    UpdateControls();
}


void CPacketCaptureView::OnClear()
{
    m_pPackets->setRowCount(0);
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
        UpdateStatus(tr("Packet capture status failed: 0x%1")
            .arg((quint32)result.GetStatus(), 8, 16, QChar('0')));
        return;
    }

    const SSbieCaptureSession session = result.GetValue();
    m_PacketCount = session.PacketCount;
    m_ByteCount = session.ByteCount;
    m_DroppedCount = session.DroppedCount;
    if (session.State == SSbieCaptureSession::eFailed ||
            session.State == SSbieCaptureSession::eStopped) {
        m_CaptureId = SSbieCaptureId();
        CloseOutputFile();
        UpdateStatus(tr("Packet capture ended (state=%1, status=0x%2).")
            .arg(session.State)
            .arg(session.BackendStatus, 8, 16, QChar('0')));
        UpdateControls();
        return;
    }
    UpdateStatus();
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
