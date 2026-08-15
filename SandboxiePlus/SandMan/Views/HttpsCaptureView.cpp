#include "stdafx.h"
#include <windows.h>
#include "HttpsCaptureView.h"
#include "..\\SandMan.h"
#include "SbieView.h"
#include "../QSbieAPI/SbieAPI.h"

#include <QCheckBox>
#include <QComboBox>
#include <QFile>
#include <QFileDialog>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QHeaderView>


static QString HttpsCapture_ToNative(const QString& Path)
{
    return QString(Path).replace('/', '\\');
}


static int HttpsCapture_FindEntry(
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


CHttpsCaptureView::CHttpsCaptureView(bool bStandAlone, QWidget* parent)
    : QWidget(parent),
      m_uTimerID(0),
      m_CapabilityFlags(0),
      m_PcapHandle(0),
      m_HarHandle(0),
      m_ExchangeCount(0),
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

    pOptions->addWidget(new QLabel(tr("Max time")), 0, 2);
    m_pMaxSeconds = new QSpinBox();
    m_pMaxSeconds->setRange(0, 86400);
    m_pMaxSeconds->setValue(300);
    m_pMaxSeconds->setSuffix(tr(" s"));
    pOptions->addWidget(m_pMaxSeconds, 0, 3);

    pOptions->addWidget(new QLabel(tr("Max file")), 0, 4);
    m_pMaxFileBytes = new QSpinBox();
    m_pMaxFileBytes->setRange(1, 0x7fffffff);
    m_pMaxFileBytes->setValue(64 * 1024 * 1024);
    m_pMaxFileBytes->setSuffix(tr(" bytes"));
    pOptions->addWidget(m_pMaxFileBytes, 0, 5);

    pOptions->addWidget(new QLabel(tr("Rotate")), 1, 0);
    m_pRotateCount = new QSpinBox();
    m_pRotateCount->setRange(0, 64);
    m_pRotateCount->setValue(0);
    pOptions->addWidget(m_pRotateCount, 1, 1);

    m_pLoopback = new QCheckBox(tr("Include loopback"));
    pOptions->addWidget(m_pLoopback, 1, 2);
    m_pIncludeBodies = new QCheckBox(tr("Include bodies"));
    m_pIncludeBodies->setChecked(false);
    pOptions->addWidget(m_pIncludeBodies, 1, 3);
    m_pDisableRedaction = new QCheckBox(tr("Disable redaction"));
    m_pDisableRedaction->setChecked(false);
    m_pDisableRedaction->setToolTip(tr(
        "Leaves Authorization, Cookie, Set-Cookie and X-Api-Key in the HAR. Off by default."));
    pOptions->addWidget(m_pDisableRedaction, 1, 4, 1, 2);
    pOptions->setColumnStretch(6, 1);
    pMainLayout->addLayout(pOptions);

    QHBoxLayout* pPcapLayout = new QHBoxLayout();
    pPcapLayout->setContentsMargins(4, 0, 4, 0);
    pPcapLayout->addWidget(new QLabel(tr("PCAPNG")));
    m_pPcapPath = new QLineEdit();
    m_pPcapPath->setReadOnly(true);
    m_pPcapPath->setPlaceholderText(tr("Choose the PCAPNG output before starting"));
    pPcapLayout->addWidget(m_pPcapPath, 1);
    m_pBrowsePcap = new QPushButton(tr("Browse..."));
    pPcapLayout->addWidget(m_pBrowsePcap);
    pMainLayout->addLayout(pPcapLayout);

    QHBoxLayout* pHarLayout = new QHBoxLayout();
    pHarLayout->setContentsMargins(4, 0, 4, 0);
    pHarLayout->addWidget(new QLabel(tr("HAR")));
    m_pHarPath = new QLineEdit();
    m_pHarPath->setReadOnly(true);
    m_pHarPath->setPlaceholderText(tr("Choose the HAR output before starting"));
    pHarLayout->addWidget(m_pHarPath, 1);
    m_pBrowseHar = new QPushButton(tr("Browse..."));
    pHarLayout->addWidget(m_pBrowseHar);
    pMainLayout->addLayout(pHarLayout);

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

    m_pEntries = new QTableWidget(0, HTTPS_CAPTURE_COL_COUNT);
    m_pEntries->setHorizontalHeaderLabels(
        tr("Time|PID|Process|Method|Status|Host|Path|TLS|Pinning").split("|"));
    m_pEntries->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_pEntries->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_pEntries->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_pEntries->setAlternatingRowColors(true);
    m_pEntries->setSortingEnabled(false);
    m_pEntries->horizontalHeader()->setStretchLastSection(true);
    m_pEntries->verticalHeader()->setVisible(false);
    pMainLayout->addWidget(m_pEntries, 1);

    connect(m_pBrowsePcap, &QPushButton::clicked, this, &CHttpsCaptureView::OnBrowsePcap);
    connect(m_pBrowseHar, &QPushButton::clicked, this, &CHttpsCaptureView::OnBrowseHar);
    connect(m_pStart, &QPushButton::clicked, this, &CHttpsCaptureView::OnStart);
    connect(m_pStop, &QPushButton::clicked, this, &CHttpsCaptureView::OnStop);
    connect(m_pClear, &QPushButton::clicked, this, &CHttpsCaptureView::OnClear);

    if (theAPI)
        connect(theAPI, SIGNAL(StatusChanged()), this, SLOT(RefreshCapabilities()));
    RefreshBoxes();
    RefreshCapabilities();
}


CHttpsCaptureView::~CHttpsCaptureView()
{
    killTimer(m_uTimerID);
    OnStop();
}


void CHttpsCaptureView::SetPreferredBox(const QString& BoxName)
{
    m_TargetScope = SSbieCaptureStart::eBox;
    m_TargetProcessId = 0;
    if (BoxName.isEmpty())
        return;
    int index = m_pBoxCombo->findText(BoxName, Qt::MatchFixedString);
    if (index >= 0)
        m_pBoxCombo->setCurrentIndex(index);
}


void CHttpsCaptureView::SetPreferredProcess(
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


void CHttpsCaptureView::RefreshBoxes()
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


void CHttpsCaptureView::RefreshCapabilities()
{
    m_CapabilityFlags = 0;
    if (theAPI && theAPI->IsConnected()) {
        auto result = theAPI->QueryCaptureCapabilities();
        if (!result.IsError())
            m_CapabilityFlags = result.GetValue().Flags;
    }
    UpdateControls();
}


bool CHttpsCaptureView::HttpsBackendReady() const
{
    return HttpsCapture_CanStart(
        m_CapabilityFlags,
        (const WCHAR*)m_PcapPath.utf16(),
        (const WCHAR*)m_HarPath.utf16());
}


QString CHttpsCaptureView::PreferredBoxName() const
{
    if (theGUI && theGUI->GetBoxView()) {
        QList<CSandBoxPtr> selected = theGUI->GetBoxView()->GetSelectedBoxes();
        if (selected.count() == 1 && !selected.first().isNull())
            return selected.first()->GetName();
    }
    return QStringLiteral("DefaultBox");
}


void CHttpsCaptureView::UpdateControls()
{
    const bool capturing = IsCapturing();
    const bool ready = HttpsBackendReady();
    m_pStart->setEnabled(ready && !capturing);
    m_pStop->setEnabled(capturing);
    m_pBrowsePcap->setEnabled(!capturing);
    m_pBrowseHar->setEnabled(!capturing);
    m_pBoxCombo->setEnabled(!capturing);
    m_pMaxFileBytes->setEnabled(!capturing);
    m_pMaxSeconds->setEnabled(!capturing);
    m_pRotateCount->setEnabled(!capturing);
    m_pLoopback->setEnabled(!capturing);
    m_pIncludeBodies->setEnabled(!capturing);
    m_pDisableRedaction->setEnabled(!capturing);

    if (!capturing &&
            (m_CapabilityFlags & HTTPS_CAPTURE_CAP_REQUIRED) !=
                HTTPS_CAPTURE_CAP_REQUIRED) {
        m_pStatus->setText(tr(
            "HTTPS capture is disabled until live isolation verification passes. The Start action remains unavailable."));
    }
    else if (!capturing && (m_PcapPath.isEmpty() || m_HarPath.isEmpty())) {
        m_pStatus->setText(tr("Choose both a PCAPNG file and a HAR file before starting."));
    }
}


void CHttpsCaptureView::UpdateStatus(const QString& Message)
{
    if (!Message.isEmpty()) {
        m_pStatus->setText(Message);
        return;
    }
    if (!IsCapturing()) {
        UpdateControls();
        return;
    }

    char status[512];
    QByteArray harUtf8 = m_HarPath.toUtf8();
    if (HttpsCapture_FormatStatus(
            status, sizeof(status),
            (ULONG)m_ExchangeCount, (ULONG)m_DroppedCount,
            harUtf8.constData()) == 0) {
        m_pStatus->setText(QString::fromUtf8(status));
    }
}


void CHttpsCaptureView::OnBrowsePcap()
{
    QString defaultName = m_PcapPath;
    if (defaultName.isEmpty())
        defaultName = QStringLiteral("https-capture.pcapng");
    QString path = QFileDialog::getSaveFileName(
        this, tr("Choose PCAPNG output"), defaultName,
        tr("PCAPNG files (*.pcapng);;All files (*.*)"));
    if (path.isEmpty())
        return;
    m_PcapPath = HttpsCapture_ToNative(path);
    m_pPcapPath->setText(m_PcapPath);
    UpdateControls();
}


void CHttpsCaptureView::OnBrowseHar()
{
    QString defaultName = m_HarPath;
    if (defaultName.isEmpty())
        defaultName = QStringLiteral("https-capture.har");
    QString path = QFileDialog::getSaveFileName(
        this, tr("Choose HAR output"), defaultName,
        tr("HAR files (*.har);;All files (*.*)"));
    if (path.isEmpty())
        return;
    m_HarPath = HttpsCapture_ToNative(path);
    m_pHarPath->setText(m_HarPath);
    UpdateControls();
}


void CHttpsCaptureView::CloseOutputFiles()
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


void CHttpsCaptureView::OnStart()
{
    if (!HttpsBackendReady()) {
        UpdateControls();
        return;
    }
    if (!theAPI || !theAPI->IsConnected()) {
        UpdateStatus(tr("Not connected to Sandboxie."));
        return;
    }
    if (m_pBoxCombo->currentText().isEmpty() ||
            m_PcapPath.isEmpty() || m_HarPath.isEmpty()) {
        UpdateStatus(tr("Choose a sandbox plus PCAPNG and HAR output files first."));
        return;
    }

    std::wstring pcapPath = m_PcapPath.toStdWString();
    std::wstring harPath = m_HarPath.toStdWString();
    HANDLE pcapFile = CreateFileW(
        pcapPath.c_str(), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (pcapFile == INVALID_HANDLE_VALUE) {
        UpdateStatus(tr("Failed to open the PCAPNG output file."));
        return;
    }
    HANDLE harFile = CreateFileW(
        harPath.c_str(), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (harFile == INVALID_HANDLE_VALUE) {
        CloseHandle(pcapFile);
        UpdateStatus(tr("Failed to open the HAR output file."));
        return;
    }
    m_PcapHandle = (quintptr)pcapFile;
    m_HarHandle = (quintptr)harFile;

    SSbieCaptureStart options;
    options.BoxName = m_pBoxCombo->currentText();
    options.Scope = m_TargetScope;
    options.ProcessId = m_TargetProcessId;
    options.Mode = SSbieCaptureStart::eHttps;
    options.Flags = m_TargetScope == SSbieCaptureStart::eBox ?
        SSbieCaptureStart::eIncludeFutureProcesses : 0;
    if (m_pLoopback->isChecked())
        options.Flags |= SSbieCaptureStart::eIncludeLoopback;
    if (m_pIncludeBodies->isChecked())
        options.Flags |= SSbieCaptureStart::eIncludeBodies;
    if (m_pDisableRedaction->isChecked())
        options.Flags |= SSbieCaptureStart::eDisableRedaction;
    options.MaxFileBytes = m_pMaxFileBytes->value();
    options.MaxSeconds = m_pMaxSeconds->value();
    options.RotateCount = m_pRotateCount->value();

    auto start = theAPI->StartCapture(options);
    if (start.IsError()) {
        CloseOutputFiles();
        UpdateStatus(tr("Failed to start HTTPS capture: 0x%1")
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
    auto harResult = theAPI->SetCaptureHarExport(
        session.Id, (quint64)(ULONG_PTR)harFile);
    CloseOutputFiles();
    if (harResult.IsError()) {
        if (!session.Id.IsNull())
            theAPI->StopCapture(session.Id);
        UpdateStatus(tr("Failed to attach the HAR output: 0x%1")
            .arg((quint32)harResult.GetStatus(), 8, 16, QChar('0')));
        return;
    }

    session = harResult.GetValue();
    if (session.State != SSbieCaptureSession::eRunning) {
        if (!session.Id.IsNull())
            theAPI->StopCapture(session.Id);
        UpdateStatus(tr("HTTPS backend did not reach RUNNING (state=%1, status=0x%2).")
            .arg(session.State)
            .arg(session.BackendStatus, 8, 16, QChar('0')));
        return;
    }

    m_CaptureId = session.Id;
    m_ExchangeCount = 0;
    m_DroppedCount = session.DroppedCount;
    m_HarOffset = 0;
    UpdateControls();
    UpdateStatus();
}


void CHttpsCaptureView::OnStop()
{
    if (!m_CaptureId.IsNull() && theAPI && theAPI->IsConnected())
        theAPI->StopCapture(m_CaptureId);
    m_CaptureId = SSbieCaptureId();
    CloseOutputFiles();
    UpdateControls();
}


void CHttpsCaptureView::OnClear()
{
    m_pEntries->setRowCount(0);
    m_ExchangeCount = 0;
    if (IsCapturing())
        UpdateStatus();
}


void CHttpsCaptureView::AppendRow(const HTTPS_CAPTURE_ROW& Row)
{
    if (m_pEntries->rowCount() >= HTTPS_CAPTURE_MAX_ROWS) {
        ++m_DroppedCount;
        return;
    }

    QString processName;
    if (theAPI) {
        CBoxedProcessPtr process = theAPI->GetProcessById(Row.pid);
        if (process)
            processName = process->GetProcessName();
    }

    const int row = m_pEntries->rowCount();
    m_pEntries->insertRow(row);
    m_pEntries->setItem(row, 0, new QTableWidgetItem(QString::fromUtf8(Row.time)));
    m_pEntries->setItem(row, 1, new QTableWidgetItem(QString::number(Row.pid)));
    m_pEntries->setItem(row, 2, new QTableWidgetItem(processName));
    m_pEntries->setItem(row, 3, new QTableWidgetItem(QString::fromUtf8(Row.method)));
    m_pEntries->setItem(row, 4, new QTableWidgetItem(QString::number(Row.status)));
    m_pEntries->setItem(row, 5, new QTableWidgetItem(QString::fromUtf8(Row.host)));
    m_pEntries->setItem(row, 6, new QTableWidgetItem(QString::fromUtf8(Row.path)));
    m_pEntries->setItem(row, 7, new QTableWidgetItem(QString::fromUtf8(Row.tls)));
    m_pEntries->setItem(row, 8, new QTableWidgetItem(
        Row.pinning_failed ? tr("failed") : tr("ok")));
    ++m_ExchangeCount;
}


void CHttpsCaptureView::ConsumeHarTail()
{
    if (m_HarPath.isEmpty())
        return;

    QFile file(m_HarPath);
    if (!file.open(QIODevice::ReadOnly))
        return;
    if (file.size() < m_HarOffset)
        m_HarOffset = 0;
    if (!file.seek(m_HarOffset))
        return;
    const QByteArray chunk = file.readAll();
    file.close();
    if (chunk.isEmpty())
        return;

    int cursor = 0;
    int consumed = 0;
    while (cursor < chunk.size()) {
        int end = 0;
        int start = HttpsCapture_FindEntry(chunk, cursor, &end);
        if (start < 0)
            break;
        HTTPS_CAPTURE_ROW row;
        QByteArray json = chunk.mid(start, end - start);
        if (HttpsCapture_ParseEntry(json.constData(), &row) == 0)
            AppendRow(row);
        cursor = end;
        consumed = end;
    }
    m_HarOffset += consumed;
}


void CHttpsCaptureView::timerEvent(QTimerEvent* pEvent)
{
    Q_UNUSED(pEvent);
    if (m_CaptureId.IsNull() || !theAPI || !theAPI->IsConnected())
        return;

    auto result = theAPI->GetCaptureStatus(m_CaptureId);
    if (result.IsError()) {
        OnStop();
        UpdateStatus(tr("HTTPS capture status failed: 0x%1")
            .arg((quint32)result.GetStatus(), 8, 16, QChar('0')));
        return;
    }

    const SSbieCaptureSession session = result.GetValue();
    m_DroppedCount = session.DroppedCount;
    ConsumeHarTail();
    if (session.State == SSbieCaptureSession::eFailed ||
            session.State == SSbieCaptureSession::eStopped) {
        m_CaptureId = SSbieCaptureId();
        CloseOutputFiles();
        UpdateStatus(tr("HTTPS capture ended (state=%1, status=0x%2).")
            .arg(session.State)
            .arg(session.BackendStatus, 8, 16, QChar('0')));
        UpdateControls();
        return;
    }
    UpdateStatus();
}


void CHttpsCaptureView::showEvent(QShowEvent* pEvent)
{
    QWidget::showEvent(pEvent);
    RefreshBoxes();
    RefreshCapabilities();
}


CHttpsCaptureWindow::CHttpsCaptureWindow(QWidget* parent)
    : QDialog(parent)
{
    Qt::WindowFlags flags = windowFlags();
    flags |= Qt::CustomizeWindowHint;
    flags &= ~Qt::WindowContextHelpButtonHint;
    setWindowFlags(flags);
    setWindowTitle(tr("Sandboxie-Plus - HTTPS Capture"));
    setWindowFlag(Qt::WindowStaysOnTopHint, theGUI->IsAlwaysOnTop());

    QGridLayout* pLayout = new QGridLayout();
    pLayout->setContentsMargins(3, 3, 3, 3);
    m_pView = new CHttpsCaptureView(true, this);
    pLayout->addWidget(m_pView, 0, 0);
    setLayout(pLayout);
    restoreGeometry(theConf->GetBlob("HttpsCaptureWindow/Window_Geometry"));
}


CHttpsCaptureWindow::~CHttpsCaptureWindow()
{
    theConf->SetBlob("HttpsCaptureWindow/Window_Geometry", saveGeometry());
}


void CHttpsCaptureWindow::closeEvent(QCloseEvent* e)
{
    Q_UNUSED(e);
    emit Closed();
    deleteLater();
}
