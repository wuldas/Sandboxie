#include "stdafx.h"
#include "CaptureView.h"
#include "..\\SandMan.h"
#include "SbieView.h"
#include "../QSbieAPI/SbieAPI.h"
#include <QElapsedTimer>
#include <QHash>

static const int CAPTURE_MAX_ROWS = 2000;
static const int CAPTURE_POLL_BATCHES = 8;
static const int CAPTURE_PENDING_MAX = 4000;
static const int CAPTURE_FLUSH_MIN = 25;
static const int CAPTURE_FLUSH_MAX = 200;
static const qint64 CAPTURE_FLUSH_BUDGET_NS = 8 * 1000 * 1000;

CCaptureView::CCaptureView(bool bStandAlone, QWidget* parent)
	: QWidget(parent)
{
	Q_UNUSED(bStandAlone);

	m_uTimerID = startTimer(100);
	m_DroppedCount = 0;
	m_UiDroppedCount = 0;
	m_EventCount = 0;
	m_ActivePid = 0;
	m_AutoScroll = true;

	m_pMainLayout = new QVBoxLayout(this);
	m_pMainLayout->setContentsMargins(0, 0, 0, 0);
	m_pMainLayout->setSpacing(2);

	m_pToolBar = new QToolBar();
	m_pBoxCombo = new QComboBox();
	m_pBoxCombo->setMinimumWidth(140);
	m_pToolBar->addWidget(new QLabel(tr(" Box ")));
	m_pToolBar->addWidget(m_pBoxCombo);

	m_pStart = m_pToolBar->addAction(CSandMan::GetIcon("Connect"), tr("Start"), this, SLOT(OnStart()));
	m_pStop = m_pToolBar->addAction(CSandMan::GetIcon("Stop"), tr("Stop"), this, SLOT(OnStop()));
	m_pClear = m_pToolBar->addAction(CSandMan::GetIcon("Clean"), tr("Clear"), this, SLOT(OnClear()));
	m_pSave = m_pToolBar->addAction(CSandMan::GetIcon("Save"), tr("Save to file"), this, SLOT(OnSave()));
	m_pToolBar->addSeparator();
	m_pLoopback = new QCheckBox(tr("Include loopback"));
	m_pToolBar->addWidget(m_pLoopback);
	m_pToolBar->addSeparator();
	m_pToolBar->addWidget(new QLabel(tr(" Filter ")));
	m_pFilterEdit = new QLineEdit();
	m_pFilterEdit->setPlaceholderText(tr("PID, process, address..."));
	m_pFilterEdit->setClearButtonEnabled(true);
	m_pFilterEdit->setMinimumWidth(180);
	m_pToolBar->addWidget(m_pFilterEdit);
	connect(m_pFilterEdit, SIGNAL(textChanged(const QString&)), this, SLOT(OnFilterChanged(const QString&)));
	m_pMainLayout->addWidget(m_pToolBar);

	m_pStatus = new QLabel();
	m_pStatus->setWordWrap(true);
	m_pMainLayout->addWidget(m_pStatus);

	m_pList = new CPanelWidgetEx();
	m_pList->GetTree()->setItemDelegate(new CTreeItemDelegate());
	m_pList->GetTree()->setAlternatingRowColors(theConf->GetBool("Options/AltRowColors", false));
	((QTreeWidgetEx*)m_pList->GetView())->setHeaderLabels(
		tr("Time|PID|Process|Event|Direction|Protocol|Local|Remote|Result").split("|"));
	((QTreeWidgetEx*)m_pList->GetView())->setColumnFixed(1, true);
	m_pList->GetView()->setSelectionMode(QAbstractItemView::ExtendedSelection);
	m_pList->GetView()->setSortingEnabled(false);
	m_pList->GetTree()->setUniformRowHeights(true);
	m_pList->GetTree()->setItemsExpandable(false);
	m_pMainLayout->addWidget(m_pList);

	if (theAPI)
		connect(theAPI, SIGNAL(StatusChanged()), this, SLOT(RefreshBoxes()));
	RefreshBoxes();
	UpdateStatus();
}

CCaptureView::~CCaptureView()
{
	killTimer(m_uTimerID);
	StopCapture();
}

void CCaptureView::SetPreferredBox(const QString& BoxName)
{
	if (BoxName.isEmpty())
		return;
	int Index = m_pBoxCombo->findText(BoxName, Qt::MatchFixedString);
	if (Index >= 0)
		m_pBoxCombo->setCurrentIndex(Index);
}

void CCaptureView::StartForBox(const QString& BoxName)
{
	if (BoxName.isEmpty())
		return;

	RefreshBoxes();
	SetPreferredBox(BoxName);
	if (!m_CaptureId.IsNull()) {
		if (m_ActivePid == 0 &&
				m_ActiveBox.compare(BoxName, Qt::CaseInsensitive) == 0)
			return;
		OnStop();
		SetPreferredBox(BoxName);
	}
	OnStart();
}

void CCaptureView::StartForProcess(const QString& BoxName, quint32 ProcessId)
{
	if (BoxName.isEmpty() || !ProcessId)
		return;

	RefreshBoxes();
	SetPreferredBox(BoxName);
	if (!m_CaptureId.IsNull()) {
		if (m_ActivePid == ProcessId &&
				m_ActiveBox.compare(BoxName, Qt::CaseInsensitive) == 0)
			return;
		OnStop();
		SetPreferredBox(BoxName);
	}

	SSbieCaptureStart Options;
	Options.BoxName = BoxName;
	Options.Scope = SSbieCaptureStart::eProcess;
	Options.Mode = SSbieCaptureStart::eConnections;
	Options.ProcessId = ProcessId;
	Options.Flags = 0;
	if (m_pLoopback->isChecked())
		Options.Flags |= SSbieCaptureStart::eIncludeLoopback;
	BeginCapture(Options);
}

void CCaptureView::showEvent(QShowEvent* pEvent)
{
	QWidget::showEvent(pEvent);
	RefreshBoxes();
}

QString CCaptureView::PreferredBoxName() const
{
	if (theGUI && theGUI->GetBoxView()) {
		QList<CSandBoxPtr> Selected = theGUI->GetBoxView()->GetSelectedBoxes();
		if (Selected.count() == 1 && !Selected.first().isNull())
			return Selected.first()->GetName();
	}
	return QStringLiteral("DefaultBox");
}

void CCaptureView::RefreshBoxes()
{
	if (!theAPI || !theAPI->IsConnected())
		return;

	QString Current = m_pBoxCombo->currentText();
	if (Current.isEmpty())
		Current = PreferredBoxName();

	m_pBoxCombo->blockSignals(true);
	m_pBoxCombo->clear();
	QMap<QString, CSandBoxPtr> Boxes = theAPI->GetAllBoxes();
	for (auto I = Boxes.begin(); I != Boxes.end(); ++I) {
		if (I.value() && I.value()->IsEnabled())
			m_pBoxCombo->addItem(I.value()->GetName());
	}
	int Index = m_pBoxCombo->findText(Current, Qt::MatchFixedString);
	if (Index < 0)
		Index = m_pBoxCombo->findText(QStringLiteral("DefaultBox"), Qt::MatchFixedString);
	if (Index < 0 && m_pBoxCombo->count() > 0)
		Index = 0;
	if (Index >= 0)
		m_pBoxCombo->setCurrentIndex(Index);
	m_pBoxCombo->blockSignals(false);
}

void CCaptureView::Clear()
{
	m_PendingEvents.clear();
	m_ProcessNameCache.clear();
	m_UiDroppedCount = 0;
	m_pList->GetTree()->clear();
	m_EventCount = 0;
	UpdateStatus();
}

void CCaptureView::StopCapture()
{
	if (m_CaptureId.IsNull() || !theAPI || !theAPI->IsConnected()) {
		m_CaptureId = SSbieCaptureId();
		UpdateStatus();
		return;
	}

	theAPI->StopCapture(m_CaptureId);
	m_CaptureId = SSbieCaptureId();
	UpdateStatus();
}

void CCaptureView::OnStart()
{
	RefreshBoxes();
	const QString BoxName = m_pBoxCombo->currentText();
	if (BoxName.isEmpty()) {
		m_pStatus->setText(tr("Select a sandbox first."));
		return;
	}

	SSbieCaptureStart Options;
	Options.BoxName = BoxName;
	Options.Scope = SSbieCaptureStart::eBox;
	Options.Mode = SSbieCaptureStart::eConnections;
	Options.Flags = SSbieCaptureStart::eIncludeFutureProcesses;
	if (m_pLoopback->isChecked())
		Options.Flags |= SSbieCaptureStart::eIncludeLoopback;
	BeginCapture(Options);
}

bool CCaptureView::BeginCapture(const SSbieCaptureStart& Options)
{
	if (!theAPI || !theAPI->IsConnected()) {
		m_pStatus->setText(tr("Not connected to Sandboxie."));
		return false;
	}
	if (!m_CaptureId.IsNull())
		return false;

	auto Caps = theAPI->QueryCaptureCapabilities();
	if (Caps.IsError()) {
		theGUI->CheckResults(QList<SB_STATUS>() << Caps, this);
		return false;
	}
	if ((Caps.GetValue().Flags & 0x00000002) == 0) {
		m_pStatus->setText(tr("Connection audit is unavailable. Enable NetworkEnableWFP=y and reload the driver."));
		return false;
	}

	auto Result = theAPI->StartCapture(Options);
	if (Result.IsError()) {
		theGUI->CheckResults(QList<SB_STATUS>() << Result, this);
		m_pStatus->setText(tr("Failed to start connection audit: %1").arg(StatusText(Result)));
		return false;
	}

	const SSbieCaptureSession Session = Result.GetValue();
	if (Session.State != 3) {
		m_pStatus->setText(tr("Capture did not enter the running state (state=%1, backend=0x%2).")
			.arg(Session.State)
			.arg(Session.BackendStatus, 8, 16, QLatin1Char('0')));
		if (!Session.Id.IsNull())
			theAPI->StopCapture(Session.Id);
		return false;
	}

	m_CaptureId = Session.Id;
	m_DroppedCount = Session.DroppedCount;
	m_ActiveBox = Options.BoxName;
	m_ActivePid = Options.ProcessId;
	m_pBoxCombo->setEnabled(false);
	m_pLoopback->setEnabled(false);
	UpdateStatus();
	return true;
}

void CCaptureView::OnStop()
{
	StopCapture();
	m_ActiveBox.clear();
	m_ActivePid = 0;
	m_pBoxCombo->setEnabled(true);
	m_pLoopback->setEnabled(true);
}

void CCaptureView::OnClear()
{
	Clear();
}

void CCaptureView::OnSave()
{
	QString DefaultName = QStringLiteral("connection-audit");
	if (!m_ActiveBox.isEmpty())
		DefaultName += QLatin1Char('-') + m_ActiveBox;
	else if (!m_pBoxCombo->currentText().isEmpty())
		DefaultName += QLatin1Char('-') + m_pBoxCombo->currentText();
	if (m_ActivePid)
		DefaultName += QStringLiteral("-pid%1").arg(m_ActivePid);
	DefaultName += QStringLiteral(".csv");

	const QString Path = QFileDialog::getSaveFileName(this,
		tr("Save connection audit to file"), DefaultName,
		tr("CSV files (*.csv);;All files (*.*)")).replace("/", "\\");
	if (Path.isEmpty())
		return;

	QFile File(Path);
	if (!File.open(QFile::WriteOnly | QFile::Truncate)) {
		QMessageBox::critical(this, "Sandboxie-Plus", tr("Failed to open file for writing"));
		return;
	}

	QTextStream Out(&File);
	Out.setEncoding(QStringConverter::Utf8);
	Out.setGenerateByteOrderMark(true);

	QTreeWidget* pTree = m_pList->GetTree();
	QStringList Header;
	const int Columns = pTree->columnCount();
	if (QTreeWidgetItem* pHeader = pTree->headerItem()) {
		for (int Column = 0; Column < Columns; ++Column)
			Header.append(pHeader->text(Column));
	}
	Out << CsvLine(Header) << "\n";

	int Written = 0;
	const int Count = pTree->topLevelItemCount();
	for (int Index = 0; Index < Count; ++Index) {
		QTreeWidgetItem* pItem = pTree->topLevelItem(Index);
		if (pItem->isHidden())
			continue;
		QStringList Row;
		for (int Column = 0; Column < Columns; ++Column)
			Row.append(pItem->text(Column));
		Out << CsvLine(Row) << "\n";
		++Written;
	}
	Out.flush();
	File.close();

	m_pStatus->setText(tr("Saved %1 visible connection-audit rows to %2. This is not packet capture.")
		.arg(Written).arg(Path));
}

QString CCaptureView::CsvLine(const QStringList& Fields)
{
	QStringList Escaped;
	foreach(const QString& Field, Fields) {
		if (Field.contains(QLatin1Char('"')) || Field.contains(QLatin1Char(',')) ||
			Field.contains(QLatin1Char('\n')) || Field.contains(QLatin1Char('\r'))) {
			QString Value = Field;
			Value.replace(QLatin1Char('"'), QStringLiteral("\"\""));
			Escaped.append(QLatin1Char('"') + Value + QLatin1Char('"'));
		}
		else
			Escaped.append(Field);
	}
	return Escaped.join(QLatin1Char(','));
}

void CCaptureView::OnFilterChanged(const QString& Text)
{
	m_FilterText = Text.trimmed();
	ApplyFilter();
	UpdateStatus();
}

bool CCaptureView::ItemMatches(const QTreeWidgetItem* pItem) const
{
	if (m_FilterText.isEmpty())
		return true;
	const int Columns = pItem->columnCount();
	for (int Column = 0; Column < Columns; ++Column) {
		if (pItem->text(Column).contains(m_FilterText, Qt::CaseInsensitive))
			return true;
	}
	return false;
}

void CCaptureView::ApplyFilter()
{
	QTreeWidget* pTree = m_pList->GetTree();
	const bool Updates = pTree->updatesEnabled();
	pTree->setUpdatesEnabled(false);
	const int Count = pTree->topLevelItemCount();
	for (int Index = 0; Index < Count; ++Index) {
		QTreeWidgetItem* pItem = pTree->topLevelItem(Index);
		pItem->setHidden(!ItemMatches(pItem));
	}
	pTree->setUpdatesEnabled(Updates);
}

void CCaptureView::timerEvent(QTimerEvent* pEvent)
{
	if (pEvent->timerId() != m_uTimerID)
		return;

	if (!theAPI || !theAPI->IsConnected()) {
		if (!m_CaptureId.IsNull()) {
			m_CaptureId = SSbieCaptureId();
			m_ActiveBox.clear();
			m_ActivePid = 0;
			m_PendingEvents.clear();
			m_pBoxCombo->setEnabled(true);
			m_pLoopback->setEnabled(true);
			UpdateStatus();
		}
		return;
	}

	if (m_CaptureId.IsNull()) {
		if (!m_PendingEvents.isEmpty())
			FlushPending();
		return;
	}

	for (int Batch = 0; Batch < CAPTURE_POLL_BATCHES; ++Batch) {
		auto Result = theAPI->ReadCaptureEvents(m_CaptureId, 32);
		if (Result.IsError()) {
			m_pStatus->setText(tr("Read failed: %1").arg(StatusText(Result)));
			StopCapture();
			m_ActiveBox.clear();
			m_ActivePid = 0;
			m_pBoxCombo->setEnabled(true);
			m_pLoopback->setEnabled(true);
			return;
		}

		const SSbieCaptureEvents Events = Result.GetValue();
		m_DroppedCount = Events.DroppedCount;
		if (!Events.Events.isEmpty())
			EnqueueEvents(Events);
		if (Events.RemainingEvents == 0)
			break;
	}

	FlushPending();
	UpdateStatus();
}

void CCaptureView::EnqueueEvents(const SSbieCaptureEvents& Events)
{
	if (Events.Events.isEmpty())
		return;

	m_PendingEvents += Events.Events;
	if (m_PendingEvents.size() > CAPTURE_PENDING_MAX) {
		const int Drop = m_PendingEvents.size() - CAPTURE_PENDING_MAX;
		m_PendingEvents.erase(m_PendingEvents.begin(),
			m_PendingEvents.begin() + Drop);
		m_UiDroppedCount += (quint64)Drop;
	}
}

void CCaptureView::FlushPending()
{
	if (m_PendingEvents.isEmpty())
		return;

	QTreeWidget* pTree = m_pList->GetTree();
	QScrollBar* pBar = pTree->verticalScrollBar();
	const bool StickToBottom = m_AutoScroll && pBar &&
		pBar->value() >= pBar->maximum() - 2;
	const bool Updates = pTree->updatesEnabled();
	pTree->setUpdatesEnabled(false);

	int Take = qMin(CAPTURE_FLUSH_MAX, m_PendingEvents.size());
	QElapsedTimer FlushTimer;
	FlushTimer.start();

	QList<QTreeWidgetItem*> Items;
	Items.reserve(Take);
	for (int Index = 0; Index < Take; ++Index) {
		Items.append(MakeItem(m_PendingEvents.at(Index)));
		if (Index + 1 >= CAPTURE_FLUSH_MIN &&
				FlushTimer.nsecsElapsed() >= CAPTURE_FLUSH_BUDGET_NS) {
			Take = Index + 1;
			break;
		}
	}
	m_PendingEvents.erase(m_PendingEvents.begin(),
		m_PendingEvents.begin() + Take);
	m_EventCount += Take;

	if (!Items.isEmpty())
		pTree->addTopLevelItems(Items);

	if (!m_FilterText.isEmpty()) {
		foreach(QTreeWidgetItem* pItem, Items)
			pItem->setHidden(!ItemMatches(pItem));
	}

	const int Extra = pTree->topLevelItemCount() - CAPTURE_MAX_ROWS;
	if (Extra > 0) {
		for (int Index = 0; Index < Extra; ++Index)
			delete pTree->takeTopLevelItem(0);
		m_EventCount = pTree->topLevelItemCount();
	}

	pTree->setUpdatesEnabled(Updates);
	if (StickToBottom)
		pTree->scrollToBottom();
}

QTreeWidgetItem* CCaptureView::MakeItem(const SSbieCaptureEvent& Event)
{
	QTreeWidgetItem* pItem = new QTreeWidgetItem();
	pItem->setText(0, FormatFileTime(Event.Timestamp));
	pItem->setText(1, QString::number(Event.ProcessId));
	pItem->setText(2, ProcessName(Event.ProcessId));
	pItem->setText(3, Event.Type == SSbieCaptureEvent::eAcceptAttempt ?
		tr("accept attempt") : tr("connect attempt"));
	pItem->setText(4, Event.Direction == SSbieCaptureEvent::eInbound ?
		tr("inbound") : tr("outbound"));
	pItem->setText(5, FormatProtocol(Event.Protocol, Event.AddressFamily));
	pItem->setText(6, FormatEndpoint(Event.LocalAddress, Event.AddressFamily, Event.LocalPort));
	pItem->setText(7, FormatEndpoint(Event.RemoteAddress, Event.AddressFamily, Event.RemotePort));
	QString Result = Event.Blocked ? tr("blocked") : tr("allowed");
	if (Event.Loopback)
		Result += tr(" / loopback");
	pItem->setText(8, Result);
	return pItem;
}

QString CCaptureView::ProcessName(quint32 ProcessId)
{
	auto It = m_ProcessNameCache.constFind(ProcessId);
	if (It != m_ProcessNameCache.constEnd())
		return It.value();

	QString Name;
	if (theAPI) {
		CBoxedProcessPtr pProcess = theAPI->GetProcessById(ProcessId);
		if (!pProcess.isNull())
			Name = pProcess->GetProcessName();
	}
	m_ProcessNameCache.insert(ProcessId, Name);
	return Name;
}

void CCaptureView::AppendEvents(const SSbieCaptureEvents& Events)
{
	EnqueueEvents(Events);
	FlushPending();
}

void CCaptureView::UpdateStatus()
{
	if (!m_CaptureId.IsNull()) {
		QString Target = m_ActiveBox;
		if (m_ActivePid)
			Target = tr("%1 PID %2").arg(m_ActiveBox).arg(m_ActivePid);
		QString Text = tr("Recording connection authorization attempts for %1. Shown: %2  Queued: %3  Dropped: %4  (not packet capture)")
			.arg(Target)
			.arg(m_EventCount)
			.arg(m_PendingEvents.size())
			.arg(m_DroppedCount);
		if (m_UiDroppedCount)
			Text += tr("  UI overflow: %1").arg(m_UiDroppedCount);
		if (!m_FilterText.isEmpty()) {
			int Matching = 0;
			QTreeWidget* pTree = m_pList->GetTree();
			const int Count = pTree->topLevelItemCount();
			for (int Index = 0; Index < Count; ++Index) {
				if (!pTree->topLevelItem(Index)->isHidden())
					++Matching;
			}
			Text += tr("  Matching: %1").arg(Matching);
		}
		m_pStatus->setText(Text);
	}
	else {
		m_pStatus->setText(tr("Idle. Start to record sandbox connection authorization attempts. This is not packet capture."));
	}

	const bool bRun = !m_CaptureId.IsNull();
	m_pStart->setEnabled(!bRun);
	m_pStop->setEnabled(bRun);
}

QString CCaptureView::FormatAddress(const QByteArray& Address, quint16 AddressFamily)
{
	if (AddressFamily == 2 && Address.size() >= 4) {
		return QString("%1.%2.%3.%4")
			.arg((unsigned int)(quint8)Address[0])
			.arg((unsigned int)(quint8)Address[1])
			.arg((unsigned int)(quint8)Address[2])
			.arg((unsigned int)(quint8)Address[3]);
	}

	if (AddressFamily == 23 && Address.size() >= 16) {
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

QString CCaptureView::FormatEndpoint(const QByteArray& Address, quint16 AddressFamily, quint16 Port)
{
	const QString Host = FormatAddress(Address, AddressFamily);
	if (AddressFamily == 23)
		return QString("[%1]:%2").arg(Host).arg(Port);
	return QString("%1:%2").arg(Host).arg(Port);
}

QString CCaptureView::FormatProtocol(quint8 Protocol, quint16 AddressFamily)
{
	QString Family = (AddressFamily == 23) ? "IPv6" : (AddressFamily == 2) ? "IPv4" : QString::number(AddressFamily);
	QString Proto;
	switch (Protocol) {
	case 6: Proto = "TCP"; break;
	case 17: Proto = "UDP"; break;
	case 1: Proto = "ICMP"; break;
	case 58: Proto = "ICMPv6"; break;
	default: Proto = QString::number(Protocol); break;
	}
	return Family + QLatin1Char('/') + Proto;
}

QString CCaptureView::FormatFileTime(quint64 FileTime)
{
	const quint64 EpochDiff = 116444736000000000ULL;
	if (FileTime < EpochDiff)
		return QString::number(FileTime);
	const qint64 Ms = (qint64)((FileTime - EpochDiff) / 10000ULL);
	return QDateTime::fromMSecsSinceEpoch(Ms).toString("hh:mm:ss.zzz");
}

QString CCaptureView::StatusText(const SB_STATUS& Status)
{
	if (!Status.IsError())
		return tr("OK");
	return CSandMan::FormatError(Status);
}

CCaptureWindow::CCaptureWindow(QWidget *parent)
	: QDialog(parent)
{
	Qt::WindowFlags flags = windowFlags();
	flags |= Qt::CustomizeWindowHint;
	flags &= ~Qt::WindowContextHelpButtonHint;
	setWindowFlags(flags);

	setWindowTitle(tr("Sandboxie-Plus - Connection Audit"));
	setWindowFlag(Qt::WindowStaysOnTopHint, theGUI->IsAlwaysOnTop());

	QGridLayout* pLayout = new QGridLayout();
	pLayout->setContentsMargins(3, 3, 3, 3);
	m_pView = new CCaptureView(true, this);
	pLayout->addWidget(m_pView, 0, 0);
	setLayout(pLayout);

	restoreGeometry(theConf->GetBlob("CaptureWindow/Window_Geometry"));
}

CCaptureWindow::~CCaptureWindow()
{
	theConf->SetBlob("CaptureWindow/Window_Geometry", saveGeometry());
}

void CCaptureWindow::closeEvent(QCloseEvent *e)
{
	Q_UNUSED(e);
	emit Closed();
	this->deleteLater();
}
