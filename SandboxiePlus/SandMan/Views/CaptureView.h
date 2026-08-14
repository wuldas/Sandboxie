#pragma once

#include "../../MiscHelpers/Common/PanelView.h"
#include "../../MiscHelpers/Common/TreeviewEx.h"
#include "../../QSbieAPI/SbieCapture.h"
#include "../../QSbieAPI/SbieStatus.h"

class CCaptureView : public QWidget
{
	Q_OBJECT
public:
	CCaptureView(bool bStandAlone = false, QWidget* parent = 0);
	~CCaptureView();

	void				Clear();
	void				StopCapture();
	bool				IsCapturing() const { return !m_CaptureId.IsNull(); }
	void				SetPreferredBox(const QString& BoxName);
	void				StartForBox(const QString& BoxName);
	void				StartForProcess(const QString& BoxName, quint32 ProcessId);

public slots:
	void				RefreshBoxes();

private slots:
	void				OnStart();
	void				OnStop();
	void				OnClear();
	void				OnSave();
	void				OnFilterChanged(const QString& Text);

protected:
	void				timerEvent(QTimerEvent* pEvent) override;
	void				showEvent(QShowEvent* pEvent) override;

	void				UpdateStatus();
	bool				BeginCapture(const SSbieCaptureStart& Options);
	QString				PreferredBoxName() const;
	void				EnqueueEvents(const SSbieCaptureEvents& Events);
	void				FlushPending();
	void				ApplyFilter();
	bool				ItemMatches(const QTreeWidgetItem* pItem) const;
	QTreeWidgetItem*	MakeItem(const SSbieCaptureEvent& Event);
	QString				ProcessName(quint32 ProcessId);
	void				AppendEvents(const SSbieCaptureEvents& Events);
	static QString		FormatAddress(const QByteArray& Address, quint16 AddressFamily);
	static QString		FormatEndpoint(const QByteArray& Address, quint16 AddressFamily, quint16 Port);
	static QString		FormatProtocol(quint8 Protocol, quint16 AddressFamily);
	static QString		FormatFileTime(quint64 FileTime);
	static QString		StatusText(const SB_STATUS& Status);
	static QString		CsvLine(const QStringList& Fields);

	int					m_uTimerID;
	SSbieCaptureId		m_CaptureId;
	QString				m_ActiveBox;
	quint32				m_ActivePid;
	quint64				m_DroppedCount;
	quint64				m_UiDroppedCount;
	int					m_EventCount;
	bool				m_AutoScroll;
	QString				m_FilterText;
	QList<SSbieCaptureEvent> m_PendingEvents;
	QHash<quint32, QString> m_ProcessNameCache;

	QVBoxLayout*		m_pMainLayout;
	QToolBar*			m_pToolBar;
	QComboBox*			m_pBoxCombo;
	QAction*			m_pStart;
	QAction*			m_pStop;
	QAction*			m_pClear;
	QAction*			m_pSave;
	QCheckBox*			m_pLoopback;
	QLineEdit*			m_pFilterEdit;
	QLabel*				m_pStatus;
	CPanelWidgetEx*		m_pList;
};

class CCaptureWindow : public QDialog
{
	Q_OBJECT
public:
	CCaptureWindow(QWidget *parent = Q_NULLPTR);
	~CCaptureWindow();

signals:
	void		Closed();

protected:
	void		closeEvent(QCloseEvent *e) override;

	CCaptureView* m_pView;
};
