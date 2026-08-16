#pragma once

#include <QDialog>
#include <QWidget>

#include "../../QSbieAPI/SbieCapture.h"
#include "https_capture_model.h"

class QCheckBox;
class QComboBox;
class QLabel;
class QPushButton;
class QSpinBox;
class QTableWidget;
class QTimerEvent;
class QShowEvent;
class QCloseEvent;


struct SPacketCapture_RowData
{
    int Kind = 0;               // 0 = packet/stream record, 1 = HAR entry
    QByteArray Payload;         // payload bytes for the hex view
    QString Detail;             // HAR detail text for the HTTP view
};


class CPacketCaptureView : public QWidget
{
    Q_OBJECT
public:
    explicit CPacketCaptureView(bool bStandAlone = false, QWidget* parent = 0);
    ~CPacketCaptureView();

    bool IsCapturing() const { return !m_CaptureId.IsNull(); }
    void SetPreferredBox(const QString& BoxName);
    void SetPreferredProcess(const QString& BoxName, quint32 ProcessId);

public slots:
    void RefreshBoxes();
    void RefreshCapabilities();

protected:
    void timerEvent(QTimerEvent* pEvent) override;
    void showEvent(QShowEvent* pEvent) override;

private slots:
    void OnOpenFolder();
    void OnStart();
    void OnStop();
    void OnClear();
    void OnRowDoubleClicked(int Row, int Column);

private:
    bool PacketBackendReady() const;
    bool HttpsBackendReady() const;
    void UpdateControls();
    void UpdateStatus(const QString& Message = QString());
    void RefreshPacketRows();
    void AppendRecords(const QList<SSbieCaptureRecord>& Records);
    void AppendRecord(const SSbieCaptureRecord& Record);
    void AppendHarRow(const HTTPS_CAPTURE_ROW& Row);
    void ConsumeHarTail();
    void TrimRows();
    void CloseOutputFiles();
    QString PreferredBoxName() const;
    static QString CaptureOutputDir();
    static QString PacketCapture_InfoText(const SSbieCaptureRecord& Record);

    int m_uTimerID;
    quint32 m_CapabilityFlags;
    SSbieCaptureId m_CaptureId;
    QString m_OutputPath;
    QString m_HarPath;
    quintptr m_PcapHandle;
    quintptr m_HarHandle;
    quint64 m_PacketCount;
    quint64 m_ByteCount;
    quint64 m_DroppedCount;
    qint64 m_HarOffset;
    quint32 m_TargetScope;
    quint32 m_TargetProcessId;
    QList<SPacketCapture_RowData> m_RowData;

    QComboBox* m_pBoxCombo;
    QPushButton* m_pOpenFolder;
    QPushButton* m_pStart;
    QPushButton* m_pStop;
    QPushButton* m_pClear;
    QSpinBox* m_pSnapLength;
    QSpinBox* m_pMaxFileBytes;
    QSpinBox* m_pMaxSeconds;
    QSpinBox* m_pRotateCount;
    QCheckBox* m_pLoopback;
    QCheckBox* m_pIncludeBodies;
    QCheckBox* m_pDisableRedaction;
    QLabel* m_pStatus;
    QTableWidget* m_pPackets;
};


class CPacketCaptureWindow : public QDialog
{
    Q_OBJECT
public:
    explicit CPacketCaptureWindow(QWidget* parent = Q_NULLPTR);
    ~CPacketCaptureWindow();

signals:
    void Closed();

protected:
    void closeEvent(QCloseEvent* e) override;

private:
    CPacketCaptureView* m_pView;
};
