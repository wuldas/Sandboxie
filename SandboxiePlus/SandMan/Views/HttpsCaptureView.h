#pragma once

#include <QDialog>
#include <QWidget>

#include "../../QSbieAPI/SbieCapture.h"
#include "https_capture_model.h"

class QCheckBox;
class QComboBox;
class QLineEdit;
class QLabel;
class QPushButton;
class QSpinBox;
class QTableWidget;
class QTimerEvent;
class QShowEvent;
class QCloseEvent;


class CHttpsCaptureView : public QWidget
{
    Q_OBJECT
public:
    explicit CHttpsCaptureView(bool bStandAlone = false, QWidget* parent = 0);
    ~CHttpsCaptureView();

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

private:
    bool HttpsBackendReady() const;
    void UpdateControls();
    void UpdateStatus(const QString& Message = QString());
    void CloseOutputFiles();
    void AppendRow(const HTTPS_CAPTURE_ROW& Row);
    void ConsumeHarTail();
    QString PreferredBoxName() const;
    static QString CaptureOutputDir();

    int m_uTimerID;
    quint32 m_CapabilityFlags;
    SSbieCaptureId m_CaptureId;
    QString m_PcapPath;
    QString m_HarPath;
    quintptr m_PcapHandle;
    quintptr m_HarHandle;
    quint64 m_ExchangeCount;
    quint64 m_DroppedCount;
    qint64 m_HarOffset;
    quint32 m_TargetScope;
    quint32 m_TargetProcessId;

    QComboBox* m_pBoxCombo;
    QPushButton* m_pOpenFolder;
    QPushButton* m_pStart;
    QPushButton* m_pStop;
    QPushButton* m_pClear;
    QSpinBox* m_pMaxFileBytes;
    QSpinBox* m_pMaxSeconds;
    QSpinBox* m_pRotateCount;
    QCheckBox* m_pLoopback;
    QCheckBox* m_pIncludeBodies;
    QCheckBox* m_pDisableRedaction;
    QLabel* m_pStatus;
    QTableWidget* m_pEntries;
};


class CHttpsCaptureWindow : public QDialog
{
    Q_OBJECT
public:
    explicit CHttpsCaptureWindow(QWidget* parent = Q_NULLPTR);
    ~CHttpsCaptureWindow();

signals:
    void Closed();

protected:
    void closeEvent(QCloseEvent* e) override;

private:
    CHttpsCaptureView* m_pView;
};
