#pragma once

#include <QDialog>
#include <QWidget>

#include "../../QSbieAPI/SbieCapture.h"

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


class CPacketCaptureView : public QWidget
{
    Q_OBJECT
public:
    explicit CPacketCaptureView(bool bStandAlone = false, QWidget* parent = 0);
    ~CPacketCaptureView();

    bool IsCapturing() const { return !m_CaptureId.IsNull(); }
    void SetPreferredBox(const QString& BoxName);

public slots:
    void RefreshBoxes();
    void RefreshCapabilities();

protected:
    void timerEvent(QTimerEvent* pEvent) override;
    void showEvent(QShowEvent* pEvent) override;

private slots:
    void OnBrowse();
    void OnStart();
    void OnStop();
    void OnClear();

private:
    bool PacketBackendReady() const;
    void UpdateControls();
    void UpdateStatus(const QString& Message = QString());
    void CloseOutputFile();
    QString PreferredBoxName() const;

    int m_uTimerID;
    quint32 m_CapabilityFlags;
    SSbieCaptureId m_CaptureId;
    QString m_OutputPath;
    quintptr m_OutputHandle;
    quint64 m_PacketCount;
    quint64 m_ByteCount;
    quint64 m_DroppedCount;

    QComboBox* m_pBoxCombo;
    QLineEdit* m_pOutputPath;
    QPushButton* m_pBrowse;
    QPushButton* m_pStart;
    QPushButton* m_pStop;
    QPushButton* m_pClear;
    QSpinBox* m_pSnapLength;
    QSpinBox* m_pMaxFileBytes;
    QSpinBox* m_pMaxSeconds;
    QSpinBox* m_pRotateCount;
    QCheckBox* m_pLoopback;
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
