#ifndef hifi_TeaResourceRequest_h
#define hifi_TeaResourceRequest_h

#include <QUrl>
#include <QNetworkReply>
#include <QTimer>

#include <ResourceRequest.h>

class TeaResourceRequest : public ResourceRequest {
    Q_OBJECT

public:
    TeaResourceRequest(
        const QUrl& url,
        const bool isObservable = true,
        const qint64 callerId = -1,
        const QString& extra = ""
    ) : ResourceRequest(url, isObservable, callerId, extra) { }

protected:
    virtual void doSend() override;

private slots:
    void onTimeout();
    void onDownloadProgress(qint64 bytesReceived, qint64 bytesTotal);
    void onRequestFinished();

private:
    void setupTimeout();
    void cleanupTimeout();

    QString path;
    QTimer* timeout { nullptr };
    QNetworkReply* reply { nullptr };
};

#include "TeaResourceRequest.moc"

#endif // hifi_TeaResourceRequest_h
