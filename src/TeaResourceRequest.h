#ifndef hifi_TeaResourceRequest_h
#define hifi_TeaResourceRequest_h

#include <QThread>
#include <QUrl>

#include <ResourceRequest.h>

class TeaResourceRequestWorker : public QThread {
    Q_OBJECT

public:
    QUrl _url;
    bool _loadedFromCache;
    ResourceRequest::Result _result;
    ResourceRequest::State _state { ResourceRequest::State::NotStarted };

private:
    void run() override;

signals:
    void finished(QByteArray data, QString webMediaType);
};

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

    TeaResourceRequestWorker* worker;
};

#include "TeaResourceRequest.moc"

#endif // hifi_TeaResourceRequest_h
