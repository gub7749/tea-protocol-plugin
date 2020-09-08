#ifndef hifi_TeaResourceRequest_h
#define hifi_TeaResourceRequest_h

#include <QUrl>

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

};

#endif // hifi_TeaResourceRequest_h
