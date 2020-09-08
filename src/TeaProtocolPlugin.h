#ifndef hifi_TeaProtocolPluginImpl_h
#define hifi_TeaProtocolPluginImpl_h

#include <QUrl>

#include <plugins/TeaProtocolPlugin.h>
#include <ResourceRequest.h>

#include "TeaResourceRequest.h"

class TeaProtocolPluginImpl : public TeaProtocolPlugin {
public:
    virtual ResourceRequest* initRequest(
        const QUrl& url,
        const bool isObservable = true,
        const qint64 callerId = -1,
        const QString& extra = ""
    ) override {
        return new TeaResourceRequest(url, isObservable, callerId, extra);
    }

};

#endif // hifi_TeaProtocolPluginImpl_h
