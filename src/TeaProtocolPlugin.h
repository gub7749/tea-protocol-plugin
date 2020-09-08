#ifndef hifi_TeaProtocolPluginImpl_h
#define hifi_TeaProtocolPluginImpl_h

#include <QString>

#include <plugins/TeaProtocolPlugin.h>

class TeaProtocolPluginImpl : public TeaProtocolPlugin {
public:
    QByteArray getFile(QString path) override;
};

#endif // hifi_TeaProtocolPluginImpl_h
