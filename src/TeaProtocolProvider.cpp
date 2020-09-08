#include <mutex>

#include <QtCore/QObject>
#include <QtCore/QtPlugin>
#include <QtCore/QStringList>

#include <plugins/RuntimePlugin.h>
#include <plugins/TeaProtocolPlugin.h>

#include "TeaProtocolPlugin.h"

class TeaProtocolProviderImpl : public QObject, public TeaProtocolProvider {
    Q_OBJECT
    Q_PLUGIN_METADATA(IID TeaProtocolProvider_iid FILE "plugin.json")
    Q_INTERFACES(TeaProtocolProvider)

public:
	TeaProtocolProviderImpl(QObject* parent = nullptr) : QObject(parent) {}
    virtual ~TeaProtocolProviderImpl() {}

	virtual TeaProtocolPluginPointer getTeaProtocolPlugin() override {
        static std::once_flag once;
        std::call_once(once, [&] {
            _teaProtocolPlugin = std::make_shared<TeaProtocolPluginImpl>();
        });
        return _teaProtocolPlugin;
    }

private:
    TeaProtocolPluginPointer _teaProtocolPlugin;
};

#include "TeaProtocolProvider.moc"
