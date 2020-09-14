#include "TeaResourceRequest.h"

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/ossl_typ.h>
#include <openssl/rand.h>

#include <QFile>
#include <QJsonDocument>
#include <QLoggingCategory>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QMetaEnum>
#include <QTcpSocket>
#include <QtConcurrent/QtConcurrent>

#include <SharedUtil.h>
#include <StatTracker.h>
#include <AccountManager.h>
#include <NetworkAccessManager.h>
#include <NetworkLogging.h>
#include <NetworkingConstants.h>
#include <ResourceRequest.h>

#include "TeaProtocolPlugin.h"

Q_LOGGING_CATEGORY(tea, "tivoli.tea")

QString hash(QString input, QCryptographicHash::Algorithm algorithm) {
    return QCryptographicHash::hash(input.toLocal8Bit(), algorithm).toHex();
}

QString password(QString seed = "") {
    QString a1 = hash("1. " + seed + "y0u", QCryptographicHash::Algorithm::Sha224);
    QString a2 = hash("2. " + seed + "are", QCryptographicHash::Algorithm::Sha384);
    QString a3 = hash("3. " + seed + "bEAUt1ful", QCryptographicHash::Algorithm::Md4);
    QString b1 = hash(
        a3 + "i really l1ke" + a1 + "strawBERRy ch33s3 cAk3" + a2,
        QCryptographicHash::Algorithm::Md5
    );
    QString b2 = hash(
        a1 + "bUT ONly" + a2 + "w1th wh1pp3d CREAM!" + a3,
        QCryptographicHash::Algorithm::Sha1
    );
    QString b3 = hash(
        a2 + "i also like" + a1 + "bagels with cream cheese" + a3,
        QCryptographicHash::Algorithm::Sha256
    );
    QString c1 = hash(
        "oh well" +
            a1 +
            "ill hope you" +
            b2 +
            "never ever" +
            a3 +
            "guess this" +
            b1 +
            "because we're trying to" +
            a2 +
            "protect people's work" +
            b3,
        QCryptographicHash::Algorithm::Sha512
    );
    QString c2 = hash(
        a3 +
            "sqiurrels" +
            c1 +
            "are" +
            b3 +
            "really" +
            a1 +
            "cute" +
            b2 +
            "and" +
            a2 +
            "foxes" +
            b1 +
            "are" +
            c1 +
            "really" +
            b2 +
            "silly",
        QCryptographicHash::Algorithm::Sha512
    );
    // qDebug() << "Maki AES: password"<<seed<< QString(c2+c1);
    return c2 + c1;
}

QByteArray encrypt(QByteArray plaindata, QString seed) {
    QByteArray data;

    unsigned char salt[8];
    RAND_bytes(salt, 8);

    // qDebug() << "Maki AES: Plain data length" << plaindata.length();

    unsigned char* cipherdata = (unsigned char*)malloc(plaindata.length() + 128); // requires a little extra
    int cipherdata_len;

    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
	int iklen = EVP_CIPHER_key_length(cipher);
	int ivlen = EVP_CIPHER_iv_length(cipher);
	int iter = 10000; // default in openssl 1.1.1
    unsigned char* keyivpair = (unsigned char*)malloc(iklen + ivlen);

    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];

    const char* passwordStr = password(seed).toLocal8Bit();

    if(!PKCS5_PBKDF2_HMAC(
		passwordStr, -1, salt, 8, iter,
        EVP_sha512(), iklen + ivlen, keyivpair
	)) {
		// qDebug() << "Maki AES: Failed to get Key IV pair";
        return data;
	}
    memcpy(key, keyivpair, iklen);                                              
  	memcpy(iv, keyivpair + iklen, ivlen);
    free(keyivpair);

    // qDebug() << "Maki AES: Salt" << QByteArray((char*)salt, 8).toHex();
    // qDebug() << "Maki AES: Key " << QByteArray((char*)key, EVP_MAX_KEY_LENGTH).toHex();
    // qDebug() << "Maki AES: IV  " << QByteArray((char*)iv, EVP_MAX_IV_LENGTH).toHex();

    int len;
    EVP_CIPHER_CTX *ctx;   
	if (!(ctx = EVP_CIPHER_CTX_new())) {
		// qDebug() << "Maki AES: Failed to init ctx";
        return data;
	}
    // qDebug() << "Maki AES: Initialized ctx";
    if (!EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv)) {
		// qDebug() << "Maki AES: Failed to init encrypt";
        return data;
	}
    // qDebug() << "Maki AES: Initialized encrypt";
    if (!EVP_EncryptUpdate(ctx,
        cipherdata, &len,
        (unsigned char*)plaindata.constData(), plaindata.length()
    )) {
		// qDebug() << "Maki AES: Failed to update encrypt";
        return data;
	}
    // qDebug() << "Maki AES: Updated encrypt";
    cipherdata_len = len;
    if(!EVP_EncryptFinal_ex(ctx,
        cipherdata + len, &len)
    ) {
		// qDebug() << "Maki AES: Failed to finalize encrypt";
        return data;
	}
    // qDebug() << "Maki AES: Finalized encrypt";
    cipherdata_len += len;
    EVP_CIPHER_CTX_free(ctx);

    // qDebug() << "Maki AES: Cipher data length" << cipherdata_len;

    QByteArray header = QByteArray(reinterpret_cast<char*>(salt), 8);
    header.prepend(QString("Salted__").toLocal8Bit());

    data = QByteArray(reinterpret_cast<char*>(cipherdata), cipherdata_len);
    data.prepend(header);
    free(cipherdata);

    return data;
}

QByteArray decrypt(QByteArray cipherdata, QString seed) {
    QByteArray data;

    QByteArray salt = cipherdata.mid(8, 8);
    cipherdata.remove(0, 16); // Salted__xxxxxxxx

    // qDebug() << "Maki AES: Cipher data length" << cipherdata.length();

    unsigned char* plaindata = (unsigned char*)malloc(cipherdata.length());
    int plaindata_len;

    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
	int iklen = EVP_CIPHER_key_length(cipher);
	int ivlen = EVP_CIPHER_iv_length(cipher);
	int iter = 10000; // default in openssl 1.1.1
    unsigned char* keyivpair = (unsigned char*)malloc(iklen + ivlen);

    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];

    const char* passwordStr = password(seed).toLocal8Bit();

    if(!PKCS5_PBKDF2_HMAC(
		passwordStr, -1, (unsigned char*)salt.constData(), 8, iter,
        EVP_sha512(), iklen + ivlen, keyivpair
	)) {
		// qDebug() << "Maki AES: Failed to get Key IV pair";
        return data;
	}
    memcpy(key, keyivpair, iklen);                                              
  	memcpy(iv, keyivpair + iklen, ivlen);
    free(keyivpair);

    // qDebug() << "Maki AES: Salt" << salt.toHex();
    // qDebug() << "Maki AES: Key " << QByteArray((char*)key, EVP_MAX_KEY_LENGTH).toHex();
    // qDebug() << "Maki AES: IV  " << QByteArray((char*)iv, EVP_MAX_IV_LENGTH).toHex();

    int len;
    EVP_CIPHER_CTX *ctx;   
	if (!(ctx = EVP_CIPHER_CTX_new())) {
		// qDebug() << "Maki AES: Failed to init ctx";
        return data;
	}
    // qDebug() << "Maki AES: Initialized ctx";
    if (!EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) {
		// qDebug() << "Maki AES: Failed to init decrypt";
        return data;
	}
    // qDebug() << "Maki AES: Initialized decrypt";
    if (!EVP_DecryptUpdate(ctx,
        plaindata, &len,
        (unsigned char*)cipherdata.constData(), cipherdata.length()
    )) {
		// qDebug() << "Maki AES: Failed to update decrypt";
        return data;
	}
    // qDebug() << "Maki AES: Updated decrypt";
    plaindata_len = len;
    if(!EVP_DecryptFinal_ex(ctx,
        plaindata + len, &len)
    ) {
		// qDebug() << "Maki AES: Failed to finalize decrypt";
        return data;
	}
    // qDebug() << "Maki AES: Finalized decrypt";
    plaindata_len += len;
    EVP_CIPHER_CTX_free(ctx);

    // qDebug() << "Maki AES: Plain data length" << plaindata_len;

    data = QByteArray(reinterpret_cast<char*>(plaindata), plaindata_len);
    free(plaindata);
    return data;
}

void TeaResourceRequest::doSend() {
    watcher = new QFutureWatcher<void>(this);
    connect(watcher, &QFutureWatcherBase::finished, this, [=](){
        if (data.second > 0) {
            _data = QByteArray(data.first, data.second);
            free(data.first);
        }
        emit finished();
    }, Qt::QueuedConnection);
    
    QFuture<void> future = QtConcurrent::run(this, &TeaResourceRequest::send);
    watcher->setFuture(future);
}

void TeaResourceRequest::send() {
    auto statTracker = DependencyManager::get<StatTracker>();
    statTracker->incrementStat(STAT_TEA_REQUEST_STARTED);

    QUrl url = QUrl(_url);
    url.setQuery(QUrlQuery());
    QString path = url.toString().replace(URL_SCHEME_TEA + "://", "");

    QTcpSocket socket;
    socket.connectToHost("tivolicloud.com", 17486, QIODevice::ReadWrite);

    QByteArray decryptedData;

    // qCDebug(tea) << "Requesting" << path;

    if (!socket.waitForConnected(10000)) {
        qCDebug(tea) << "Connection timed out" << path;
        _result = Timeout;
    } else {
        auto accountManager = DependencyManager::get<AccountManager>();
        QString accessToken = accountManager->getAccountInfo().getAccessToken().token;

        unsigned char random[8];
        RAND_bytes(random, 8);

        QVariantMap request;
        request["accessToken"] = accessToken;
        request["path"] = path;
        request["random"] = QByteArray(reinterpret_cast<char*>(random), 8).toHex();

        QByteArray requestStr = QJsonDocument::fromVariant(request).toJson(
            QJsonDocument::JsonFormat::Compact
        );
        QByteArray encryptedRequest = encrypt(requestStr, "");

        socket.write(encryptedRequest);

        QByteArray receivedData;

        if (socket.waitForBytesWritten(5000)) {
            // waiting for server to fetch file, encrypt and start sending
            
            // socket.waitForReadyRead(10000);
            socket.waitForDisconnected(-1);

            receivedData = socket.readAll();
        }

        socket.close();

        if (!receivedData.isEmpty()) {
            decryptedData = decrypt(receivedData, path);

            if (decryptedData.isEmpty()) {
                qCDebug(tea) << "Failed to decrypt" << path;
                _result = Error;
            } else {
                _result = Success;
            }
        } else {
            qCDebug(tea) << "Not found" << path;
            _result = NotFound;
        }
    }

    _state = Finished;

    recordBytesDownloadedInStats(STAT_TEA_RESOURCE_TOTAL_BYTES, decryptedData.size());

    if (_result == Success) {
        statTracker->incrementStat(STAT_TEA_REQUEST_FAILED);
        if (loadedFromCache()) {
            statTracker->incrementStat(STAT_TEA_REQUEST_CACHE);
        }
    } else {
        statTracker->incrementStat(STAT_TEA_REQUEST_SUCCESS);
    }

    // qCDebug(tea) << "Received" << path << decryptedData.length();

    data.first = (char*)malloc(decryptedData.size());

    if (data.first == 0) {
        qCDebug(tea) << "No memory to allocate" << path << decryptedData.length();
        data.second = 0;
    } else {
        data.second = decryptedData.length();
        memcpy(data.first, decryptedData.data(), decryptedData.length());
    }
}