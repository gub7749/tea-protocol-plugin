#include "TeaResourceRequest.h"

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/ossl_typ.h>
#include <openssl/rand.h>

#include <QFile>
#include <QJsonDocument>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QMetaEnum>
#include <QTcpSocket>

#include <SharedUtil.h>
#include <StatTracker.h>
#include <AccountManager.h>
#include <NetworkAccessManager.h>
#include <NetworkLogging.h>
#include <NetworkingConstants.h>
#include <ResourceRequest.h>

#include "TeaProtocolPlugin.h"

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

    unsigned char cipherdata[plaindata.length() + 128]; // requires a little extra
    int cipherdata_len;

    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
	int iklen = EVP_CIPHER_key_length(cipher);
	int ivlen = EVP_CIPHER_iv_length(cipher);
	int iter = 10000; // default in openssl 1.1.1
	unsigned char keyivpair[iklen + ivlen];

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

    return data;
}

QByteArray decrypt(QByteArray cipherdata, QString seed) {
    QByteArray data;

    QByteArray salt = cipherdata.mid(8, 8);
    cipherdata.remove(0, 16); // Salted__xxxxxxxx

    // qDebug() << "Maki AES: Cipher data length" << cipherdata.length();

    unsigned char plaindata[cipherdata.length()];
    int plaindata_len;

    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
	int iklen = EVP_CIPHER_key_length(cipher);
	int ivlen = EVP_CIPHER_iv_length(cipher);
	int iter = 10000; // default in openssl 1.1.1
	unsigned char keyivpair[iklen + ivlen];

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
    return data;
}

QByteArray getFile(QString path) {
    QByteArray data;

    QTcpSocket socket;
    socket.connectToHost("127.0.0.1", 17486, QIODevice::ReadWrite);
    // qDebug() << "Maki AES: connecting";

    if (!socket.waitForConnected(10000)) {
        // qDebug() << "Maki AES: connected failed";
        // _result = Timeout;
    } else {
        // qDebug() << "Maki AES: connected";

        auto accountManager = DependencyManager::get<AccountManager>();
        QString accessToken = accountManager->getAccountInfo().getAccessToken().token;

        // qDebug() << "Maki AES: path"<<path;

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
        // qDebug() << "Maki AES: encryptedRequest"<<encryptedRequest;
        // qDebug() << "Maki AES: encryptedRequest"<<QString(encryptedRequest);

        socket.write(encryptedRequest);
        // qDebug() << "Maki AES: sending request";

        QByteArray receivedData;

        if (socket.waitForBytesWritten(5000)) {
            // qDebug() << "Maki AES: bytes written!";

            // waiting for server to fetch file, encrypt and start sending
            socket.waitForReadyRead(10000);

            while (socket.waitForReadyRead(100) || socket.bytesAvailable() > 0) {
                // qDebug() << "Maki AES: receiving...";
                receivedData.append(socket.readAll());
                socket.flush();
            }

        } else {
            // qDebug() << "Maki AES: failed, no bytes written";
            // _result = Timeout;
        }

        if (!receivedData.isEmpty()) {
            // do stuff

            data = decrypt(receivedData, path);
            if (data.isEmpty()) {
                // _result = Error;
            } else {
                // _result = Success;
            }

            // _result = Success;
        } else {
            // _result = Error;
        }
        
        // qDebug() << "Maki AES: received data length"<<receivedData.length();
    }

    socket.close();

    // _state = Finished;

    return data;
}

void TeaResourceRequest::doSend() {
    auto statTracker = DependencyManager::get<StatTracker>();
    statTracker->incrementStat(STAT_TEA_REQUEST_STARTED);

    QUrl url = QUrl(_url);
    url.setQuery(QUrlQuery());
    QString path = url.toString().replace(URL_SCHEME_TEA + "://", "");

    _data = getFile(path);

    if (_data.isEmpty()) {
        _result = Error;
    } else {
        _result = Success;
    }

    _state = Finished;

    recordBytesDownloadedInStats(STAT_TEA_RESOURCE_TOTAL_BYTES, _data.size());

     if (_result == Success) {
        statTracker->incrementStat(STAT_TEA_REQUEST_FAILED);
        if (loadedFromCache()) {
            statTracker->incrementStat(STAT_TEA_REQUEST_CACHE);
        }
    } else {
        statTracker->incrementStat(STAT_TEA_REQUEST_SUCCESS);
    }

    emit finished();
}