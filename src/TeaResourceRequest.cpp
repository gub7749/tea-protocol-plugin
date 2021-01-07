#include "TeaResourceRequest.h"

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/ossl_typ.h>
#include <openssl/rand.h>

#include <QJsonDocument>
#include <QLoggingCategory>
#include <QNetworkRequest>

#include <SharedUtil.h>
#include <StatTracker.h>
#include <AccountManager.h>
#include <NetworkAccessManager.h>
#include <NetworkLogging.h>
#include <NetworkingConstants.h>
#include <ResourceRequest.h>
#include <ResourceManager.h>
#include <Gzip.h>
#include <Brotli.h>

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
        return QByteArray();
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
        return QByteArray();
	}
    // qDebug() << "Maki AES: Initialized ctx";
    if (!EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv)) {
		// qDebug() << "Maki AES: Failed to init encrypt";
        return QByteArray();
	}
    // qDebug() << "Maki AES: Initialized encrypt";
    if (!EVP_EncryptUpdate(ctx,
        cipherdata, &len,
        (unsigned char*)plaindata.constData(), plaindata.length()
    )) {
		// qDebug() << "Maki AES: Failed to update encrypt";
        return QByteArray();
	}
    // qDebug() << "Maki AES: Updated encrypt";
    cipherdata_len = len;
    if(!EVP_EncryptFinal_ex(ctx,
        cipherdata + len, &len)
    ) {
		// qDebug() << "Maki AES: Failed to finalize encrypt";
        return QByteArray();
	}
    // qDebug() << "Maki AES: Finalized encrypt";
    cipherdata_len += len;
    EVP_CIPHER_CTX_free(ctx);

    // qDebug() << "Maki AES: Cipher data length" << cipherdata_len;

    QByteArray header = QByteArray(reinterpret_cast<char*>(salt), 8);
    header.prepend(QString("Salted__").toLocal8Bit());

    QByteArray data = QByteArray(reinterpret_cast<char*>(cipherdata), cipherdata_len);
    data.prepend(header);
    free(cipherdata);

    return data;
}

QByteArray decrypt(QByteArray cipherdata, QString seed) {
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
        return QByteArray();
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
        return QByteArray();
	}
    // qDebug() << "Maki AES: Initialized ctx";
    if (!EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) {
		// qDebug() << "Maki AES: Failed to init decrypt";
        return QByteArray();
	}
    // qDebug() << "Maki AES: Initialized decrypt";
    if (!EVP_DecryptUpdate(ctx,
        plaindata, &len,
        (unsigned char*)cipherdata.constData(), cipherdata.length()
    )) {
		// qDebug() << "Maki AES: Failed to update decrypt";
        return QByteArray();
	}
    // qDebug() << "Maki AES: Updated decrypt";
    plaindata_len = len;
    if(!EVP_DecryptFinal_ex(ctx,
        plaindata + len, &len)
    ) {
		// qDebug() << "Maki AES: Failed to finalize decrypt";
        return QByteArray();
	}
    // qDebug() << "Maki AES: Finalized decrypt";
    plaindata_len += len;
    EVP_CIPHER_CTX_free(ctx);

    // qDebug() << "Maki AES: Plain data length" << plaindata_len;

    QByteArray data = QByteArray(reinterpret_cast<char*>(plaindata), plaindata_len);
    free(plaindata);
    return data;
}

void TeaResourceRequest::setupTimeout() {
    static const int TIMEOUT_MS = 10000; // 10 seconds

    timeout = new QTimer();
    connect(this, &QObject::destroyed, timeout, &QTimer::deleteLater);
    connect(timeout, &QTimer::timeout, this, &TeaResourceRequest::onTimeout);

    timeout->setSingleShot(true);
    timeout->start(TIMEOUT_MS);
}

void TeaResourceRequest::cleanupTimeout() {
    timeout->disconnect(this);
    timeout->deleteLater();
    timeout = nullptr;
}

void TeaResourceRequest::doSend() {
    DependencyManager::get<StatTracker>()->incrementStat(STAT_TEA_REQUEST_STARTED);

    QUrl url = QUrl(_url);
    url.setQuery(QUrlQuery());
    path = url.toString().replace(URL_SCHEME_TEA + "://", "");
    if (path.startsWith("/")) path = path.mid(1);

    // qCDebug(tea) << "Requesting" << path;

    #define TEA_URL "https://tea.tivolicloud.com"
    // #define TEA_URL "http://tea.localhost:3000"
    QUrl networkRequestUrl = QUrl(TEA_URL);
    networkRequestUrl.setPath("/" + hash("itsteatime" + path, QCryptographicHash::Algorithm::Sha224));
    if (networkRequestUrl.isEmpty()) networkRequestUrl = QUrl(TEA_URL);

    QNetworkRequest networkRequest(networkRequestUrl);
    networkRequest.setHeader(QNetworkRequest::UserAgentHeader, TIVOLI_CLOUD_VR_USER_AGENT);
    networkRequest.setAttribute(QNetworkRequest::FollowRedirectsAttribute, false);
    networkRequest.setHeader(QNetworkRequest::ContentTypeHeader, "application/octet-stream");

    // when overriding Accept-Encoding, qt disables auto decompress
    networkRequest.setRawHeader("Accept-Encoding", "gzip, br");

    // make request body

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

    // networkRequest.setHeader(QNetworkRequest::ContentLengthHeader, encryptedRequest.length());
    networkRequest.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::PreferNetwork);
    networkRequest.setRawHeader(QString("X-Tea-Request").toLocal8Bit(), encryptedRequest.toBase64());

    // get request

    reply =  NetworkAccessManager::getInstance().get(networkRequest);

    connect(reply, &QNetworkReply::finished, this, &TeaResourceRequest::onRequestFinished);
    connect(reply, &QNetworkReply::downloadProgress, this, &TeaResourceRequest::onDownloadProgress);

    setupTimeout();
}

void TeaResourceRequest::onTimeout() {
    qCDebug(tea) << "Connection timed out" << path;

    reply->disconnect(this);
    reply->abort();
    reply->deleteLater();
    reply = nullptr;

    cleanupTimeout();
    
    _result = Timeout;
    _state = Finished;
    emit finished();

    DependencyManager::get<StatTracker>()->incrementStat(STAT_TEA_REQUEST_FAILED);
}

void TeaResourceRequest::onDownloadProgress(qint64 bytesReceived, qint64 bytesTotal) {
    // we've received data so reset the timer
    timeout->start();

    // qCDebug(tea) << "Download progress" << bytesReceived << "/" << bytesTotal;
    emit progress(bytesReceived, bytesTotal);
    recordBytesDownloadedInStats(STAT_TEA_RESOURCE_TOTAL_BYTES, bytesReceived);
}

void TeaResourceRequest::onRequestFinished() {
    cleanupTimeout();

    if (reply->error() == QNetworkReply::NoError) {
        QByteArray receivedData = reply->readAll();

        _loadedFromCache = reply->attribute(QNetworkRequest::SourceIsFromCacheAttribute).toBool();

        // qCDebug(tea) << "Received" << path << "from cache" << _loadedFromCache;

        if (!receivedData.isEmpty()) {
            _data = decrypt(receivedData, path);

            if (_data.isEmpty()) {
                qCDebug(tea) << "Failed to decrypt" << path;
                _result = Error;
            } else {
                _result = Success;

                _webMediaType = reply->header(QNetworkRequest::ContentTypeHeader)
                    .toString().split(";").first();

                auto contentEncoding = reply->rawHeader("Content-Encoding");                
                if (contentEncoding.size() > 0) {
                    QByteArray decompressedData;
                    if (contentEncoding.compare("gzip", Qt::CaseInsensitive) == 0) {
                        if (gunzip(_data, decompressedData)) {
                            _data = decompressedData;
                        } else {
                            qCDebug(tea) << "Failed to decompress gzip for: " << _url;
                            _result = Error;
                        }
                    } else if (contentEncoding.compare("br", Qt::CaseInsensitive) == 0) {
                        if (brotliDecompress(_data, decompressedData)) {
                            _data = decompressedData;
                        } else {
                            qCDebug(tea) << "Failed to decompress brotli for: " << _url;
                            _result = Error;
                        }
                    } else {
                        qCDebug(tea) << "Unknown content-encoding: " << contentEncoding;
                        _result = Error;
                    }
                }
            }
        } else {
            qCDebug(tea) << "No data received" << path 
                << reply->attribute(QNetworkRequest::HttpStatusCodeAttribute)
                << reply->attribute(QNetworkRequest::HttpReasonPhraseAttribute);
            _result = NotFound;
        }
    } else {
        switch (reply->error()) {
            case QNetworkReply::TimeoutError:
            case QNetworkReply::OperationCanceledError:
                qCDebug(tea) << "Connection timed out" << path;
                _result = Timeout;
                break;

            case QNetworkReply::ContentNotFoundError:
                qCDebug(tea) << "Not found" << path;
                _result = NotFound;
                break;

            default:
                qCDebug(tea) << "Error" << path << reply->error();
                _result = Error;
                break;
        }
    }

    reply->disconnect(this);
    reply->deleteLater();
    reply = nullptr;

    _totalSizeOfResource = _data.length();
    recordBytesDownloadedInStats(STAT_TEA_RESOURCE_TOTAL_BYTES, _data.length());

    _state = Finished;
    emit finished();

    auto statTracker = DependencyManager::get<StatTracker>();
    if (_result == Success) {
        statTracker->incrementStat(STAT_TEA_REQUEST_FAILED);
        if (_loadedFromCache) {
            statTracker->incrementStat(STAT_TEA_REQUEST_CACHE);
        }
    } else {
        statTracker->incrementStat(STAT_TEA_REQUEST_SUCCESS);
    }
}
