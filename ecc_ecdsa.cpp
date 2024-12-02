#include "ecc_ecdsa.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <iostream>

void generateECDSAKeys(const std::string& privateKeyFile, const std::string& publicKeyFile) {
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); // Используем стандартную кривую P-256
    if (!key) {
        std::cerr << "Ошибка создания ключей ECDSA" << std::endl;
        return;
    }

    if (!EC_KEY_generate_key(key)) {
        std::cerr << "Ошибка генерации ключей ECDSA" << std::endl;
        EC_KEY_free(key);
        return;
    }

    // Сохранение приватного ключа
    FILE* privateKeyFp = fopen(privateKeyFile.c_str(), "wb");
    if (!privateKeyFp || !PEM_write_ECPrivateKey(privateKeyFp, key, nullptr, nullptr, 0, nullptr, nullptr)) {
        std::cerr << "Ошибка сохранения приватного ключа ECDSA" << std::endl;
        if (privateKeyFp) fclose(privateKeyFp);
        EC_KEY_free(key);
        return;
    }
    fclose(privateKeyFp);

    // Сохранение публичного ключа
    FILE* publicKeyFp = fopen(publicKeyFile.c_str(), "wb");
    if (!publicKeyFp || !PEM_write_EC_PUBKEY(publicKeyFp, key)) {
        std::cerr << "Ошибка сохранения публичного ключа ECDSA" << std::endl;
        if (publicKeyFp) fclose(publicKeyFp);
        EC_KEY_free(key);
        return;
    }
    fclose(publicKeyFp);

    EC_KEY_free(key);
    std::cout << "Ключи ECDSA успешно сгенерированы!" << std::endl;
}

std::vector<unsigned char> signMessage(const std::string& message, const std::string& privateKeyFile) {
    // Чтение приватного ключа
    FILE* privateKeyFp = fopen(privateKeyFile.c_str(), "rb");
    if (!privateKeyFp) {
        std::cerr << "Ошибка открытия приватного ключа ECDSA" << std::endl;
        return {};
    }
    EC_KEY* key = PEM_read_ECPrivateKey(privateKeyFp, nullptr, nullptr, nullptr);
    fclose(privateKeyFp);

    if (!key) {
        std::cerr << "Ошибка чтения приватного ключа ECDSA" << std::endl;
        return {};
    }

    // Хэширование сообщения
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(message.c_str()), message.size(), hash);

    // Создание подписи
    unsigned int sigLen;
    std::vector<unsigned char> signature(ECDSA_size(key));
    if (!ECDSA_sign(0, hash, SHA256_DIGEST_LENGTH, signature.data(), &sigLen, key)) {
        std::cerr << "Ошибка создания подписи" << std::endl;
        EC_KEY_free(key);
        return {};
    }
    signature.resize(sigLen);
    EC_KEY_free(key);
    return signature;
}

bool verifySignature(const std::string& message, const std::vector<unsigned char>& signature, const std::string& publicKeyFile) {
    // Чтение публичного ключа
    FILE* publicKeyFp = fopen(publicKeyFile.c_str(), "rb");
    if (!publicKeyFp) {
        std::cerr << "Ошибка открытия публичного ключа ECDSA" << std::endl;
        return false;
    }
    EC_KEY* key = PEM_read_EC_PUBKEY(publicKeyFp, nullptr, nullptr, nullptr);
    fclose(publicKeyFp);

    if (!key) {
        std::cerr << "Ошибка чтения публичного ключа ECDSA" << std::endl;
        return false;
    }

    // Хэширование сообщения
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(message.c_str()), message.size(), hash);

    // Проверка подписи
    bool isValid = ECDSA_verify(0, hash, SHA256_DIGEST_LENGTH, signature.data(), signature.size(), key) == 1;
    EC_KEY_free(key);
    return isValid;
}
