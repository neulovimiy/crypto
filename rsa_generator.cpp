#include "rsa_generator.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstring>

void generateRSAKeys(const std::string& entropyData, const std::string& filename) {
    if (entropyData.empty()) {
        std::cerr << "Ошибка: недостаточно энтропии." << std::endl;
        return;
    }

    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();

    // Используем первые символы entropyData для инициализации BIGNUM
    std::string seed(entropyData.begin(), entropyData.begin() + std::min(entropyData.size(), size_t(8)));
    BN_bin2bn(reinterpret_cast<const unsigned char*>(seed.data()), seed.size(), bn);

    if (RSA_generate_key_ex(rsa, 2048, bn, NULL) != 1) {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        std::cerr << "Ошибка генерации ключей: " << err_buf << std::endl;
        BN_free(bn);
        RSA_free(rsa);
        return;
    }

    // Сохранение публичного ключа в файл
    BIO *pub = BIO_new_file((filename + "_pub.pem").c_str(), "w");
    PEM_write_bio_RSAPublicKey(pub, rsa);
    BIO_free_all(pub);

    // Сохранение приватного ключа в файл
    BIO *priv = BIO_new_file((filename + "_priv.pem").c_str(), "w");
    PEM_write_bio_RSAPrivateKey(priv, rsa, NULL, NULL, 0, NULL, NULL);
    BIO_free_all(priv);

    BN_free(bn);
    RSA_free(rsa);
}

std::vector<unsigned char> rsaEncryptBinary(const std::string& message, const std::string& publicKeyFilename) {
    FILE *fp = fopen(publicKeyFilename.c_str(), "r");
    if (fp == NULL) {
        std::cerr << "Ошибка открытия публичного ключа: " << publicKeyFilename << std::endl;
        return {};
    }

    RSA *rsa = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (rsa == NULL) {
        std::cerr << "Ошибка чтения публичного ключа" << std::endl;
        return {};
    }

    int messageLength = message.length();
    std::vector<unsigned char> encryptedData(RSA_size(rsa));
    int encryptedLength = RSA_public_encrypt(messageLength, (unsigned char*)message.c_str(), encryptedData.data(), rsa, RSA_PKCS1_PADDING);
    if (encryptedLength == -1) {
        std::cerr << "Ошибка шифрования RSA" << std::endl;
        RSA_free(rsa);
        return {};
    }

    RSA_free(rsa);
    encryptedData.resize(encryptedLength);
    return encryptedData;
}

std::string rsaDecryptBinary(const std::vector<unsigned char>& encryptedData, const std::string& privateKeyFilename) {
    FILE *fp = fopen(privateKeyFilename.c_str(), "r");
    if (fp == NULL) {
        std::cerr << "Ошибка открытия приватного ключа: " << privateKeyFilename << std::endl;
        return "";
    }

    RSA *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (rsa == NULL) {
        std::cerr << "Ошибка чтения приватного ключа" << std::endl;
        ERR_print_errors_fp(stderr);
        return "";
    }

    size_t encryptedLength = encryptedData.size();
    if (encryptedLength > (size_t)RSA_size(rsa)) {
        std::cerr << "Ошибка: данные для расшифровки слишком большие для ключа RSA." << std::endl;
        RSA_free(rsa);
        return "";
    }

    std::vector<unsigned char> decryptedData(RSA_size(rsa));

    int decryptedLength = RSA_private_decrypt(encryptedLength, encryptedData.data(), decryptedData.data(), rsa, RSA_PKCS1_PADDING);

    if (decryptedLength == -1) {
        std::cerr << "Ошибка расшифровки RSA" << std::endl;
        ERR_print_errors_fp(stderr);
        RSA_free(rsa);
        return "";
    }

    std::string decryptedMessage((char*)decryptedData.data(), decryptedLength);
    RSA_free(rsa);
    return decryptedMessage;
}