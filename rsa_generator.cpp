#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <vector>
#include <string>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
// Функция для преобразования байтов в 16-ричную строку
std::string bytesToHex(const std::vector<unsigned char>& data) {
    std::ostringstream hexStream;
    for (unsigned char byte : data) {
        hexStream << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    return hexStream.str();
}

// Функция для преобразования 16-ричной строки в байты
std::vector<unsigned char> hexToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = (unsigned char) strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

// Функция для шифрования приватного ключа с использованием AES
std::string encryptPrivateKeyWithAES(const std::string& privateKey, const std::string& keyHex, const std::string& ivHex) {
    // Преобразуем ключ и IV из 16-ричного формата в байты
    std::vector<unsigned char> key = hexToBytes(keyHex);
    std::vector<unsigned char> iv = hexToBytes(ivHex);

    // Создаем контекст для шифрования
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Ошибка создания контекста шифрования." << std::endl;
        return "";
    }

    // Инициализируем шифрование
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()) != 1) {
        std::cerr << "Ошибка инициализации шифрования." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    // Шифруем приватный ключ
    std::vector<unsigned char> encryptedKey(privateKey.size() + EVP_MAX_BLOCK_LENGTH);
    int encryptedLen = 0;
    if (EVP_EncryptUpdate(ctx, encryptedKey.data(), &encryptedLen, (const unsigned char*)privateKey.data(), privateKey.size()) != 1) {
        std::cerr << "Ошибка шифрования." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    int finalLen = 0;
    if (EVP_EncryptFinal_ex(ctx, encryptedKey.data() + encryptedLen, &finalLen) != 1) {
        std::cerr << "Ошибка завершения шифрования." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    encryptedLen += finalLen;
    encryptedKey.resize(encryptedLen);

    EVP_CIPHER_CTX_free(ctx);

    // Преобразуем зашифрованный ключ в 16-ричный формат
    return bytesToHex(encryptedKey);
}

// Функция для сохранения зашифрованного приватного ключа
void saveEncryptedPrivateKey(const std::string& encryptedPrivateKey, const std::string& filePath) {
    std::ofstream file(filePath);
    if (!file) {
        std::cerr << "Не удалось открыть файл для записи." << std::endl;
        return;
    }
    file << encryptedPrivateKey;
    if (!file) {
        std::cerr << "Ошибка записи в файл." << std::endl;
        return;
    }
    file.close();

    std::cout << "Encrypted private key saved to file: " << filePath << std::endl;
}

void generateRSAKeys(const std::string& entropyData, const std::string& publicKeyFilename, const std::string& privateKeyFilename) {
    if (entropyData.empty()) {
        std::cerr << "Ошибка: недостаточно энтропии." << std::endl;
        return;
    }

    RAND_add(entropyData.data(), entropyData.size(), entropyData.size() * 0.5);

    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();

    // Use a fixed public exponent (65537)
    if (BN_set_word(bn, RSA_F4) != 1) {
        std::cerr << "Ошибка установки публичного экспонента." << std::endl;
        BN_free(bn);
        return;
    }

    // Generate RSA keys
    if (RSA_generate_key_ex(rsa, 2048, bn, NULL) != 1) {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        std::cerr << "Ошибка генерации ключей: " << err_buf << std::endl;
        BN_free(bn);
        RSA_free(rsa);
        return;
    }

    // Save public key
    BIO *pub = BIO_new_file(publicKeyFilename.c_str(), "w");
    if (!PEM_write_bio_RSAPublicKey(pub, rsa)) {
        std::cerr << "Ошибка записи публичного ключа." << std::endl;
    }
    BIO_free_all(pub);

    // Save private key
    BIO *priv = BIO_new_file(privateKeyFilename.c_str(), "w");
    if (!PEM_write_bio_RSAPrivateKey(priv, rsa, NULL, NULL, 0, NULL, NULL)) {
        std::cerr << "Ошибка записи приватного ключа." << std::endl;
    }
    BIO_free_all(priv);

    BN_free(bn);
    RSA_free(rsa);
}

std::vector<unsigned char> rsaEncryptFile(const std::vector<unsigned char>& message, const std::string& publicKeyFilename) {
    FILE *fp = fopen(publicKeyFilename.c_str(), "r");
    if (fp == NULL) {
        std::cerr << "Ошибка открытия публичного ключа: " << publicKeyFilename << std::endl;
        return {};
    }

    RSA *rsa = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (rsa == NULL) {
        std::cerr << "Ошибка чтения публичного ключа" << std::endl;
        ERR_print_errors_fp(stderr);
        return {};
    }

    int blockSize = RSA_size(rsa) - 11; // Максимальный размер блока для шифрования
    std::vector<unsigned char> encryptedData;

    for (size_t i = 0; i < message.size(); i += blockSize) {
        size_t chunkSize = std::min(static_cast<size_t>(blockSize), message.size() - i);
        std::vector<unsigned char> chunk(message.begin() + i, message.begin() + i + chunkSize);

        std::vector<unsigned char> encryptedChunk(RSA_size(rsa));
        int encryptedLength = RSA_public_encrypt(chunk.size(), chunk.data(), encryptedChunk.data(), rsa, RSA_PKCS1_PADDING);
        if (encryptedLength == -1) {
            std::cerr << "Ошибка шифрования RSA" << std::endl;
            ERR_print_errors_fp(stderr);
            RSA_free(rsa);
            return {};
        }

        encryptedData.insert(encryptedData.end(), encryptedChunk.begin(), encryptedChunk.begin() + encryptedLength);
    }

    RSA_free(rsa);
    return encryptedData;
}

std::vector<unsigned char> rsaDecryptFile(const std::vector<unsigned char>& encryptedData, const std::string& privateKeyFilename) {
    FILE *fp = fopen(privateKeyFilename.c_str(), "r");
    if (fp == NULL) {
        std::cerr << "Ошибка открытия приватного ключа: " << privateKeyFilename << std::endl;
        return {};
    }

    RSA *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (rsa == NULL) {
        std::cerr << "Ошибка чтения приватного ключа" << std::endl;
        ERR_print_errors_fp(stderr);
        return {};
    }

    int blockSize = RSA_size(rsa);
    std::vector<unsigned char> decryptedData;

    for (size_t i = 0; i < encryptedData.size(); i += blockSize) {
        std::vector<unsigned char> encryptedChunk(encryptedData.begin() + i, encryptedData.begin() + i + blockSize);

        std::vector<unsigned char> decryptedChunk(RSA_size(rsa));
        int decryptedLength = RSA_private_decrypt(encryptedChunk.size(), encryptedChunk.data(), decryptedChunk.data(), rsa, RSA_PKCS1_PADDING);
        if (decryptedLength == -1) {
            std::cerr << "Ошибка расшифровки RSA" << std::endl;
            ERR_print_errors_fp(stderr);
            RSA_free(rsa);
            return {};
        }

        decryptedData.insert(decryptedData.end(), decryptedChunk.begin(), decryptedChunk.begin() + decryptedLength);
    }

    RSA_free(rsa);
    return decryptedData;
}