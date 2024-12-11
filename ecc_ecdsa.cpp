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

// Функция для шифрования данных с использованием AES
std::string encryptWithAES(const std::string& data, const std::string& keyHex, const std::string& ivHex) {
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

    // Шифруем данные
    std::vector<unsigned char> encryptedData(data.size() + EVP_MAX_BLOCK_LENGTH);
    int encryptedLen = 0;
    if (EVP_EncryptUpdate(ctx, encryptedData.data(), &encryptedLen, (const unsigned char*)data.data(), data.size()) != 1) {
        std::cerr << "Ошибка шифрования." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    int finalLen = 0;
    if (EVP_EncryptFinal_ex(ctx, encryptedData.data() + encryptedLen, &finalLen) != 1) {
        std::cerr << "Ошибка завершения шифрования." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    encryptedLen += finalLen;
    encryptedData.resize(encryptedLen);

    EVP_CIPHER_CTX_free(ctx);

    // Преобразуем зашифрованные данные в 16-ричный формат
    return bytesToHex(encryptedData);
}

// Функция для сохранения зашифрованных данных в файл
void saveEncryptedData(const std::string& encryptedData, const std::string& filePath) {
    std::ofstream file(filePath);
    if (!file) {
        std::cerr << "Не удалось открыть файл для записи." << std::endl;
        return;
    }
    file << encryptedData;
    if (!file) {
        std::cerr << "Ошибка записи в файл." << std::endl;
        return;
    }
    file.close();

    std::cout << "Encrypted data saved to file: " << filePath << std::endl;
}
void generateECDSAKeys(const std::string& entropyData, const std::string& privateKeyFile, const std::string& publicKeyFile, const std::string& keyHex, const std::string& ivHex) {
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); // Используем стандартную кривую P-256
    if (!key) {
        std::cerr << "Ошибка создания ключей ECDSA" << std::endl;
        return;
    }

    // Добавляем собранную энтропию в генератор случайных чисел
    RAND_load_file("/dev/urandom", 32); // Загружаем 32 байта энтропии из /dev/urandom
    RAND_poll(); // Дополнительно инициализируем генератор случайных чисел

    if (!EC_KEY_generate_key(key)) {
        std::cerr << "Ошибка генерации ключей ECDSA" << std::endl;
        EC_KEY_free(key);
        return;
    }

    // Сохранение публичного ключа
    FILE* publicKeyFp = fopen(publicKeyFile.c_str(), "wb");
    if (!publicKeyFp || !PEM_write_EC_PUBKEY(publicKeyFp, key)) {
        std::cerr << "Ошибка сохранения публичного ключа ECDSA" << std::endl;
        if (publicKeyFp) fclose(publicKeyFp);
        EC_KEY_free(key);
        return;
    }
    fclose(publicKeyFp);

    // Чтение приватного ключа в виде строки
    BIO* bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_ECPrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr)) {
        std::cerr << "Ошибка чтения приватного ключа ECDSA" << std::endl;
        BIO_free(bio);
        EC_KEY_free(key);
        return;
    }

    BUF_MEM* bptr;
    BIO_get_mem_ptr(bio, &bptr);
    std::string privateKey(bptr->data, bptr->length);
    BIO_free(bio);

    // Шифрование приватного ключа
    std::string encryptedPrivateKey = encryptWithAES(privateKey, keyHex, ivHex);
    if (encryptedPrivateKey.empty()) {
        std::cerr << "Ошибка шифрования приватного ключа ECDSA" << std::endl;
        EC_KEY_free(key);
        return;
    }

    // Сохранение зашифрованного приватного ключа
    saveEncryptedData(encryptedPrivateKey, privateKeyFile);

    EC_KEY_free(key);
    std::cout << "Ключи ECDSA успешно сгенерированы и приватный ключ зашифрован!" << std::endl;
}
std::vector<unsigned char> signFile(const std::string& filename, const std::string& privateKeyFile) {
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

    // Чтение содержимого файла
    std::ifstream fileIn(filename, std::ios::binary);
    if (!fileIn) {
        std::cerr << "Ошибка открытия файла для подписи: " << filename << std::endl;
        EC_KEY_free(key);
        return {};
    }

    std::vector<unsigned char> fileData((std::istreambuf_iterator<char>(fileIn)), std::istreambuf_iterator<char>());

    // Хэширование содержимого файла
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(fileData.data(), fileData.size(), hash);

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

bool verifyFileSignature(const std::string& filename, const std::vector<unsigned char>& signature, const std::string& publicKeyFile) {
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

    // Чтение содержимого файла
    std::ifstream fileIn(filename, std::ios::binary);
    if (!fileIn) {
        std::cerr << "Ошибка открытия файла для проверки подписи: " << filename << std::endl;
        EC_KEY_free(key);
        return false;
    }

    std::vector<unsigned char> fileData((std::istreambuf_iterator<char>(fileIn)), std::istreambuf_iterator<char>());

    // Хэширование содержимого файла
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(fileData.data(), fileData.size(), hash);

    // Проверка подписи
    bool isValid = ECDSA_verify(0, hash, SHA256_DIGEST_LENGTH, signature.data(), signature.size(), key) == 1;
    EC_KEY_free(key);
    return isValid;
}