#ifndef ECC_ECDSA_H
#define ECC_ECDSA_H

#include <string>
#include <vector>

// Генерация ключей ECDSA
void generateECDSAKeys(const std::string& privateKeyFile, const std::string& publicKeyFile);

// Генерация подписи с использованием приватного ключа ECDSA
std::vector<unsigned char> signMessage(const std::string& message, const std::string& privateKeyFile);

// Проверка подписи с использованием публичного ключа ECDSA
bool verifySignature(const std::string& message, const std::vector<unsigned char>& signature, const std::string& publicKeyFile);

#endif // ECC_ECDSA_H
