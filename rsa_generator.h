#ifndef RSA_GENERATOR_H
#define RSA_GENERATOR_H

#include <string>
#include <vector>

void generateRSAKeys(const std::string& entropyData, const std::string& filename);
std::vector<unsigned char> rsaEncryptBinary(const std::string& message, const std::string& publicKeyFilename);
std::string rsaDecryptBinary(const std::vector<unsigned char>& encryptedData, const std::string& privateKeyFilename);

#endif // RSA_GENERATOR_H