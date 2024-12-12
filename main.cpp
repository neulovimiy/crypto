#include <iostream>
#include <fstream>
#include <windows.h>
#include <vector>
#include <ctime>
#include <string>
#include <chrono>
#include <thread>
#include <openssl/crypto.h>
#include "rsa_generator.h"
#include "aes_generator.h"
#include "ecc_ecdsa.h"
#include <openssl/evp.h>
#include <limits>
#include <iomanip>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <sstream>
#include "resource.h"
#pragma comment(lib, "advapi32.lib")
#define IDC_EDIT_MESSAGE 101
#define IDC_BUTTON_OK 102
#define IDC_EDIT_PASSWORD 103
#define IDC_BUTTON_DECRYPTION_PRIV_KEY 10
std::string messageN;

// Функция для преобразования строки UTF-8 в UTF-16
std::wstring utf8_to_utf16(const std::string& utf8) {
    if (utf8.empty()) return std::wstring();

    // Вычисляем необходимый размер буфера для UTF-16
    int utf16_length = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
    if (utf16_length == 0) {
        return std::wstring();
    }

    // Выделяем буфер для UTF-16
    std::vector<wchar_t> utf16_buffer(utf16_length);

    // Преобразуем строку
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, utf16_buffer.data(), utf16_length);

    return std::wstring(utf16_buffer.data());
}

// Функция для отображения сообщения
void showMessageN(const std::string& message) {
    // Преобразуем строку из UTF-8 в UTF-16
    std::wstring wmessage = utf8_to_utf16(message);

    // Используем MessageBoxW
    MessageBoxW(NULL, wmessage.c_str(), L"Info", MB_OK | MB_ICONINFORMATION);
}




// Глобальная переменная для хранения процента прогресса
int progressPercent = 0;
std::string entropyData;

// Открытие диалогового окна для выбора пути к файлу
std::string openFileDialog(HWND hwnd, const std::string& title) {
    OPENFILENAME ofn;
    char szFile[260] = {0};

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = "All files\0"; // \0*.*\0Text files\0*.TXT\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFile[0] = '\0';
    ofn.lpstrTitle = title.c_str();
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileName(&ofn)) {
        return std::string(szFile);
    }
    return "";
}

std::string saveFileDialog(HWND hwnd, const std::string& title, const std::string& filter) {
    OPENFILENAME ofn;
    char szFile[260] = {0};

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = filter.c_str();
    ofn.nFilterIndex = 1;
    ofn.lpstrFile[0] = '\0';
    ofn.lpstrTitle = title.c_str();
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;

    if (GetSaveFileName(&ofn)) {
        return std::string(szFile);
    }
    return "";
}

// Функция обработки сообщений окна
LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    PAINTSTRUCT ps;
    HDC hdc;
    RECT clientRect;

    HBRUSH brush;
    int filledWidth = 0;

    switch (message) {
        case WM_PAINT:
            // Отрисовка полоски прогресса
            hdc = BeginPaint(hwnd, &ps);
            GetClientRect(hwnd, &clientRect);

            // Отрисовка рамки полоски
            brush = CreateSolidBrush(RGB(0, 0, 0)); // Черная рамка
            SelectObject(hdc, brush);
            Rectangle(hdc, 0, 0, clientRect.right, clientRect.bottom);

            // Вычисляем ширину заполненной части
            filledWidth = (clientRect.right - 10) * progressPercent / 100;

            // Заполняем полоску
            brush = CreateSolidBrush(RGB(0, 255, 0)); // Зеленый цвет заполнения
            SelectObject(hdc, brush);
            Rectangle(hdc, 5, 5, filledWidth + 5, clientRect.bottom - 5);

            DeleteObject(brush);

            EndPaint(hwnd, &ps);
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProc(hwnd, message, wParam, lParam);
    }
    return 0;
}

// Функция для шифрования данных
std::vector<unsigned char> aesEncrypt(const std::string& plaintext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
    std::vector<unsigned char> ciphertext(plaintext.size() + 16);
    int len = 0, ciphertextLen = 0;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size());
    ciphertextLen += len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + ciphertextLen, &len);
    ciphertextLen += len;
    ciphertext.resize(ciphertextLen);
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}

// Функция для расшифрования данных
std::string aesDecrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
    std::vector<unsigned char> plaintext(ciphertext.size());
    int len = 0, plaintextLen = 0;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
    plaintextLen += len;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + plaintextLen, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ""; // Ошибка расшифрования
    }
    plaintextLen += len;
    plaintext.resize(plaintextLen);
    EVP_CIPHER_CTX_free(ctx);

    return std::string(plaintext.begin(), plaintext.end());
}

void handleRSACryptoEncryption(HWND hwnd) {
    std::string publicKeyFile;
    std::string inputFile;
    std::string outputFile;

    publicKeyFile = openFileDialog(hwnd, "Select the RSA public key");
    if (publicKeyFile.empty()) {
        showMessageN("RSA public key file selection was cancelled.");
        return;
    }

    inputFile = openFileDialog(hwnd, "Select the file to encrypt");
    if (inputFile.empty()) {
        showMessageN("Input file selection was cancelled.");
        return;
    }

    outputFile = openFileDialog(hwnd, "Select the file to save the encrypted data");
    if (outputFile.empty()) {
        showMessageN("Output file selection was cancelled.");
        return;
    }

    // Чтение содержимого файла
    std::ifstream fileIn(inputFile, std::ios::binary);
    if (!fileIn) {
        showMessageN("Error opening input file.");
        return;
    }

    std::vector<unsigned char> fileData((std::istreambuf_iterator<char>(fileIn)), std::istreambuf_iterator<char>());

    // Шифрование данных
    std::vector<unsigned char> encryptedRSA = rsaEncryptFile(fileData, publicKeyFile);

    // Запись зашифрованных данных в файл
    std::ofstream outFile(outputFile, std::ios::binary);
    if (!outFile) {
        showMessageN("Error opening output file for writing.");
        return;
    }

    outFile.write((char*)encryptedRSA.data(), encryptedRSA.size());
    if (!outFile) {
        showMessageN("Error writing to the output file.");
        return;
    }

    showMessageN("The file has been successfully encrypted and saved to: " + outputFile);
}

// Функция для конвертации HEX строки в массив байтов
std::vector<unsigned char> hexStringToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        unsigned char byte = std::stoi(hex.substr(i, 2), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

// Обработчик диалогового окна
INT_PTR CALLBACK DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    static std::string *keyIvString = nullptr;

    switch (uMsg) {
        case WM_INITDIALOG:
            // Инициализация указателя на строку для keyIvString
            keyIvString = (std::string*)lParam;
            return TRUE;

        case WM_COMMAND:
            if (LOWORD(wParam) == IDOK) {
                // Извлекаем текст из поля ввода
                char keyIvBuffer[512];
                GetDlgItemText(hwndDlg, IDC_KEY_IV, keyIvBuffer, sizeof(keyIvBuffer));
                *keyIvString = keyIvBuffer; // Передаем строку целиком

                EndDialog(hwndDlg, IDOK);
                return TRUE;
            }
            break;

        case WM_CLOSE:
            EndDialog(hwndDlg, IDCANCEL);
            return TRUE;
    }
    return FALSE;
}

void handleRSAKeyDecryption(HWND hwnd) {
    // Открываем диалоговое окно для выбора пути зашифрованного приватного ключа
    std::string encryptedPrivateKeyPath = openFileDialog(hwnd, "Select Encrypted RSA Private Key");
    if (encryptedPrivateKeyPath.empty()) {
        showMessageN("Encrypted RSA private key file selection was cancelled.");
        return;
    }

    std::string keyIvString;
    // Передаем указатель на строку в диалог
    if (DialogBoxParam(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_DIALOG1), hwnd, DialogProc, (LPARAM)&keyIvString) != IDOK) {
        MessageBox(hwnd, "Key and IV input cancelled.", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    // Разделяем строку на ключ и IV
    size_t colonPos = keyIvString.find(':');
    if (colonPos == std::string::npos) {
        MessageBox(hwnd, "Invalid format. Please enter the key and IV separated by a colon.", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    std::string keyHex = keyIvString.substr(0, colonPos);
    std::string ivHex = keyIvString.substr(colonPos + 1);

    // Конвертируем HEX строки в массивы байтов
    std::vector<unsigned char> key = hexStringToBytes(keyHex);
    std::vector<unsigned char> iv = hexStringToBytes(ivHex);

    // Выводим для проверки
    std::cout << "Key (Hex): " << keyHex << "\n";
    std::cout << "IV (Hex): " << ivHex << "\n";

    // Чтение зашифрованного приватного ключа
    std::ifstream encryptedPrivateKeyIn(encryptedPrivateKeyPath, std::ios::binary);
    if (!encryptedPrivateKeyIn) {
        showMessageN("Error: Unable to read encrypted private key file.");
        return;
    }

    std::vector<unsigned char> encryptedKey((std::istreambuf_iterator<char>(encryptedPrivateKeyIn)), std::istreambuf_iterator<char>());
    encryptedPrivateKeyIn.close();

    // Расшифровка приватного ключа
    std::string decryptedKey = aesDecrypt(encryptedKey, key, iv);
    if (decryptedKey.empty()) {
        showMessageN("Error: Decryption failed.");
        return;
    }

    // Открываем диалоговое окно для выбора пути сохранения расшифрованного ключа
    std::string decryptedKeyPath = saveFileDialog(hwnd, "Save Decrypted RSA Private Key", "RSA Private Key (*.pem)\0*.pem\0All Files (*.*)\0*.*\0");
    if (decryptedKeyPath.empty()) {
        showMessageN("Decrypted RSA private key file save was cancelled.");
        return;
    }

    // Сохранение расшифрованного приватного ключа в выбранный файл
    std::ofstream decryptedPrivateKeyOut(decryptedKeyPath, std::ios::trunc);
    if (!decryptedPrivateKeyOut) {
        showMessageN("Error saving decrypted private key.");
        return;
    }
    decryptedPrivateKeyOut << decryptedKey;
    decryptedPrivateKeyOut.close();

    showMessageN("The private key has been successfully decrypted and saved to: " + decryptedKeyPath);
}
// Функция для проверки доступности USB-накопителя
bool isUSBDriveAvailable(const std::string& driveLetter) {
    std::string rootPath = driveLetter + "\\";
    UINT driveType = GetDriveType(rootPath.c_str());

    // Проверяем, является ли устройство съемным накопителем
    return driveType == DRIVE_REMOVABLE;
}
// Функция для поиска всех доступных USB-накопителей
std::vector<std::string> findAvailableUSBDrives() {
    std::vector<std::string> availableDrives;
    char driveLetter = 'A';

    // Перебираем все возможные буквы дисков от A: до Z:
    for (char driveLetter = 'A'; driveLetter <= 'Z'; ++driveLetter) {
        std::string drivePath = std::string(1, driveLetter) + ":";
        if (isUSBDriveAvailable(drivePath)) {
            availableDrives.push_back(drivePath);
        }
    }

    return availableDrives;
}


void handleRSAKeyGeneration(HWND hwnd, const std::string& entropyData) {
    // Открываем диалоговое окно для ввода ключа и IV
    std::string keyIvString;
    if (DialogBoxParam(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_DIALOG1), hwnd, DialogProc, (LPARAM)&keyIvString) != IDOK) {
        MessageBox(hwnd, "Key and IV input cancelled.", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    // Проверяем, что ключ и IV введены корректно
    if (keyIvString.empty()) {
        MessageBox(hwnd, "Key and IV cannot be empty.", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    // Разделяем строку на ключ и IV
    size_t colonPos = keyIvString.find(':');
    if (colonPos == std::string::npos) {
        MessageBox(hwnd, "Invalid format. Please enter the key and IV separated by a colon.", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    std::string keyHex = keyIvString.substr(0, colonPos);
    std::string ivHex = keyIvString.substr(colonPos + 1);

    // Конвертируем HEX строки в массивы байтов
    std::vector<unsigned char> key = hexStringToBytes(keyHex);
    std::vector<unsigned char> iv = hexStringToBytes(ivHex);

    // Открываем диалоговое окно для выбора пути сохранения публичного ключа
    std::string publicKeyPath = saveFileDialog(hwnd, "Save RSA Public Key", "RSA Public Key (*.pem)\0*.pem\0All Files (*.*)\0*.*\0");
    if (publicKeyPath.empty()) {
        showMessageN("RSA public key file save was cancelled.");
        return;
    }

    // Открываем диалоговое окно для выбора пути сохранения приватного ключа
    std::string privateKeyPath = saveFileDialog(hwnd, "Save RSA Private Key", "RSA Private Key (*.pem)\0*.pem\0All Files (*.*)\0*.*\0");
    if (privateKeyPath.empty()) {
        showMessageN("RSA private key file save was cancelled.");
        return;
    }

    // Генерация ключей и сохранение их по выбранным путям
    generateRSAKeys(entropyData, publicKeyPath, privateKeyPath);

    // Чтение приватного ключа
    std::ifstream privateKeyIn(privateKeyPath);
    if (!privateKeyIn) {
        showMessageN("Error: Unable to read private key file.");
        return;
    }

    std::string rawPrivateKey((std::istreambuf_iterator<char>(privateKeyIn)), std::istreambuf_iterator<char>());
    privateKeyIn.close();

    // Шифрование приватного ключа
    std::vector<unsigned char> encryptedKey = aesEncrypt(rawPrivateKey, key, iv);

    // Сохранение зашифрованного приватного ключа
    std::ofstream privateKeyOut(privateKeyPath, std::ios::binary);
    if (!privateKeyOut) {
        showMessageN("Error saving encrypted private key.");
        return;
    }
    privateKeyOut.write(reinterpret_cast<const char*>(encryptedKey.data()), encryptedKey.size());
    privateKeyOut.close();

    showMessageN("RSA keys have been successfully generated and the private key encrypted.");
}

void handleAESKeyGeneration(HWND hwnd, const std::string& entropyData) {
    // Открываем диалоговое окно для выбора пути сохранения ключа
    std::string keyFile = saveFileDialog(hwnd, "Save AES Key", "AES Key (*.key)\0*.key\0All Files (*.*)\0*.*\0");
    if (keyFile.empty()) {
        showMessageN("AES key file save was cancelled.");
        return;
    }

    // Открываем диалоговое окно для выбора пути сохранения IV
    std::string ivFile = saveFileDialog(hwnd, "Save AES IV", "AES IV (*.iv)\0*.iv\0All Files (*.*)\0*.*\0");
    if (ivFile.empty()) {
        showMessageN("AES IV file save was cancelled.");
        return;
    }

    // Генерация ключей и сохранение их по выбранным путям
    generateAESKeys(entropyData, keyFile, ivFile);
    showMessageN("AES keys and IV have been successfully generated and saved.");
}

void handleECDSAKeyGeneration(HWND hwnd, const std::string& entropyData) {
    // Открываем диалоговое окно для ввода ключа и IV
    std::string keyIvString;
    if (DialogBoxParam(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_DIALOG1), hwnd, DialogProc, (LPARAM)&keyIvString) != IDOK) {
        MessageBox(hwnd, "Key and IV input cancelled.", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    // Проверяем, что ключ и IV введены корректно
    if (keyIvString.empty()) {
        MessageBox(hwnd, "Key and IV cannot be empty.", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    // Разделяем строку на ключ и IV
    size_t colonPos = keyIvString.find(':');
    if (colonPos == std::string::npos) {
        MessageBox(hwnd, "Invalid format. Please enter the key and IV separated by a colon.", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    std::string keyHex = keyIvString.substr(0, colonPos);
    std::string ivHex = keyIvString.substr(colonPos + 1);

    // Конвертируем HEX строки в массивы байтов
    std::vector<unsigned char> key = hexStringToBytes(keyHex);
    std::vector<unsigned char> iv = hexStringToBytes(ivHex);

    // Открываем диалоговое окно для выбора пути сохранения приватного ключа
    std::string privateKeyPath = saveFileDialog(hwnd, "Save ECDSA Private Key", "ECDSA Private Key (*.pem)\0*.pem\0All Files (*.*)\0*.*\0");
    if (privateKeyPath.empty()) {
        showMessageN("ECDSA private key file save was cancelled.");
        return;
    }

    // Открываем диалоговое окно для выбора пути сохранения публичного ключа
    std::string publicKeyPath = saveFileDialog(hwnd, "Save ECDSA Public Key", "ECDSA Public Key (*.pem)\0*.pem\0All Files (*.*)\0*.*\0");
    if (publicKeyPath.empty()) {
        showMessageN("ECDSA public key file save was cancelled.");
        return;
    }

    // Генерация ключей и сохранение их по выбранным путям
    generateECDSAKeys(entropyData, privateKeyPath, publicKeyPath);

    // Чтение приватного ключа
    std::ifstream privateKeyIn(privateKeyPath);
    if (!privateKeyIn) {
        showMessageN("Error: Unable to read private key file.");
        return;
    }

    std::string rawPrivateKey((std::istreambuf_iterator<char>(privateKeyIn)), std::istreambuf_iterator<char>());
    privateKeyIn.close();

    // Шифрование приватного ключа
    std::vector<unsigned char> encryptedKey = aesEncrypt(rawPrivateKey, key, iv);

    // Сохранение зашифрованного приватного ключа
    std::ofstream privateKeyOut(privateKeyPath, std::ios::binary);
    if (!privateKeyOut) {
        showMessageN("Error saving encrypted private key.");
        return;
    }
    privateKeyOut.write(reinterpret_cast<const char*>(encryptedKey.data()), encryptedKey.size());
    privateKeyOut.close();

    showMessageN("ECDSA keys have been successfully generated and the private key encrypted.");
}
void handleECDSAKeyDecryption(HWND hwnd) {
    // Открываем диалоговое окно для выбора пути зашифрованного приватного ключа
    std::string encryptedPrivateKeyPath = openFileDialog(hwnd, "Select Encrypted ECDSA Private Key");
    if (encryptedPrivateKeyPath.empty()) {
        showMessageN("Encrypted ECDSA private key file selection was cancelled.");
        return;
    }

    std::string keyIvString;
    // Передаем указатель на строку в диалог
    if (DialogBoxParam(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_DIALOG1), hwnd, DialogProc, (LPARAM)&keyIvString) != IDOK) {
        MessageBox(hwnd, "Key and IV input cancelled.", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    // Разделяем строку на ключ и IV
    size_t colonPos = keyIvString.find(':');
    if (colonPos == std::string::npos) {
        MessageBox(hwnd, "Invalid format. Please enter the key and IV separated by a colon.", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    std::string keyHex = keyIvString.substr(0, colonPos);
    std::string ivHex = keyIvString.substr(colonPos + 1);

    // Конвертируем HEX строки в массивы байтов
    std::vector<unsigned char> key = hexStringToBytes(keyHex);
    std::vector<unsigned char> iv = hexStringToBytes(ivHex);

    // Чтение зашифрованного приватного ключа
    std::ifstream encryptedPrivateKeyIn(encryptedPrivateKeyPath, std::ios::binary);
    if (!encryptedPrivateKeyIn) {
        showMessageN("Error: Unable to read encrypted private key file.");
        return;
    }

    std::vector<unsigned char> encryptedKey((std::istreambuf_iterator<char>(encryptedPrivateKeyIn)), std::istreambuf_iterator<char>());
    encryptedPrivateKeyIn.close();

    // Расшифровка приватного ключа
    std::string decryptedKey = aesDecrypt(encryptedKey, key, iv);
    if (decryptedKey.empty()) {
        showMessageN("Error: Decryption failed.");
        return;
    }

    // Открываем диалоговое окно для выбора пути сохранения расшифрованного ключа
    std::string decryptedKeyPath = saveFileDialog(hwnd, "Save Decrypted ECDSA Private Key", "ECDSA Private Key (*.pem)\0*.pem\0All Files (*.*)\0*.*\0");
    if (decryptedKeyPath.empty()) {
        showMessageN("Decrypted ECDSA private key file save was cancelled.");
        return;
    }

    // Сохранение расшифрованного приватного ключа в выбранный файл
    std::ofstream decryptedPrivateKeyOut(decryptedKeyPath, std::ios::trunc);
    if (!decryptedPrivateKeyOut) {
        showMessageN("Error saving decrypted private key.");
        return;
    }
    decryptedPrivateKeyOut << decryptedKey;
    decryptedPrivateKeyOut.close();

    showMessageN("The private key has been successfully decrypted and saved to: " + decryptedKeyPath);
}

void handleRSACryptoDecryption(HWND hwnd) {
    std::string privateKeyFile;
    std::string inputFile;
    std::string outputFile;

    privateKeyFile = openFileDialog(hwnd, "Select the RSA private key");
    if (privateKeyFile.empty()) {
        showMessageN("RSA private key file selection was cancelled.");
        return;
    }

    inputFile = openFileDialog(hwnd, "Select the file to decrypt");
    if (inputFile.empty()) {
        showMessageN("Input file selection was cancelled.");
        return;
    }

    outputFile = openFileDialog(hwnd, "Select the file to save the decrypted data");
    if (outputFile.empty()) {
        showMessageN("Output file selection was cancelled.");
        return;
    }

    // Чтение зашифрованного содержимого файла
    std::ifstream fileIn(inputFile, std::ios::binary);
    if (!fileIn) {
        showMessageN("Error opening input file.");
        return;
    }

    std::vector<unsigned char> encryptedData((std::istreambuf_iterator<char>(fileIn)), std::istreambuf_iterator<char>());

    // Расшифрование данных
    std::vector<unsigned char> decryptedRSA = rsaDecryptFile(encryptedData, privateKeyFile);

    // Запись расшифрованных данных в файл
    std::ofstream outFile(outputFile, std::ios::binary);
    if (!outFile) {
        showMessageN("Error opening output file for writing.");
        return;
    }

    outFile.write((char*)decryptedRSA.data(), decryptedRSA.size());
    if (!outFile) {
        showMessageN("Error writing to the output file.");
        return;
    }

    showMessageN("The file has been successfully decrypted and saved to: " + outputFile);
}

void handleAESEncryption(HWND hwnd) {
    std::string keyFile, ivFile, inputFile, outputFile;

    keyFile = openFileDialog(hwnd, "Select the AES Key File");
    if (keyFile.empty()) {
        showMessageN("AES key file selection was cancelled.");
        return;
    }

    ivFile = openFileDialog(hwnd, "Select the IV File");
    if (ivFile.empty()) {
        showMessageN("IV file selection was cancelled.");
        return;
    }

    inputFile = openFileDialog(hwnd, "Select the file to encrypt");
    if (inputFile.empty()) {
        showMessageN("Input file selection was cancelled.");
        return;
    }

    outputFile = openFileDialog(hwnd, "Select the file to save the encrypted data");
    if (outputFile.empty()) {
        showMessageN("Output file selection was cancelled.");
        return;
    }

    std::vector<unsigned char> key(32), iv(16);

    std::ifstream keyIn(keyFile, std::ios::binary);
    if (!keyIn || !keyIn.read((char*)key.data(), key.size())) {
        showMessageN("Error reading AES key file.");
        return;
    }

    std::ifstream ivIn(ivFile, std::ios::binary);
    if (!ivIn || !ivIn.read((char*)iv.data(), iv.size())) {
        showMessageN("Error reading IV file.");
        return;
    }

    // Чтение содержимого файла
    std::ifstream fileIn(inputFile, std::ios::binary);
    if (!fileIn) {
        showMessageN("Error opening input file.");
        return;
    }

    std::vector<unsigned char> fileData((std::istreambuf_iterator<char>(fileIn)), std::istreambuf_iterator<char>());

    // Шифрование данных
    std::vector<unsigned char> encrypted = aesEncrypt(std::string(fileData.begin(), fileData.end()), key, iv);

    // Запись зашифрованных данных в файл
    std::ofstream outFile(outputFile, std::ios::binary);
    if (!outFile) {
        showMessageN("Error opening output file for writing.");
        return;
    }

    outFile.write((char*)encrypted.data(), encrypted.size());
    if (!outFile) {
        showMessageN("Error writing to the output file.");
        return;
    }

    showMessageN("The file has been successfully encrypted and saved to: " + outputFile);
}

void handleAESDecryption(HWND hwnd) {
    std::string keyFile, ivFile, inputFile, outputFile;

    keyFile = openFileDialog(hwnd, "Select the AES Key File");
    if (keyFile.empty()) {
        showMessageN("AES key file selection was cancelled.");
        return;
    }

    ivFile = openFileDialog(hwnd, "Select the IV File");
    if (ivFile.empty()) {
        showMessageN("IV file selection was cancelled.");
        return;
    }

    inputFile = openFileDialog(hwnd, "Select the file to decrypt");
    if (inputFile.empty()) {
        showMessageN("Input file selection was cancelled.");
        return;
    }

    outputFile = openFileDialog(hwnd, "Select the file to save the decrypted data");
    if (outputFile.empty()) {
        showMessageN("Output file selection was cancelled.");
        return;
    }

    std::vector<unsigned char> key(32), iv(16);

    std::ifstream keyIn(keyFile, std::ios::binary);
    if (!keyIn || !keyIn.read((char*)key.data(), key.size())) {
        showMessageN("Error reading AES key file.");
        return;
    }

    std::ifstream ivIn(ivFile, std::ios::binary);
    if (!ivIn || !ivIn.read((char*)iv.data(), iv.size())) {
        showMessageN("Error reading IV file.");
        return;
    }

    // Чтение зашифрованного содержимого файла
    std::ifstream fileIn(inputFile, std::ios::binary);
    if (!fileIn) {
        showMessageN("Error opening input file.");
        return;
    }

    std::vector<unsigned char> encryptedData((std::istreambuf_iterator<char>(fileIn)), std::istreambuf_iterator<char>());

    // Расшифрование данных
    std::string decrypted = aesDecrypt(encryptedData, key, iv);
    if (decrypted.empty()) {
        showMessageN("Decryption failed.");
        return;
    }

    // Запись расшифрованных данных в файл
    std::ofstream outFile(outputFile, std::ios::binary);
    if (!outFile) {
        showMessageN("Error opening output file for writing.");
        return;
    }

    outFile.write(decrypted.data(), decrypted.size());
    if (!outFile) {
        showMessageN("Error writing to the output file.");
        return;
    }

    showMessageN("The file has been successfully decrypted and saved to: " + outputFile);
}

void handleMessageSigning(HWND hwnd) {
    std::string privateKeyFile;
    std::string inputFile;
    std::string outputFile;

    inputFile = openFileDialog(hwnd, "Select the file to sign");
    if (inputFile.empty()) {
        showMessageN("Input file selection was cancelled.");
        return;
    }

    privateKeyFile = openFileDialog(hwnd, "Select the ECDSA Private Key File");
    if (privateKeyFile.empty()) {
        showMessageN("Private key file selection was cancelled.");
        return;
    }

    outputFile = openFileDialog(hwnd, "Select the File to Save the Signature");
    if (outputFile.empty()) {
        showMessageN("Output file selection was cancelled.");
        return;
    }

    std::vector<unsigned char> signature = signFile(inputFile, privateKeyFile);

    std::string hexSignature;
    for (unsigned char c : signature) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02X", c);
        hexSignature += hex;
    }

    std::ofstream outFile(outputFile);
    if (!outFile) {
        showMessageN("Error opening the file for writing.");
        return;
    }

    outFile << hexSignature;
    if (!outFile) {
        showMessageN("Error writing to the file.");
        return;
    }

    showMessageN("The signature has been successfully saved to the file: " + outputFile);
}

void handleSignatureVerification(HWND hwnd) {
    std::string publicKeyFile;
    std::string inputFile;
    std::string signatureFile;

    inputFile = openFileDialog(hwnd, "Select the file to verify");
    if (inputFile.empty()) {
        showMessageN("Input file selection was cancelled.");
        return;
    }

    publicKeyFile = openFileDialog(hwnd, "Select the ECDSA public key");
    if (publicKeyFile.empty()) {
        showMessageN("Public key file selection canceled or failed.");
        return;
    }

    signatureFile = openFileDialog(hwnd, "Select the signature file");
    if (signatureFile.empty()) {
        showMessageN("Signature file selection was cancelled.");
        return;
    }

    // Чтение подписи из файла
    std::ifstream sigFileIn(signatureFile);
    if (!sigFileIn) {
        showMessageN("Error opening signature file.");
        return;
    }

    std::string hexSignature((std::istreambuf_iterator<char>(sigFileIn)), std::istreambuf_iterator<char>());

    // Преобразование HEX-строки в бинарный формат
    std::vector<unsigned char> signature;
    for (size_t i = 0; i < hexSignature.length(); i += 2) {
        std::string byteString = hexSignature.substr(i, 2);
        unsigned char byte = (unsigned char)strtol(byteString.c_str(), nullptr, 16);
        signature.push_back(byte);
    }

    // Верификация подписи
    bool valid = verifyFileSignature(inputFile, signature, publicKeyFile);
    if (valid) {
        showMessageN("The signature is valid.");
    } else {
        showMessageN("The signature is invalid.");
    }
}

// Функция для обработки сообщений окна
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    // Обработка команд (кнопок)
    switch (uMsg) {
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case 1: // Генерация RSA ключей
                    handleRSAKeyGeneration(hwnd, entropyData);
                    break;
                case 2: // Генерация AES ключей
                    handleAESKeyGeneration(hwnd, entropyData);
                    break;
                case 3: // Генерация ECDSA ключей
                    handleECDSAKeyGeneration(hwnd, entropyData);
                    break;
                case 4: // Шифрование RSA
                    handleRSACryptoEncryption(hwnd);
                    break;
                case 5: // Расшифрование RSA
                    handleRSACryptoDecryption(hwnd);
                    break;
                case 6: // Шифрование AES
                    handleAESEncryption(hwnd);
                    break;
                case 7: // Расшифрование AES
                    handleAESDecryption(hwnd);
                    break;
                case 8: // Подпись сообщения ECDSA
                    handleMessageSigning(hwnd);
                    break;
                case 9: // Проверка подписи ECDSA
                    handleSignatureVerification(hwnd);
                    break;
                case 10:
                    handleRSAKeyDecryption(hwnd);
                    break;
                case 11: // Расшифровка ECDSA ключа
                    handleECDSAKeyDecryption(hwnd);
                    break;

                case 0: // Выход
                    exit(0);
                    PostQuitMessage(0);
                    break;

                default:
                    break;
            }
            break;

        case WM_CLOSE:
            exit(0);
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

// Функция для создания окна и меню
HWND createMainWindow(HINSTANCE hInstance) {
    const char CLASS_NAME[] = "MainWindow";

    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;

    if (!RegisterClass(&wc)) {
        std::cerr << "Ошибка регистрации класса окна!" << std::endl;
        return nullptr;
    }

    HWND hwnd = CreateWindowEx(
            0, CLASS_NAME, "Cryptographic Operations Menu", WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT, CW_USEDEFAULT, 315, 600, nullptr, nullptr, hInstance, nullptr
    );

    if (hwnd == nullptr) {
        std::cerr << "Ошибка создания окна!" << std::endl;
        return nullptr;
    }

    return hwnd;
}

void createButtons(HWND hwnd, HINSTANCE hInstance) {
    int buttonWidth = 200;
    int buttonHeight = 30;
    int x = 50; // Горизонтальная позиция кнопок
    int y = 50; // Начальная вертикальная позиция
    int spacing = 10; // Отступ между кнопками
    std::wstring btnText1 = utf8_to_utf16("Генерация RSA ключей");
    std::wstring btnText2 = utf8_to_utf16("Генерация AES ключа");
    std::wstring btnText3 = utf8_to_utf16("Генерация ECDSA ключей");
    std::wstring btnText4 = utf8_to_utf16("RSA Шифрование");
    std::wstring btnText5 = utf8_to_utf16("RSA Расшифрование");
    std::wstring btnText6 = utf8_to_utf16("AES Шифрование");
    std::wstring btnText7 = utf8_to_utf16("AES Расшифрование");
    std::wstring btnText8 = utf8_to_utf16("ECDSA подписать");
    std::wstring btnText9 = utf8_to_utf16("ECDSA проверить подпись");
    std::wstring btnText10 = utf8_to_utf16("Расшифровка priv_RSA");
    std::wstring btnText11 = utf8_to_utf16("Расшифровка priv_ECDSA");
    std::wstring btnText12 = utf8_to_utf16("Выход");
    // Создаем кнопки с использованием CreateWindowW
    CreateWindowW(L"BUTTON", btnText1.c_str(), WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                  x, y, buttonWidth, buttonHeight, hwnd, (HMENU)1, hInstance, nullptr);

    y += buttonHeight + spacing;
    CreateWindowW(L"BUTTON", btnText2.c_str(), WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                  x, y, buttonWidth, buttonHeight, hwnd, (HMENU)2, hInstance, nullptr);

    y += buttonHeight + spacing;
    CreateWindowW(L"BUTTON", btnText3.c_str(), WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                  x, y, buttonWidth, buttonHeight, hwnd, (HMENU)3, hInstance, nullptr);

    y += buttonHeight + spacing;
    CreateWindowW(L"BUTTON", btnText4.c_str(), WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                  x, y, buttonWidth, buttonHeight, hwnd, (HMENU)4, hInstance, nullptr);

    y += buttonHeight + spacing;
    CreateWindowW(L"BUTTON", btnText5.c_str(), WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                  x, y, buttonWidth, buttonHeight, hwnd, (HMENU)5, hInstance, nullptr);

    y += buttonHeight + spacing;
    CreateWindowW(L"BUTTON", btnText6.c_str(), WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                  x, y, buttonWidth, buttonHeight, hwnd, (HMENU)6, hInstance, nullptr);

    y += buttonHeight + spacing;
    CreateWindowW(L"BUTTON", btnText7.c_str(), WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                  x, y, buttonWidth, buttonHeight, hwnd, (HMENU)7, hInstance, nullptr);

    y += buttonHeight + spacing;
    CreateWindowW(L"BUTTON", btnText8.c_str(), WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                  x, y, buttonWidth, buttonHeight, hwnd, (HMENU)8, hInstance, nullptr);

    y += buttonHeight + spacing;
    CreateWindowW(L"BUTTON", btnText9.c_str(), WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                  x, y, buttonWidth, buttonHeight, hwnd, (HMENU)9, hInstance, nullptr);

    y += buttonHeight + spacing;
    CreateWindowW(L"BUTTON", btnText10.c_str(), WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                  x, y, buttonWidth, buttonHeight, hwnd, (HMENU)IDC_BUTTON_DECRYPTION_PRIV_KEY, hInstance, nullptr);

    y += buttonHeight + spacing;
    CreateWindowW(L"BUTTON", btnText11.c_str(), WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                  x, y, buttonWidth, buttonHeight, hwnd, (HMENU)11, hInstance, nullptr);

    y += buttonHeight + spacing;
    CreateWindowW(L"BUTTON", btnText12.c_str(), WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                  x, y, buttonWidth, buttonHeight, hwnd, (HMENU)0, hInstance, nullptr);

}

// Создание окна прогресса
HWND CreateProgressWindow(HINSTANCE hInstance) {
    WNDCLASSEX wc = { 0 };
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 0;
    wc.hInstance = hInstance;
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszMenuName = NULL;
    wc.lpszClassName = "ProgressWindowClass";
    wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);

    RegisterClassEx(&wc);

    HWND hwndA = CreateWindowEx(WS_EX_OVERLAPPEDWINDOW,
                                "ProgressWindowClass",
                                "Process...",
                                WS_OVERLAPPEDWINDOW,
                                CW_USEDEFAULT, CW_USEDEFAULT,
                                400, 200,
                                NULL, NULL,
                                hInstance, NULL);

    if (hwndA == NULL) {
        MessageBoxA(NULL, "Ошибка создания окна", "Ошибка", MB_OK | MB_ICONERROR);
        return NULL;
    }

    ShowWindow(hwndA, SW_SHOW);
    UpdateWindow(hwndA);
    return hwndA;
}

// Функция для отображения сообщения
void showMessage(const std::string& message) {
    // Преобразуем строку в юникод
    std::wstring wmessage = std::wstring(message.begin(), message.end());

    // Используем MessageBoxW
    MessageBoxW(NULL, wmessage.c_str(), L"Сбор энтропии", MB_OK | MB_ICONINFORMATION);
}

// Функция сбора энтропии с помощью движения мыши
std::string collectMouseEntropy(int maxDurationMs = 60000, int intervalMs = 10, int minMovements = 100) {
    std::string entropyData;
    POINT cursorPosition;
    POINT previousPosition = { -1, -1 };
    int movementCount = 0;
    auto start = GetTickCount();

    showMessageN("Двигайте мишкой для сбора энтропии...");

    // Создаем окно прогресса
    HWND progressWindow = CreateProgressWindow(GetModuleHandle(NULL));

    while (true) {
        if (GetCursorPos(&cursorPosition)) {
            int deltaX = abs(cursorPosition.x - previousPosition.x);
            int deltaY = abs(cursorPosition.y - previousPosition.y);

            if (deltaX > 1 || deltaY > 1) {
                entropyData += std::to_string(cursorPosition.x);
                entropyData += std::to_string(cursorPosition.y);

                auto timestamp = std::chrono::high_resolution_clock::now().time_since_epoch().count();
                entropyData += std::to_string(timestamp);

                previousPosition = cursorPosition;
                movementCount++;

                // Обновляем полоску прогресса
                progressPercent = (movementCount * 100) / minMovements;
                InvalidateRect(progressWindow, NULL, TRUE);
                UpdateWindow(progressWindow);
            }
        }

        if ((GetTickCount() - start) >= maxDurationMs && movementCount < minMovements) {
            std::cerr << "\nНе удалось собрать достаточно энтропии (меньше " << minMovements << " движений мышью)." << std::endl;
            return {};
        }

        if (movementCount >= minMovements) {
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
    }

    // Закрываем окно прогресса
    DestroyWindow(progressWindow);

    // Сохраняем энтропию в файл
    std::ofstream entropyFile("entropy.txt");
    if (entropyFile.is_open()) {
        entropyFile << entropyData;
        entropyFile.close();
    } else {
        std::cerr << "Не удалось открыть файл для записи энтропии." << std::endl;
    }

    return entropyData;
}

// Функция для преобразования вектора байтов в 16-ричную строку
std::string toHexString(const std::vector<unsigned char>& data) {
    std::ostringstream hexStream;
    for (unsigned char byte : data) {
        hexStream << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    return hexStream.str();
}

// Функция для генерации AES-ключа и IV
std::pair<std::string, std::string> generateKeyAndIV() {
    // Генерация AES-ключа (32 байта для AES-256)
    std::vector<unsigned char> key(32);
    if (RAND_bytes(key.data(), key.size()) != 1) {
        std::cerr << "Ошибка генерации AES-ключа." << std::endl;
        return std::make_pair("", "");
    }

    // Генерация IV (16 байтов)
    std::vector<unsigned char> iv(16);
    if (RAND_bytes(iv.data(), iv.size()) != 1) {
        std::cerr << "Ошибка генерации IV." << std::endl;
        return std::make_pair("", "");
    }

    // Преобразуем ключ и IV в 16-ричный формат
    std::string keyHex = toHexString(key);
    std::string ivHex = toHexString(iv);

    return std::make_pair(keyHex, ivHex);
}

// Функция для сохранения ключа и IV в файл
void saveKeyAndIVToFile(const std::string& keyHex, const std::string& ivHex, const std::string& filePath) {
    // Объединяем ключ и IV в одну строку
    std::string combined = keyHex + ":" + ivHex;

    // Сохранение объединенной строки в текстовый файл
    std::ofstream file(filePath);
    if (!file) {
        std::cerr << "Не удалось открыть файл для записи." << std::endl;
        return;
    }
    file << combined;
    if (!file) {
        std::cerr << "Ошибка записи в файл." << std::endl;
        return;
    }
    file.close();

    std::cout << "Key and IV saved to file: " << filePath << std::endl;
}



LRESULT CALLBACK PasswordWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            // Создание текстового поля для отображения пароля
            CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | ES_READONLY,
                           50, 50, 300, 30, hwnd, (HMENU)IDC_EDIT_PASSWORD, GetModuleHandle(NULL), NULL);
            break;
        }
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

void showPassword(const std::string& password) {
    // Регистрация класса окна
    WNDCLASS wc = {};
    wc.lpfnWndProc = PasswordWindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = "PasswordWindowClass";
    RegisterClass(&wc);

    // Создание окна
    HWND hwnd = CreateWindowEx(0, "PasswordWindowClass", "Generated Password", WS_OVERLAPPEDWINDOW,
                               CW_USEDEFAULT, CW_USEDEFAULT, 400, 200, NULL, NULL, GetModuleHandle(NULL), NULL);

    // Отображение пароля в текстовом поле
    HWND hEdit = GetDlgItem(hwnd, IDC_EDIT_PASSWORD);
    SetWindowText(hEdit, password.c_str());

    // Показ окна
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    // Цикл сообщений для окна
    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

int main() {
    // Установка кодировки консоли
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    // Инициализация библиотеки OpenSSL
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);

    int maxDurationMs = 60000;
    int intervalMs = 10;
    int minMovements = 100;

    // Создание потока для сбора энтропии
    std::thread entropyThread([&]() {
        entropyData = collectMouseEntropy(maxDurationMs, intervalMs, minMovements);
    });

    while (true) {
        if (progressPercent >= 100) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
    }
    // Поиск всех доступных USB-накопителей
    std::vector<std::string> usbDrives = findAvailableUSBDrives();

    if (usbDrives.empty()) {
        // Отображаем окно с ошибкой
        showMessageN("Ошибка: не найдено ни одного внешнего накопителя.");
        return 1;
    }

    // Вывод найденных накопителей
    std::cout << "Найдены следующие внешние накопители:" << std::endl;
    for (const auto& drive : usbDrives) {
        std::cout << drive << std::endl;
    }

    // Выбор первого найденного накопителя (или можно добавить логику для выбора конкретного)
    std::string usbDrive = usbDrives[0];
    // Генерация AES-ключа и IV
    auto keyAndIVHex = generateKeyAndIV();
    if (keyAndIVHex.first.empty() || keyAndIVHex.second.empty()) {
        std::cerr << "Ошибка генерации ключа или IV." << std::endl;
        return 1;
    }

    // Объединяем ключ и IV в одну строку
    std::string password = keyAndIVHex.first + ":" + keyAndIVHex.second;

    // Показ пароля пользователю
    showPassword(password);

    // Сохранение ключа и IV на флешку
    std::string filePath = usbDrive + "\\key_and_iv.txt";
    saveKeyAndIVToFile(keyAndIVHex.first, keyAndIVHex.second, filePath);

    // Создание окна
    HINSTANCE hInstance = GetModuleHandle(nullptr);
    HWND hwnd = createMainWindow(hInstance);
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    if (hwnd == nullptr) {
        return 1;
    }

    // Создание кнопок
    createButtons(hwnd, hInstance);

    // Запуск цикла сообщений
    MSG msg = {};
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}