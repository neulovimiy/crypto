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
    MessageBoxW(NULL, wmessage.c_str(), L"Информация", MB_OK | MB_ICONINFORMATION);
}

// Глобальная переменная для хранения процента прогресса
int progressPercent = 0;
std::string entropyData;

// Открытие диалогового окна для выбора пути к файлу
std::string openFileDialog(HWND hwnd, const std::string& title) {
    OPENFILENAMEW ofn;
    wchar_t szFile[260] = {0};
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile) / sizeof(wchar_t);

    // Преобразуем заголовок из UTF-8 в UTF-16
    std::wstring wTitle = utf8_to_utf16(title);
    ofn.lpstrTitle = wTitle.c_str();

    ofn.lpstrFilter = L"All files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFile[0] = '\0';
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileNameW(&ofn)) {
        // Преобразуем выбранный путь из UTF-16 в UTF-8
        std::wstring wFilePath(szFile);
        std::string filePath(wFilePath.begin(), wFilePath.end());
        return filePath;
    }
    return "";
}

std::string saveFileDialog(HWND hwnd, const std::string& title, const std::string& filter) {
    OPENFILENAMEW ofn;
    wchar_t szFile[260] = {0};
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile) / sizeof(wchar_t);

    // Преобразуем фильтр из UTF-8 в UTF-16
    std::wstring wFilter = utf8_to_utf16(filter);
    ofn.lpstrFilter = wFilter.c_str();

    // Преобразуем заголовок из UTF-8 в UTF-16
    std::wstring wTitle = utf8_to_utf16(title);
    ofn.lpstrTitle = wTitle.c_str();

    ofn.nFilterIndex = 1;
    ofn.lpstrFile[0] = '\0';
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;

    if (GetSaveFileNameW(&ofn)) {
        // Преобразуем выбранный путь из UTF-16 в UTF-8
        std::wstring wFilePath(szFile);
        std::string filePath(wFilePath.begin(), wFilePath.end());
        return filePath;
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
    publicKeyFile = openFileDialog(hwnd, "Выберите открытый ключ RSA");
    if (publicKeyFile.empty()) {
        showMessageN("Выбор файла с открытым ключом RSA был отменен.");
        return;
    }
    inputFile = openFileDialog(hwnd, "Выберите файл для шифрования");
    if (inputFile.empty()) {
        showMessageN("Выбор входного файла был отменен.");
        return;
    }
    outputFile = openFileDialog(hwnd, "Выберите файл для сохранения зашифрованных данных");
    if (outputFile.empty()) {
        showMessageN("Выбор выходного файла был отменен.");
        return;
    }
    // Чтение содержимого файла
    std::ifstream fileIn(inputFile, std::ios::binary);
    if (!fileIn) {
        showMessageN("Ошибка при открытии входного файла.");
        return;
    }
    std::vector<unsigned char> fileData((std::istreambuf_iterator<char>(fileIn)), std::istreambuf_iterator<char>());
    // Шифрование данных
    std::vector<unsigned char> encryptedRSA = rsaEncryptFile(fileData, publicKeyFile);
    // Запись зашифрованных данных в файл
    std::ofstream outFile(outputFile, std::ios::binary);
    if (!outFile) {
        showMessageN("Ошибка при открытии выходного файла для записи.");
        return;
    }
    outFile.write((char*)encryptedRSA.data(), encryptedRSA.size());
    if (!outFile) {
        showMessageN("Ошибка записи в выходной файл.");
        return;
    }
    showMessageN("Файл был успешно зашифрован и сохранен в: " + outputFile);
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
    std::string publicKeyPath = saveFileDialog(hwnd, "Сохранение открытого ключа", "RSA Public Key (*.pem)\0*.pem\0All Files (*.*)\0*.*\0");
    if (publicKeyPath.empty()) {
        showMessageN("Сохранение файла открытого ключа RSA было отменено.");
        return;
    }
    // Открываем диалоговое окно для выбора пути сохранения приватного ключа
    std::string privateKeyPath = saveFileDialog(hwnd, "Сохранение закрытого ключа RSA", "RSA Private Key (*.pem)\0*.pem\0All Files (*.*)\0*.*\0");
    if (privateKeyPath.empty()) {
        showMessageN("Сохранение файла закрытого ключа RSA было отменено.");
        return;
    }
    // Генерация ключей и сохранение их по выбранным путям
    generateRSAKeys(entropyData, publicKeyPath, privateKeyPath);
    // Чтение приватного ключа
    std::ifstream privateKeyIn(privateKeyPath);
    if (!privateKeyIn) {
        showMessageN("Ошибка: Не удается прочитать файл закрытого ключа.");
        return;
    }
    std::string rawPrivateKey((std::istreambuf_iterator<char>(privateKeyIn)), std::istreambuf_iterator<char>());
    privateKeyIn.close();
    // Шифрование приватного ключа
    std::vector<unsigned char> encryptedKey = aesEncrypt(rawPrivateKey, key, iv);
    // Сохранение зашифрованного приватного ключа
    std::ofstream privateKeyOut(privateKeyPath, std::ios::binary);
    if (!privateKeyOut) {
        showMessageN("Ошибка при сохранении зашифрованного закрытого ключа.");
        return;
    }
    privateKeyOut.write(reinterpret_cast<const char*>(encryptedKey.data()), encryptedKey.size());
    privateKeyOut.close();
    showMessageN("Ключи RSA были успешно сгенерированы, а закрытый ключ зашифрован.");
}

void handleAESKeyGeneration(HWND hwnd, const std::string& entropyData) {
    // Открываем диалоговое окно для выбора пути сохранения ключа
    std::string keyFile = saveFileDialog(hwnd, "Сохранить ключ AES", "AES Key (*.key)\0*.key\0All Files (*.*)\0*.*\0");
    if (keyFile.empty()) {
        showMessageN("Сохранение ключевого файла AES было отменено.");
        return;
    }
    // Открываем диалоговое окно для выбора пути сохранения IV
    std::string ivFile = saveFileDialog(hwnd, "Сохранить AES IV", "AES IV (*.iv)\0*.iv\0All Files (*.*)\0*.*\0");
    if (ivFile.empty()) {
        showMessageN("Сохранение файла AES IV было отменено.");
        return;
    }
    // Генерация ключей и сохранение их по выбранным путям
    generateAESKeys(entropyData, keyFile, ivFile);
    showMessageN("Ключи AES и IV были успешно сгенерированы и сохранены.");
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
    std::string privateKeyPath = saveFileDialog(hwnd, "Сохраните секретный ключ ECDSA", "ECDSA Private Key (*.pem)\0*.pem\0All Files (*.*)\0*.*\0");
    if (privateKeyPath.empty()) {
        showMessageN("Сохранение файла секретного ключа ECDSA было отменено.");
        return;
    }
    // Открываем диалоговое окно для выбора пути сохранения публичного ключа
    std::string publicKeyPath = saveFileDialog(hwnd, "Сохранение открытого ключа ECDSA", "ECDSA Public Key (*.pem)\0*.pem\0All Files (*.*)\0*.*\0");
    if (publicKeyPath.empty()) {
        showMessageN("Сохранение файла открытого ключа ECDSA было отменено.");
        return;
    }
    // Генерация ключей и сохранение их по выбранным путям
    generateECDSAKeys(entropyData, privateKeyPath, publicKeyPath);
    // Чтение приватного ключа
    std::ifstream privateKeyIn(privateKeyPath);
    if (!privateKeyIn) {
        showMessageN("Ошибка: Не удается прочитать файл закрытого ключа.");
        return;
    }
    std::string rawPrivateKey((std::istreambuf_iterator<char>(privateKeyIn)), std::istreambuf_iterator<char>());
    privateKeyIn.close();
    // Шифрование приватного ключа
    std::vector<unsigned char> encryptedKey = aesEncrypt(rawPrivateKey, key, iv);
    // Сохранение зашифрованного приватного ключа
    std::ofstream privateKeyOut(privateKeyPath, std::ios::binary);
    if (!privateKeyOut) {
        showMessageN("Ошибка при сохранении зашифрованного закрытого ключа.");
        return;
    }
    privateKeyOut.write(reinterpret_cast<const char*>(encryptedKey.data()), encryptedKey.size());
    privateKeyOut.close();
    showMessageN("Ключи ECDSA были успешно сгенерированы, а закрытый ключ зашифрован.");
}

void handleAESEncryption(HWND hwnd) {
    std::string keyFile, ivFile, inputFile, outputFile;
    keyFile = openFileDialog(hwnd, "Выберите файл ключа AES");
    if (keyFile.empty()) {
        showMessageN("Выбор ключевого файла AES был отменен.");
        return;
    }
    ivFile = openFileDialog(hwnd, "Выберите файл IV");
    if (ivFile.empty()) {
        showMessageN("IV выбор файла был отменен.");
        return;
    }
    inputFile = openFileDialog(hwnd, "Выберите файл для шифрования");
    if (inputFile.empty()) {
        showMessageN("Выбор входного файла был отменен.");
        return;
    }
    outputFile = openFileDialog(hwnd, "Выберите файл для сохранения зашифрованных данных");
    if (outputFile.empty()) {
        showMessageN("Выбор выходного файла был отменен.");
        return;
    }
    std::vector<unsigned char> key(32), iv(16);
    std::ifstream keyIn(keyFile, std::ios::binary);
    if (!keyIn || !keyIn.read((char*)key.data(), key.size())) {
        showMessageN("Ошибка при чтении ключевого файла AES.");
        return;
    }
    std::ifstream ivIn(ivFile, std::ios::binary);
    if (!ivIn || !ivIn.read((char*)iv.data(), iv.size())) {
        showMessageN("Ошибка при чтении IV файла.");
        return;
    }
    // Чтение содержимого файла
    std::ifstream fileIn(inputFile, std::ios::binary);
    if (!fileIn) {
        showMessageN("Ошибка при открытии входного файла.");
        return;
    }
    std::vector<unsigned char> fileData((std::istreambuf_iterator<char>(fileIn)), std::istreambuf_iterator<char>());
    // Шифрование данных
    std::vector<unsigned char> encrypted = aesEncrypt(std::string(fileData.begin(), fileData.end()), key, iv);
    // Запись зашифрованных данных в файл
    std::ofstream outFile(outputFile, std::ios::binary);
    if (!outFile) {
        showMessageN("Ошибка при открытии выходного файла для записи.");
        return;
    }
    outFile.write((char*)encrypted.data(), encrypted.size());
    if (!outFile) {
        showMessageN("Ошибка записи в выходной файл.");
        return;
    }
    showMessageN("Файл был успешно зашифрован и сохранен в: " + outputFile);
}
void handleAESDecryption(HWND hwnd) {
    std::string keyFile, ivFile, inputFile, outputFile;
    keyFile = openFileDialog(hwnd, "Выберите файл ключа AES");
    if (keyFile.empty()) {
        showMessageN("Выбор ключевого файла AES был отменен.");
        return;
    }
    ivFile = openFileDialog(hwnd, "Выберите файл IV");
    if (ivFile.empty()) {
        showMessageN("IV выбор файла был отменен.");
        return;
    }
    inputFile = openFileDialog(hwnd, "Выберите файл для расшифровки");
    if (inputFile.empty()) {
        showMessageN("Выбор входного файла был отменен.");
        return;
    }
    outputFile = openFileDialog(hwnd, "Выберите файл для сохранения расшифрованных данных");
    if (outputFile.empty()) {
        showMessageN("Выбор выходного файла был отменен.");
        return;
    }
    std::vector<unsigned char> key(32), iv(16);
    std::ifstream keyIn(keyFile, std::ios::binary);
    if (!keyIn || !keyIn.read((char*)key.data(), key.size())) {
        showMessageN("Ошибка при чтении ключевого файла AES.");
        return;
    }
    std::ifstream ivIn(ivFile, std::ios::binary);
    if (!ivIn || !ivIn.read((char*)iv.data(), iv.size())) {
        showMessageN("Ошибка при чтении ключевого файла AES.");
        return;
    }
    // Чтение зашифрованного содержимого файла
    std::ifstream fileIn(inputFile, std::ios::binary);
    if (!fileIn) {
        showMessageN("Ошибка при открытии входного файла.");
        return;
    }
    std::vector<unsigned char> encryptedData((std::istreambuf_iterator<char>(fileIn)), std::istreambuf_iterator<char>());
    // Расшифрование данных
    std::string decrypted = aesDecrypt(encryptedData, key, iv);
    if (decrypted.empty()) {
        showMessageN("Расшифровка не удалась.");
        return;
    }
    // Запись расшифрованных данных в файл
    std::ofstream outFile(outputFile, std::ios::binary);
    if (!outFile) {
        showMessageN("Ошибка при открытии выходного файла для записи.");
        return;
    }
    outFile.write(decrypted.data(), decrypted.size());
    if (!outFile) {
        showMessageN("Ошибка записи в выходной файл.");
        return;
    }
    showMessageN("Файл был успешно расшифрован и сохранен в: " + outputFile);
}

void handleMessageSigning(HWND hwnd) {
    // 1. Выбор зашифрованного приватного ключа
    std::string encryptedPrivateKeyPath = openFileDialog(hwnd, "Выберите зашифрованный закрытый ключ ECDSA");
    if (encryptedPrivateKeyPath.empty()) {
        showMessageN("Выбор зашифрованного файла с закрытым ключом ECDSA был отменен.");
        return;
    }

    // 2. Ввод ключа и IV
    std::string keyIvString;
    if (DialogBoxParam(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_DIALOG1), hwnd, DialogProc, (LPARAM)&keyIvString) != IDOK) {
        MessageBox(hwnd, "Key and IV input cancelled.", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    size_t colonPos = keyIvString.find(':');
    if (colonPos == std::string::npos) {
        MessageBox(hwnd, "Invalid format. Please enter the key and IV separated by a colon.", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    std::string keyHex = keyIvString.substr(0, colonPos);
    std::string ivHex = keyIvString.substr(colonPos + 1);
    std::vector<unsigned char> key = hexStringToBytes(keyHex);
    std::vector<unsigned char> iv = hexStringToBytes(ivHex);

    // Чтение зашифрованного приватного ключа
    std::ifstream encryptedPrivateKeyIn(encryptedPrivateKeyPath, std::ios::binary);
    if (!encryptedPrivateKeyIn) {
        showMessageN("Ошибка: Не удается прочитать зашифрованный файл с закрытым ключом.");
        return;
    }

    std::vector<unsigned char> encryptedKey((std::istreambuf_iterator<char>(encryptedPrivateKeyIn)), std::istreambuf_iterator<char>());
    encryptedPrivateKeyIn.close();

    // Расшифровка приватного ключа
    std::string decryptedKey = aesDecrypt(encryptedKey, key, iv);
    if (decryptedKey.empty()) {
        showMessageN("Ошибка: Не удалось расшифровать файл.");
        return;
    }

    // Сохранение расшифрованного ключа во временный файл
    std::string tempDecryptedKeyPath = "temp_decrypted_key.pem";
    std::ofstream decryptedPrivateKeyOut(tempDecryptedKeyPath, std::ios::trunc);
    if (!decryptedPrivateKeyOut) {
        showMessageN("Ошибка при сохранении расшифрованного закрытого ключа.");
        return;
    }
    decryptedPrivateKeyOut << decryptedKey;
    decryptedPrivateKeyOut.close();

    // 3. Выбор файла для подписи
    std::string inputFile = openFileDialog(hwnd, "Выберите файл для подписи");
    if (inputFile.empty()) {
        showMessageN("Выбор входного файла был отменен.");
        // Удаляем временный файл, если подпись не производится
        std::remove(tempDecryptedKeyPath.c_str());
        return;
    }

    // 4. Выбор пути для сохранения подписи
    std::string outputFile = openFileDialog(hwnd, "Выберите файл для сохранения подписи");
    if (outputFile.empty()) {
        showMessageN("Выбор выходного файла был отменен.");
        // Удаляем временный файл, если подпись не производится
        std::remove(tempDecryptedKeyPath.c_str());
        return;
    }

    // Генерация подписи
    std::vector<unsigned char> signature = signFile(inputFile, tempDecryptedKeyPath);
    std::string hexSignature;
    for (unsigned char c : signature) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02X", c);
        hexSignature += hex;
    }

    // Сохранение подписи
    std::ofstream outFile(outputFile);
    if (!outFile) {
        showMessageN("Ошибка при открытии файла для записи.");
        std::remove(tempDecryptedKeyPath.c_str());
        return;
    }
    outFile << hexSignature;
    if (!outFile) {
        showMessageN("Ошибка записи в файл.");
        std::remove(tempDecryptedKeyPath.c_str());
        return;
    }

    // Удаление временного файла
    std::remove(tempDecryptedKeyPath.c_str());

    showMessageN("Подпись была успешно сохранена в файле: " + outputFile);
}

void handleSignatureVerification(HWND hwnd) {
    std::string publicKeyFile;
    std::string inputFile;
    std::string signatureFile;
    inputFile = openFileDialog(hwnd, "Выберите файл для проверки");
    if (inputFile.empty()) {
        showMessageN("Выбор входного файла был отменен.");
        return;
    }
    publicKeyFile = openFileDialog(hwnd, "Выберите открытый ключ ECDSA");
    if (publicKeyFile.empty()) {
        showMessageN("Выбор файла с открытым ключом отменен или завершился ошибкой.");
        return;
    }
    signatureFile = openFileDialog(hwnd, "Выберите файл подписи");
    if (signatureFile.empty()) {
        showMessageN("Выбор файла подписи был отменен.");
        return;
    }
    // Чтение подписи из файла
    std::ifstream sigFileIn(signatureFile);
    if (!sigFileIn) {
        showMessageN("Выбор файла подписи был отменен.");
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
        showMessageN("Подпись действительна.");
    } else {
        showMessageN("Подпись не действительна.");
    }
}
void handleCompleteDecryption(HWND hwnd) {
    // 1. Выбор зашифрованного приватного ключа
    std::string encryptedPrivateKeyPath = openFileDialog(hwnd, "Выберите зашифрованный закрытый ключ RSA");
    if (encryptedPrivateKeyPath.empty()) {
        showMessageN("Выбор зашифрованного файла с закрытым ключом RSA был отменен.");
        return;
    }

    // 2. Ввод ключа и IV
    std::string keyIvString;
    if (DialogBoxParam(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_DIALOG1), hwnd, DialogProc, (LPARAM)&keyIvString) != IDOK) {
        MessageBox(hwnd, "Key and IV input cancelled.", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    size_t colonPos = keyIvString.find(':');
    if (colonPos == std::string::npos) {
        MessageBox(hwnd, "Invalid format. Please enter the key and IV separated by a colon.", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    std::string keyHex = keyIvString.substr(0, colonPos);
    std::string ivHex = keyIvString.substr(colonPos + 1);
    std::vector<unsigned char> key = hexStringToBytes(keyHex);
    std::vector<unsigned char> iv = hexStringToBytes(ivHex);

    // Чтение зашифрованного приватного ключа
    std::ifstream encryptedPrivateKeyIn(encryptedPrivateKeyPath, std::ios::binary);
    if (!encryptedPrivateKeyIn) {
        showMessageN("Ошибка: Не удается прочитать зашифрованный файл с закрытым ключом.");
        return;
    }

    std::vector<unsigned char> encryptedKey((std::istreambuf_iterator<char>(encryptedPrivateKeyIn)), std::istreambuf_iterator<char>());
    encryptedPrivateKeyIn.close();

    // Расшифровка приватного ключа
    std::string decryptedKey = aesDecrypt(encryptedKey, key, iv);
    if (decryptedKey.empty()) {
        showMessageN("Ошибка: Не удалось расшифровать файл.");
        return;
    }

    // Сохранение расшифрованного приватного ключа во временный файл
    std::string tempDecryptedKeyPath = "temp_decrypted_key.pem";
    std::ofstream decryptedPrivateKeyOut(tempDecryptedKeyPath, std::ios::trunc);
    if (!decryptedPrivateKeyOut) {
        showMessageN("Ошибка при сохранении расшифрованного закрытого ключа.");
        return;
    }
    decryptedPrivateKeyOut << decryptedKey;
    decryptedPrivateKeyOut.close();

    // 3. Выбор файла для расшифровки
    std::string inputFile = openFileDialog(hwnd, "Выберите файл для расшифровки");
    if (inputFile.empty()) {
        showMessageN("Выбор входного файла был отменен.");
        return;
    }

    // 4. Выбор пути для сохранения расшифрованного файла
    std::string outputFile = openFileDialog(hwnd, "Выберите файл для сохранения расшифрованных данных");
    if (outputFile.empty()) {
        showMessageN("Выбор выходного файла был отменен.");
        return;
    }

    // Чтение зашифрованного содержимого файла
    std::ifstream fileIn(inputFile, std::ios::binary);
    if (!fileIn) {
        showMessageN("Ошибка при открытии входного файла.");
        return;
    }
    std::vector<unsigned char> encryptedData((std::istreambuf_iterator<char>(fileIn)), std::istreambuf_iterator<char>());

    // Расшифрование данных с использованием расшифрованного приватного ключа
    std::vector<unsigned char> decryptedRSA = rsaDecryptFile(encryptedData, tempDecryptedKeyPath);

    // Запись расшифрованных данных в файл
    std::ofstream outFile(outputFile, std::ios::binary);
    if (!outFile) {
        showMessageN("Ошибка при открытии выходного файла для записи.");
        return;
    }
    outFile.write((char*)decryptedRSA.data(), decryptedRSA.size());
    if (!outFile) {
        showMessageN("Ошибка записи в выходной файл.");
        return;
    }

    // Удаление временного файла
    std::remove(tempDecryptedKeyPath.c_str());

    showMessageN("Файл был успешно расшифрован и сохранен в: " + outputFile);
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
                    handleCompleteDecryption(hwnd);
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
            0, CLASS_NAME, "Menu", WS_OVERLAPPEDWINDOW,
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
LRESULT CALLBACK PasswordWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            // Создание текстового поля для отображения пароля
            CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | ES_READONLY,
                           10, 50, 755, 30, hwnd, (HMENU)IDC_EDIT_PASSWORD, GetModuleHandle(NULL), NULL);
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
    HWND hwnd = CreateWindowEx(0, "PasswordWindowClass", "It's secret", WS_OVERLAPPEDWINDOW,
                               CW_USEDEFAULT, CW_USEDEFAULT, 815, 200, NULL, NULL, GetModuleHandle(NULL), NULL);
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

    // Генерация AES-ключа и IV
    auto keyAndIVHex = generateKeyAndIV();
    if (keyAndIVHex.first.empty() || keyAndIVHex.second.empty()) {
        std::cerr << "Ошибка генерации ключа или IV." << std::endl;
        return 1;
    }
    // Объединяем ключ и IV в одну строку
    std::string password = keyAndIVHex.first + ":" + keyAndIVHex.second;
    showMessageN("Сфоткай, запиши на листок или как-то по другому запомни следующее окно.");
    // Показ пароля пользователю
    showPassword(password);
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