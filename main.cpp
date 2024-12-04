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
#include <thread>

#define IDC_EDIT_MESSAGE 101
#define IDC_BUTTON_OK 102
#define _CRT_SECURE_NO_WARNINGS

std::string messageN;

LRESULT CALLBACK MessageInputWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            // Создание поля для ввода сообщения (многострочное поле)
            CreateWindowEx(0, "EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL,
                           50, 50, 300, 100, hwnd, (HMENU)IDC_EDIT_MESSAGE, GetModuleHandle(NULL), NULL);

            // Создание кнопки "OK"
            CreateWindow("BUTTON", "OK", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                         150, 170, 100, 30, hwnd, (HMENU)IDC_BUTTON_OK, GetModuleHandle(NULL), NULL);
            break;
        }
        case WM_COMMAND: {
            if (LOWORD(wParam) == IDC_BUTTON_OK) {
                // Получение текста из поля ввода, когда нажата кнопка "OK"
                char buffer[1024];
                HWND hEdit = GetDlgItem(hwnd, IDC_EDIT_MESSAGE);
                GetWindowText(hEdit, buffer, sizeof(buffer));
                messageN = buffer;  // Сохраняем введенное сообщение в глобальную переменную

                // Закрытие окна после получения текста
                PostMessage(hwnd, WM_CLOSE, 0, 0);
            }
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


// Функция для отображения сообщения
void showMessageN(const std::string& message) {
    // Преобразуем строку в юникод
    std::wstring wmessage = std::wstring(message.begin(), message.end());

    // Используем MessageBoxW
    MessageBoxW(NULL, wmessage.c_str(), L"Info", MB_OK | MB_ICONINFORMATION);
}

const std::string CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

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

// Чтение содержимого файла в вектор байтов
std::vector<unsigned char> readFileToVector(const std::string& filename, size_t size) {
    std::ifstream file(filename, std::ios::binary);
    std::vector<unsigned char> buffer(size);
    if (file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        return buffer;
    }
    return {};
}

void handleRSACryptoEncryption(HWND hwnd) {
    std::string publicKeyFile;
    std::string outputFile;

    publicKeyFile = openFileDialog(hwnd, "Select the RSA public key");
    std::cout << publicKeyFile << "\n";

    const char* className = "MessageInputWindow";
    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = MessageInputWindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = className;
    RegisterClass(&wc);

    HWND inputWindow = CreateWindowEx(0, className, "Enter Message", WS_OVERLAPPEDWINDOW,
                                      CW_USEDEFAULT, CW_USEDEFAULT, 400, 300, NULL, NULL, wc.hInstance, NULL);

    if (inputWindow == NULL) {
        showMessageN("Failed to create input window.");
        return;
    }

    ShowWindow(inputWindow, SW_SHOWNORMAL);
    UpdateWindow(inputWindow);

    MSG msg = { 0 };
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    std::cout << "Message for encryption: " << messageN << std::endl;

    outputFile = openFileDialog(hwnd, "Select the file to save the encrypted message");
    std::cout << outputFile << "\n";

    std::vector<unsigned char> encryptedRSA = rsaEncryptBinary(messageN, publicKeyFile);

    std::string hexEncrypted;
    for (unsigned char c : encryptedRSA) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02X", c);
        hexEncrypted += hex;
    }

    std::ofstream outFile(outputFile);
    if (!outFile) {
        showMessageN("Error opening the file for writing.");
        return;
    }

    outFile << hexEncrypted;
    if (!outFile) {
        showMessageN("Error writing to the file.");
        return;
    }

    showMessageN("The encrypted RSA message has been successfully saved to a file: " + outputFile);
}




void handleRSAKeyGeneration(const std::string& entropyData) {
    generateRSAKeys(entropyData, "my_rsa_keys");
    showMessageN("RSA keys have been successfully generated and saved as 'my_rsa_keys'.");
}


void handleAESKeyGeneration() {
    const std::string keyFile = "my_aes_key.txt";
    const std::string ivFile = "my_aes_iv.txt";

    generateAESKeys(keyFile, ivFile);

    showMessageN("AES keys and IV have been successfully generated and saved as 'my_aes_key.txt' and 'my_aes_iv.txt'.");
}

void handleECDSAKeyGeneration() {
    const std::string privateKeyFile = "ecdsa_private_key.pem";
    const std::string publicKeyFile = "ecdsa_public_key.pem";

    generateECDSAKeys(privateKeyFile, publicKeyFile);

    showMessageN("ECDSA private and public keys have been successfully generated and saved as 'ecdsa_private_key.pem' and 'ecdsa_public_key.pem'.");
}

void handleRSACryptoDecryption(HWND hwnd) {
    std::string privateKeyFile;

    privateKeyFile = openFileDialog(hwnd, "Select the RSA private key");
    std::cout << privateKeyFile << "\n";

    const char* className = "EncryptedMessageInputWindow";
    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = MessageInputWindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = className;
    RegisterClass(&wc);

    HWND inputWindow = CreateWindowEx(0, className, "Enter Encrypted Message", WS_OVERLAPPEDWINDOW,
                                      CW_USEDEFAULT, CW_USEDEFAULT, 400, 300, NULL, NULL, wc.hInstance, NULL);

    if (inputWindow == NULL) {
        showMessageN("Failed to create input window.");
        return;
    }

    ShowWindow(inputWindow, SW_SHOWNORMAL);
    UpdateWindow(inputWindow);

    MSG msg = { 0 };
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    std::cout << "Encrypted message for decryption: " << messageN << std::endl;

    std::vector<unsigned char> encryptedData;
    for (size_t i = 0; i < messageN.length(); i += 2) {
        std::string byteString = messageN.substr(i, 2);
        char byte = (char) strtol(byteString.c_str(), NULL, 16);
        encryptedData.push_back(byte);
    }

    std::string decryptedRSA = rsaDecryptBinary(encryptedData, privateKeyFile);

    showMessageN("Decrypted RSA message: " + decryptedRSA);
}

void handleAESEncryption(HWND hwnd) {
    std::string keyFile, ivFile, message, outputFile;

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

    const char* className = "MessageInputWindow";
    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = MessageInputWindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = className;
    RegisterClass(&wc);

    HWND inputWindow = CreateWindowEx(0, className, "Enter Message", WS_OVERLAPPEDWINDOW,
                                      CW_USEDEFAULT, CW_USEDEFAULT, 400, 300, NULL, NULL, wc.hInstance, NULL);

    if (inputWindow == NULL) {
        showMessageN("Failed to create input window.");
        return;
    }

    ShowWindow(inputWindow, SW_SHOWNORMAL);
    UpdateWindow(inputWindow);

    MSG msg = { 0 };
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    if (messageN.empty()) {
        showMessageN("No message entered for encryption.");
        return;
    }

    outputFile = openFileDialog(hwnd, "Select the file to save the encrypted message");
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

    std::vector<unsigned char> encrypted = aesEncrypt(messageN, key, iv);

    std::string hexEncrypted;
    for (unsigned char c : encrypted) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02X", c);
        hexEncrypted += hex;
    }

    std::ofstream outFile(outputFile);
    if (!outFile) {
        showMessageN("Error opening the file for writing.");
        return;
    }

    outFile << hexEncrypted;
    if (!outFile) {
        showMessageN("Error writing to the file.");
        return;
    }

    showMessageN("The encrypted message has been successfully saved to the file: " + outputFile);
}

void handleAESDecryption(HWND hwnd) {
    std::string keyFile, ivFile;

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

    const char* className = "EncryptedMessageInputWindow";
    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = MessageInputWindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = className;
    RegisterClass(&wc);

    HWND inputWindow = CreateWindowEx(0, className, "Enter Encrypted Message (Hex Format)", WS_OVERLAPPEDWINDOW,
                                      CW_USEDEFAULT, CW_USEDEFAULT, 400, 300, NULL, NULL, wc.hInstance, NULL);

    if (inputWindow == NULL) {
        showMessageN("Failed to create input window.");
        return;
    }

    ShowWindow(inputWindow, SW_SHOWNORMAL);
    UpdateWindow(inputWindow);

    MSG msg = { 0 };
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    if (messageN.empty()) {
        showMessageN("No encrypted message provided.");
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

    std::vector<unsigned char> encryptedData;
    for (size_t i = 0; i < messageN.length(); i += 2) {
        std::string byteString = messageN.substr(i, 2);
        unsigned char byte = (unsigned char)strtol(byteString.c_str(), nullptr, 16);
        encryptedData.push_back(byte);
    }

    std::string decrypted = aesDecrypt(encryptedData, key, iv);
    if (decrypted.empty()) {
        showMessageN("Decryption failed.");
        return;
    }

    showMessageN("Decrypted message: " + decrypted);
}

void handleMessageSigning(HWND hwnd) {
    std::string privateKeyFile;
    std::string outputFile;

    const char* className = "MessageInputWindow";
    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = MessageInputWindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = className;
    RegisterClass(&wc);

    HWND inputWindow = CreateWindowEx(0, className, "Enter Message for Signing", WS_OVERLAPPEDWINDOW,
                                      CW_USEDEFAULT, CW_USEDEFAULT, 400, 300, NULL, NULL, wc.hInstance, NULL);

    if (inputWindow == NULL) {
        showMessageN("Failed to create input window.");
        return;
    }

    ShowWindow(inputWindow, SW_SHOWNORMAL);
    UpdateWindow(inputWindow);

    MSG msg = { 0 };
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    if (messageN.empty()) {
        showMessageN("No message provided for signing.");
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

    std::vector<unsigned char> signature = signMessage(messageN, privateKeyFile);

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
    std::string hexSignature;

    // Открытие диалогового окна для выбора публичного ключа
    publicKeyFile = openFileDialog(hwnd, "Select the ECDSA public key");
    if (publicKeyFile.empty()) {
        showMessageN("Public key file selection canceled or failed.");
        return;
    }

    // Создание окна для ввода сообщения
    const char* className = "MessageInputWindow";
    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = MessageInputWindowProc; // Обработчик окна для ввода
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = className;
    RegisterClass(&wc);

    HWND inputWindow = CreateWindowEx(0, className, "Enter message for signature verification", WS_OVERLAPPEDWINDOW,
                                      CW_USEDEFAULT, CW_USEDEFAULT, 400, 300, NULL, NULL, wc.hInstance, NULL);
    if (!inputWindow) {
        showMessageN("Failed to create message input window.");
        return;
    }

    ShowWindow(inputWindow, SW_SHOWNORMAL);
    UpdateWindow(inputWindow);

    // Цикл обработки сообщений окна ввода
    MSG msg = { 0 };
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // Проверка наличия введенного сообщения
    if (messageN.empty()) {
        showMessageN("Message input was canceled or empty.");
        return;
    }


    // Создание окна для ввода сообщения
    const char* className_ = "SignatureInputWindow";
    WNDCLASS wc_ = { 0 };
    wc_.lpfnWndProc = MessageInputWindowProc; // Обработчик окна для ввода
    wc_.hInstance = GetModuleHandle(NULL);
    wc_.lpszClassName = className_;
    RegisterClass(&wc_);

    HWND inputWindow_ = CreateWindowEx(0, className_, "Enter signature in hexadecimal format", WS_OVERLAPPEDWINDOW,
                                       CW_USEDEFAULT, CW_USEDEFAULT, 400, 300, NULL, NULL, wc_.hInstance, NULL);
    if (!inputWindow_) {
        showMessageN("Failed to create signature input window.");
        return;
    }

    ShowWindow(inputWindow_, SW_SHOWNORMAL);
    UpdateWindow(inputWindow_);

    // Цикл обработки сообщений окна ввода
    MSG msg_ = { 0 };
    while (GetMessage(&msg_, NULL, 0, 0)) {
        TranslateMessage(&msg_);
        DispatchMessage(&msg_);
    }
    hexSignature = messageN;
    // Проверка наличия введенной подписи
    if (hexSignature.empty()) {
        showMessageN("Signature input was canceled or empty.");
        return;
    }

    // Преобразование HEX-строки в бинарный формат
    std::vector<unsigned char> signature;
    for (size_t i = 0; i < hexSignature.length(); i += 2) {
        std::string byteString = hexSignature.substr(i, 2);
        unsigned char byte = (unsigned char)strtol(byteString.c_str(), nullptr, 16);
        signature.push_back(byte);
    }

    // Верификация подписи
    bool valid = verifySignature(messageN, signature, publicKeyFile);
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
                    handleRSAKeyGeneration(entropyData);
                    break;
                case 2: // Генерация AES ключей
                    handleAESKeyGeneration();
                    break;
                case 3: // Генерация ECDSA ключей
                    handleECDSAKeyGeneration();
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
            CW_USEDEFAULT, CW_USEDEFAULT, 315, 510, nullptr, nullptr, hInstance, nullptr
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

    CreateWindow("BUTTON", "Generate RSA Keys", WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                 x, y, buttonWidth, buttonHeight, hwnd, (HMENU)1, hInstance, nullptr);

    y += buttonHeight + spacing;
    CreateWindow("BUTTON", "Generate AES Keys", WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                 x, y, buttonWidth, buttonHeight, hwnd, (HMENU)2, hInstance, nullptr);

    y += buttonHeight + spacing;
    CreateWindow("BUTTON", "Generate ECDSA Keys", WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                 x, y, buttonWidth, buttonHeight, hwnd, (HMENU)3, hInstance, nullptr);

    y += buttonHeight + spacing;
    CreateWindow("BUTTON", "RSA Encryption", WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                 x, y, buttonWidth, buttonHeight, hwnd, (HMENU)4, hInstance, nullptr);

    y += buttonHeight + spacing;
    CreateWindow("BUTTON", "RSA Decryption", WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                 x, y, buttonWidth, buttonHeight, hwnd, (HMENU)5, hInstance, nullptr);

    y += buttonHeight + spacing;
    CreateWindow("BUTTON", "AES Encryption", WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                 x, y, buttonWidth, buttonHeight, hwnd, (HMENU)6, hInstance, nullptr);

    y += buttonHeight + spacing;
    CreateWindow("BUTTON", "AES Decryption", WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                 x, y, buttonWidth, buttonHeight, hwnd, (HMENU)7, hInstance, nullptr);

    y += buttonHeight + spacing;
    CreateWindow("BUTTON", "ECDSA Sign Message", WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                 x, y, buttonWidth, buttonHeight, hwnd, (HMENU)8, hInstance, nullptr);

    y += buttonHeight + spacing;
    CreateWindow("BUTTON", "ECDSA Verify Signature", WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                 x, y, buttonWidth, buttonHeight, hwnd, (HMENU)9, hInstance, nullptr);

    y += buttonHeight + spacing;
    CreateWindow("BUTTON", "Exit", WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
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

    showMessage("Move the mouse to collect entropy...");

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


// Основная функция
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