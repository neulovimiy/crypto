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
const std::string CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

// Глобальная переменная для хранения процента прогресса
int progressPercent = 0;

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

// Создание окна прогресса
HWND CreateProgressWindow(HINSTANCE hInstance) {
    WNDCLASSEX wc = { 0 };  // Zero initialize the structure
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

    HWND hwnd = CreateWindowEx(WS_EX_OVERLAPPEDWINDOW,
                               "ProgressWindowClass",  // Class name
                               "Process...",    // Window title
                               WS_OVERLAPPEDWINDOW,   // Window style
                               CW_USEDEFAULT, CW_USEDEFAULT,
                               400, 200,              // Window size
                               NULL, NULL,
                               hInstance, NULL);

    if (hwnd == NULL) {
        MessageBoxA(NULL, "Ошибка создания окна", "Ошибка", MB_OK | MB_ICONERROR);
        return NULL;
    }

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
    return hwnd;
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

void showMenu() {
    std::cout << "Выберите действие:" << std::endl;
    std::cout << "1. Генерация ключей RSA" << std::endl;
    std::cout << "2. Генерация ключей AES" << std::endl;
    std::cout << "3. Генерация ключей ECC" << std::endl;
    std::cout << "4. Зашифровать RSA" << std::endl;
    std::cout << "5. Расшифровать RSA" << std::endl;
    std::cout << "6. Зашифровать AES" << std::endl;
    std::cout << "7. Расшифровать AES" << std::endl;
    std::cout << "8. Подписать ECDSA" << std::endl;
    std::cout << "9. Проверить подпись ECDSA" << std::endl;
    std::cout << "10. Выход" << std::endl;
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    // Инициализация библиотеки OpenSSL
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);

    int maxDurationMs = 60000;
    int intervalMs = 10;
    int minMovements = 100;

    // Сбор энтропии с помощью движения мыши
    std::string entropyData = collectMouseEntropy(maxDurationMs, intervalMs, minMovements);

    if (!entropyData.empty()) {
        int choice = 0;

        do {
            showMenu();
            std::cout << "Введите номер действия: ";

            // Проверка на корректность ввода
            if (!(std::cin >> choice)) {
                std::cerr << "Неверный ввод. Введите число.\n";

                // Очистка потока и сброс состояния ошибки
                std::cin.clear();
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                continue;
            }

            // Обработка выбора пользователя
            switch (choice) {
                case 1:
                    generateRSAKeys(entropyData, "my_rsa_keys");
                    break;
                case 2: {
                    const std::string keyFile = "my_aes_key.txt";
                    const std::string ivFile = "my_aes_iv.txt";

                    generateAESKeys(keyFile, ivFile);
                    break;
                }

                case 3: {
                    const std::string privateKeyFile = "ecdsa_private_key.pem";
                    const std::string publicKeyFile = "ecdsa_public_key.pem";
                    generateECDSAKeys(privateKeyFile, publicKeyFile);
                    break;
                }
                case 4: {
                    std::string publicKeyFile;
                    std::string message;
                    std::string outputFile; // Добавляем переменную для имени выходного файла

                    std::cout << "Введите путь к публичному ключу RSA: ";
                    std::cin.ignore();
                    std::getline(std::cin, publicKeyFile);

                    std::cout << "Введите сообщение для шифрования: ";
                    std::getline(std::cin, message);

                    std::cout << "Введите путь к файлу для сохранения зашифрованного сообщения: ";
                    std::getline(std::cin, outputFile);

                    std::vector<unsigned char> encryptedRSA = rsaEncryptBinary(message, publicKeyFile);

                    // Преобразование зашифрованного сообщения в шестнадцатеричный формат
                    std::string hexEncrypted;
                    for (unsigned char c : encryptedRSA) {
                        char hex[3];
                        snprintf(hex, sizeof(hex), "%02X", c);
                        hexEncrypted += hex;
                    }

                    // Запись зашифрованного сообщения в файл
                    std::ofstream outFile(outputFile);
                    if (!outFile) {
                        std::cerr << "Ошибка открытия файла для записи." << std::endl;
                        break;
                    }

                    outFile << hexEncrypted;
                    if (!outFile) {
                        std::cerr << "Ошибка записи в файл." << std::endl;
                        break;
                    }

                    std::cout << "Зашифрованное RSA сообщение успешно сохранено в файл: " << outputFile << std::endl;
                    break;
                }
                case 5: {
                    std::string privateKeyFile;
                    std::string encryptedMessage;
                    std::cout << "Введите путь к приватному ключу RSA: ";
                    std::cin.ignore();
                    std::getline(std::cin, privateKeyFile);
                    std::cout << "Введите зашифрованное сообщение в шестнадцатеричном формате: ";
                    std::getline(std::cin, encryptedMessage);

                    std::vector<unsigned char> encryptedData;
                    for (size_t i = 0; i < encryptedMessage.length(); i += 2) {
                        std::string byteString = encryptedMessage.substr(i, 2);
                        char byte = (char) strtol(byteString.c_str(), NULL, 16);
                        encryptedData.push_back(byte);
                    }

                    std::string decryptedRSA = rsaDecryptBinary(encryptedData, privateKeyFile);
                    std::cout << "Расшифрованное RSA сообщение: " << decryptedRSA << std::endl;
                    break;
                }
                case 6: {
                    std::string keyFile, ivFile, message;
                    std::string outputFile; // Добавляем переменную для имени выходного файла

                    std::cout << "Введите путь к файлу с AES ключом: ";
                    std::cin.ignore();
                    std::getline(std::cin, keyFile);

                    std::cout << "Введите путь к файлу с IV: ";
                    std::getline(std::cin, ivFile);

                    std::cout << "Введите сообщение для шифрования: ";
                    std::getline(std::cin, message);

                    std::cout << "Введите путь к файлу для сохранения зашифрованного сообщения: ";
                    std::getline(std::cin, outputFile);

                    std::vector<unsigned char> key(32), iv(16);

                    // Считывание ключа
                    std::ifstream keyIn(keyFile, std::ios::binary);
                    if (!keyIn || !keyIn.read((char*)key.data(), key.size())) {
                        std::cerr << "Ошибка чтения ключа." << std::endl;
                        break;
                    }

                    // Считывание IV
                    std::ifstream ivIn(ivFile, std::ios::binary);
                    if (!ivIn || !ivIn.read((char*)iv.data(), iv.size())) {
                        std::cerr << "Ошибка чтения IV." << std::endl;
                        break;
                    }

                    // Шифрование
                    std::vector<unsigned char> encrypted = aesEncrypt(message, key, iv);

                    // Преобразование зашифрованного сообщения в шестнадцатеричный формат
                    std::string hexEncrypted;
                    for (unsigned char c : encrypted) {
                        char hex[3];
                        snprintf(hex, sizeof(hex), "%02X", c);
                        hexEncrypted += hex;
                    }

                    // Запись зашифрованного сообщения в файл
                    std::ofstream outFile(outputFile);
                    if (!outFile) {
                        std::cerr << "Ошибка открытия файла для записи." << std::endl;
                        break;
                    }

                    outFile << hexEncrypted;
                    if (!outFile) {
                        std::cerr << "Ошибка записи в файл." << std::endl;
                        break;
                    }

                    std::cout << "Зашифрованное сообщение успешно сохранено в файл: " << outputFile << std::endl;
                    break;
                }


                case 7: {
                    std::string keyFile, ivFile, encryptedMessage;
                    std::cout << "Введите путь к файлу с AES ключом: ";
                    std::cin.ignore();
                    std::getline(std::cin, keyFile);

                    std::cout << "Введите путь к файлу с IV: ";
                    std::getline(std::cin, ivFile);

                    std::cout << "Введите зашифрованное сообщение в шестнадцатеричном формате: ";
                    std::getline(std::cin, encryptedMessage);

                    std::vector<unsigned char> key(32), iv(16);

                    // Считывание ключа
                    std::ifstream keyIn(keyFile, std::ios::binary);
                    if (!keyIn || !keyIn.read((char*)key.data(), key.size())) {
                        std::cerr << "Ошибка чтения ключа." << std::endl;
                        break;
                    }

                    // Считывание IV
                    std::ifstream ivIn(ivFile, std::ios::binary);
                    if (!ivIn || !ivIn.read((char*)iv.data(), iv.size())) {
                        std::cerr << "Ошибка чтения IV." << std::endl;
                        break;
                    }

                    // Преобразование HEX-строки в бинарные данные
                    std::vector<unsigned char> encryptedData;
                    for (size_t i = 0; i < encryptedMessage.length(); i += 2) {
                        std::string byteString = encryptedMessage.substr(i, 2);
                        unsigned char byte = (unsigned char)strtol(byteString.c_str(), nullptr, 16);
                        encryptedData.push_back(byte);
                    }

                    // Расшифрование
                    std::string decrypted = aesDecrypt(encryptedData, key, iv);
                    if (decrypted.empty()) {
                        std::cerr << "Ошибка завершения расшифрования." << std::endl;
                        break;
                    }

                    std::cout << "Расшифрованное сообщение: " << decrypted << std::endl;
                    break;
                }

                case 8: {
                    std::string message;
                    std::string privateKeyFile;
                    std::string outputFile; // Добавляем переменную для имени выходного файла

                    std::cout << "Введите сообщение для подписи: ";
                    std::cin.ignore();
                    std::getline(std::cin, message);

                    std::cout << "Введите путь к приватному ключу ECDSA: ";
                    std::getline(std::cin, privateKeyFile);

                    std::cout << "Введите путь к файлу для сохранения подписи: ";
                    std::getline(std::cin, outputFile);

                    std::vector<unsigned char> signature = signMessage(message, privateKeyFile);

                    // Преобразование подписи в шестнадцатеричный формат
                    std::string hexSignature;
                    for (unsigned char c : signature) {
                        char hex[3];
                        snprintf(hex, sizeof(hex), "%02X", c);
                        hexSignature += hex;
                    }

                    // Запись подписи в файл
                    std::ofstream outFile(outputFile);
                    if (!outFile) {
                        std::cerr << "Ошибка открытия файла для записи." << std::endl;
                        break;
                    }

                    outFile << hexSignature;
                    if (!outFile) {
                        std::cerr << "Ошибка записи в файл." << std::endl;
                        break;
                    }

                    std::cout << "Подпись успешно сохранена в файл: " << outputFile << std::endl;
                    break;
                }

                case 9: {
                    std::string message;
                    std::string publicKeyFile;
                    std::string hexSignature;
                    std::cout << "Введите сообщение для проверки подписи: ";
                    std::cin.ignore();
                    std::getline(std::cin, message);

                    std::cout << "Введите путь к публичному ключу ECDSA: ";
                    std::getline(std::cin, publicKeyFile);

                    std::cout << "Введите подпись в шестнадцатеричном формате: ";
                    std::getline(std::cin, hexSignature);

                    std::vector<unsigned char> signature;
                    for (size_t i = 0; i < hexSignature.length(); i += 2) {
                        std::string byteString = hexSignature.substr(i, 2);
                        unsigned char byte = (unsigned char)strtol(byteString.c_str(), nullptr, 16);
                        signature.push_back(byte);
                    }

                    if (verifySignature(message, signature, publicKeyFile)) {
                        std::cout << "Подпись действительна." << std::endl;
                    } else {
                        std::cout << "Подпись недействительна." << std::endl;
                    }
                    break;
                }
                case 10:
                    std::cout << "Выход из программы." << std::endl;
                    break;
                default:
                    std::cout << "Неверный выбор. Попробуйте снова." << std::endl;
            }
        } while (choice != 10);
    } else {
        std::cerr << "Не удалось сгенерировать случайное значение из-за недостаточной энтропии." << std::endl;
    }

    // Очистка данных OpenSSL
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();

    return 0;
}