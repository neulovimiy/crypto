cmake_minimum_required(VERSION 3.29.6)
project(EntropyRSA)

set(CMAKE_CXX_STANDARD 11)

# Указываем файлы исходного кода, включая applink.c
add_executable(EntropyRSA main.cpp rsa_generator.cpp aes_generator.cpp "C:/Program Files/OpenSSL-Win64/include/openssl/applink.c" ecc_ecdsa.cpp)

# Указываем пути к OpenSSL вручную
set(OPENSSL_INCLUDE_DIR "C:/Program Files/OpenSSL-Win64/include")
set(OPENSSL_LIBRARIES "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MD/libssl.lib" "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MD/libcrypto.lib")

# Подключение библиотек и включение директорий
target_include_directories(EntropyRSA PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(EntropyRSA ${OPENSSL_LIBRARIES})

# Подключение библиотек WinAPI
target_link_libraries(EntropyRSA user32 gdi32 comctl32 advapi32 crypt32)