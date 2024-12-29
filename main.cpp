#include <windows.h>
#include <iostream> 
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <filesystem>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <io.h>
#include <fcntl.h>
#include <limits>
#include <cctype>

using namespace std;
using namespace CryptoPP;
namespace fs = std::filesystem;

// Клас для валідації введених даних
class InputValidator {
public:
    static bool validateChoice(int& choice, int min, int maxValue) {
        if (!(wcin >> choice)) {
            wcin.clear();
            std::wcin.ignore(1000, L'\n');
            return false;
        }

        if (choice < min || choice > maxValue) {
            std::wcin.ignore(1000, L'\n');
            return false;
        }

        return true;
    }

    static bool validatePath(const wstring& path, bool shouldExist = true) {
        if (path.empty()) {
            return false;
        }

        try {
            if (shouldExist && !fs::exists(path)) {
                return false;
            }

            fs::path fsPath(path);
            if (!fsPath.has_filename()) {
                return false;
            }

            return true;
        }
        catch (const fs::filesystem_error&) {
            return false;
        }
    }

    static bool validateDirectory(const wstring& path, bool shouldExist = true) {
        try {
            if (shouldExist && !fs::exists(path)) {
                return false;
            }

            if (shouldExist && !fs::is_directory(path)) {
                return false;
            }

            // Перевіряємо права доступу
            if (shouldExist) {
                DWORD attributes = GetFileAttributesW(path.c_str());
                if (attributes == INVALID_FILE_ATTRIBUTES) {
                    return false;
                }
            }

            return true;
        }
        catch (const fs::filesystem_error&) {
            return false;
        }
    }

    static bool hasWritePermission(const wstring& path) {
        try {
            // Спроба створити тимчасовий файл
            wstring testFile = path + L"\\test.tmp";
            ofstream file(testFile);
            if (!file) {
                return false;
            }
            file.close();
            fs::remove(testFile);
            return true;
        }
        catch (...) {
            return false;
        }
    }
};

class FileKeyManager {
private:
    wstring keysPath;
    SecByteBlock masterKey;
    map<string, SecByteBlock> keyCache;

    string calculateFileHash(const vector<char>& content) {
        SHA256 hash;
        vector<CryptoPP::byte> digest(hash.DigestSize());

        hash.CalculateDigest(digest.data(),
            reinterpret_cast<const CryptoPP::byte*>(content.data()),
            content.size());

        string result;
        HexEncoder encoder(new StringSink(result));
        encoder.Put(digest.data(), digest.size());
        encoder.MessageEnd();

        return result;
    }

public:
    struct FileKey {
        SecByteBlock key;
        SecByteBlock iv;

        FileKey() : key(AES::DEFAULT_KEYLENGTH), iv(AES::BLOCKSIZE) {}
    };

    FileKeyManager(const wstring& drivePath, const SecByteBlock& mk)
        : masterKey(mk), keysPath(drivePath + L"\\.keys") {
        CreateDirectoryW(keysPath.c_str(), NULL);
        SetFileAttributesW(keysPath.c_str(), FILE_ATTRIBUTE_HIDDEN);
    }

    pair<SecByteBlock, SecByteBlock> generateNewKey() {
        SecByteBlock key(AES::DEFAULT_KEYLENGTH);
        SecByteBlock iv(AES::BLOCKSIZE);

        AutoSeededRandomPool prng;
        prng.GenerateBlock(key, key.size());
        prng.GenerateBlock(iv, iv.size());

        return { key, iv };
    }

    void encryptAndStoreKey(const SecByteBlock& key, const SecByteBlock& iv, const string& keyId) {
        CBC_Mode<AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(masterKey, masterKey.size(), masterKey.data());

        string combined;
        combined.append(reinterpret_cast<const char*>(key.data()), key.size());
        combined.append(reinterpret_cast<const char*>(iv.data()), iv.size());

        string encrypted;
        StringSource ss(combined, true,
            new StreamTransformationFilter(encryptor,
                new StringSink(encrypted)
            )
        );

        wstring keyPath = keysPath + L"\\" + wstring(keyId.begin(), keyId.end()) + L".key";
        ofstream keyFile(keyPath, ios::binary);
        keyFile.write(encrypted.data(), encrypted.size());
        keyFile.close();
    }

    bool decryptKey(const string& encryptedKey, FileKey& fileKey) {
        try {
            CBC_Mode<AES>::Decryption decryptor;
            decryptor.SetKeyWithIV(masterKey, masterKey.size(), masterKey.data());

            string decrypted;
            StringSource ss(encryptedKey, true,
                new StreamTransformationFilter(decryptor,
                    new StringSink(decrypted)
                )
            );

            if (decrypted.length() < AES::DEFAULT_KEYLENGTH + AES::BLOCKSIZE) {
                wcout << L"Розшифрований ключ має неправильний розмір\n";
                return false;
            }

            fileKey.key = SecByteBlock(
                reinterpret_cast<const CryptoPP::byte*>(decrypted.data()),
                AES::DEFAULT_KEYLENGTH
            );
            fileKey.iv = SecByteBlock(
                reinterpret_cast<const CryptoPP::byte*>(decrypted.data() + AES::DEFAULT_KEYLENGTH),
                AES::BLOCKSIZE
            );

            return true;
        }
        catch (const Exception& e) {
            wcerr << L"Помилка розшифрування ключа: " << e.what() << endl;
            return false;
        }
    }

    string storeFileKey(const vector<char>& content, const SecByteBlock& key, const SecByteBlock& iv) {
        string keyId = calculateFileHash(content);
        encryptAndStoreKey(key, iv, keyId);
        return keyId;
    }
};


class FlashProtection {
private:
    wstring devicePath;
    SecByteBlock masterKey;
    unique_ptr<FileKeyManager> keyManager;

    bool isValidFlashDrive(const wstring& path) {
        if (!InputValidator::validateDirectory(path)) {
            return false;
        }

        wstring keyFilePath = path + L"\\security.key";
        ifstream keyFile(keyFilePath.c_str(), ios::binary);
        if (!keyFile) return false;

        vector<CryptoPP::byte> storedHash(SHA256::DIGESTSIZE);
        keyFile.read(reinterpret_cast<char*>(&storedHash[0]), SHA256::DIGESTSIZE);
        keyFile.close();

        SHA256 hash;
        vector<CryptoPP::byte> calculated(SHA256::DIGESTSIZE);
        string volumeData = getVolumeData(path);
        hash.CalculateDigest(&calculated[0],
            reinterpret_cast<const CryptoPP::byte*>(volumeData.c_str()),
            volumeData.length());

        return memcmp(&calculated[0], &storedHash[0], SHA256::DIGESTSIZE) == 0;
    }

    string getVolumeData(const wstring& path) {
        wchar_t volumeName[MAX_PATH + 1];
        wchar_t fileSystem[MAX_PATH + 1];
        DWORD serialNumber;

        GetVolumeInformation(
            path.c_str(),
            volumeName,
            MAX_PATH + 1,
            &serialNumber,
            nullptr,
            nullptr,
            fileSystem,
            MAX_PATH + 1
        );

        wstring wVolumeName(volumeName);
        string volumeNameStr(wVolumeName.begin(), wVolumeName.end());
        return volumeNameStr + to_string(serialNumber);
    }

    void initializeSecurity(const wstring& path) {
        if (!InputValidator::hasWritePermission(path)) {
            throw runtime_error("Немає прав доступу для ініціалізації безпеки");
        }

        masterKey = SecByteBlock(AES::DEFAULT_KEYLENGTH);
        AutoSeededRandomPool prng;
        prng.GenerateBlock(masterKey, masterKey.size());

        wstring keyFilePath = path + L"\\security.key";
        ofstream keyFile(keyFilePath.c_str(), ios::binary);

        SHA256 hash;
        vector<CryptoPP::byte> calculated(SHA256::DIGESTSIZE);
        string volumeData = getVolumeData(path);
        hash.CalculateDigest(&calculated[0],
            reinterpret_cast<const CryptoPP::byte*>(volumeData.c_str()),
            volumeData.length());

        keyFile.write(reinterpret_cast<char*>(&calculated[0]), calculated.size());
        keyFile.write(reinterpret_cast<const char*>(masterKey.data()), masterKey.size());
        keyFile.close();

        SetFileAttributesW(keyFilePath.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    }

    bool loadSecurity(const wstring& path) {
        wstring keyFilePath = path + L"\\security.key";
        if (!InputValidator::validatePath(keyFilePath)) {
            return false;
        }

        ifstream keyFile(keyFilePath.c_str(), ios::binary);
        if (!keyFile) return false;

        masterKey = SecByteBlock(AES::DEFAULT_KEYLENGTH);

        keyFile.seekg(SHA256::DIGESTSIZE);
        keyFile.read(reinterpret_cast<char*>(masterKey.data()), masterKey.size());
        keyFile.close();

        return true;
    }

public:
    FlashProtection() {}

    bool initialize(const wstring& drivePath) {
        if (!InputValidator::validateDirectory(drivePath)) {
            wcerr << L"Недійсний шлях до накопичувача\n";
            return false;
        }

        devicePath = drivePath;

        if (!isValidFlashDrive(drivePath)) {
            wcout << L"Ініціалізація нового захищеного накопичувача...\n";
            try {
                initializeSecurity(drivePath);
            }
            catch (const exception& e) {
                wcerr << L"Помилка ініціалізації: " << e.what() << endl;
                return false;
            }
        }

        if (!loadSecurity(drivePath)) {
            return false;
        }

        keyManager = make_unique<FileKeyManager>(drivePath, masterKey);
        return true;
    }

    bool encryptFile(const wstring& inputFile, const wstring& outputFile) {
        if (!InputValidator::validatePath(inputFile, true)) {
            wcerr << L"Вхідний файл не існує або недоступний\n";
            return false;
        }

        if (!InputValidator::validatePath(fs::path(outputFile).parent_path(), true)) {
            wcerr << L"Директорія для вихідного файлу не існує\n";
            return false;
        }

        try {
            ifstream inFile(inputFile, ios::binary);
            if (!inFile) {
                wcerr << L"Помилка відкриття вхідного файлу\n";
                return false;
            }

            vector<char> content(
                (istreambuf_iterator<char>(inFile)),
                istreambuf_iterator<char>()
            );
            inFile.close();

            auto [key, iv] = keyManager->generateNewKey();

            CBC_Mode<AES>::Encryption encryptor;
            encryptor.SetKeyWithIV(key, key.size(), iv);

            string encrypted;
            StringSource ss(
                reinterpret_cast<const CryptoPP::byte*>(content.data()),
                content.size(),
                true,
                new StreamTransformationFilter(
                    encryptor,
                    new StringSink(encrypted)
                )
            );

            ofstream outFile(outputFile, ios::binary);
            if (!outFile) {
                wcerr << L"Помилка відкриття вихідного файлу\n";
                return false;
            }
            outFile.write(encrypted.data(), encrypted.size());
            outFile.close();

            keyManager->storeFileKey(content, key, iv);

            return true;
        }
        catch (const Exception& e) {
            wcerr << L"Помилка шифрування: " << e.what() << endl;
            return false;
        }
    }

    bool decryptFile(const wstring& inputFile, const wstring& outputFile) {
        if (!InputValidator::validatePath(inputFile, true)) {
            wcerr << L"Вхідний файл не існує або недоступний\n";
            return false;
        }

        if (!InputValidator::validatePath(fs::path(outputFile).parent_path(), true)) {
            wcerr << L"Директорія для вихідного файлу не існує\n";
            return false;
        }

        try {
            ifstream inFile(inputFile, ios::binary);
            if (!inFile) {
                wcerr << L"Помилка відкриття вхідного файлу\n";
                return false;
            }

            vector<char> encrypted(
                (istreambuf_iterator<char>(inFile)),
                istreambuf_iterator<char>()
            );
            inFile.close();

            bool success = false;
            wstring keysDir = devicePath + L"\\.keys";

            for (const auto& entry : fs::directory_iterator(keysDir)) {
                if (!entry.is_regular_file()) continue;
                if (entry.path().extension() != L".key") continue;

                ifstream keyFile(entry.path(), ios::binary);
                string encryptedKey;
                encryptedKey.assign(
                    istreambuf_iterator<char>(keyFile),
                    istreambuf_iterator<char>()
                );
                keyFile.close();

                FileKeyManager::FileKey fileKey;
                if (!keyManager->decryptKey(encryptedKey, fileKey)) {
                    continue;
                }

                try {
                    CBC_Mode<AES>::Decryption decryptor;
                    decryptor.SetKeyWithIV(fileKey.key, fileKey.key.size(), fileKey.iv);

                    string decrypted;
                    StringSource ss(
                        reinterpret_cast<const CryptoPP::byte*>(encrypted.data()),
                        encrypted.size(),
                        true,
                        new StreamTransformationFilter(
                            decryptor,
                            new StringSink(decrypted)
                        )
                    );

                    ofstream outFile(outputFile, ios::binary);
                    if (!outFile) {
                        wcerr << L"Помилка відкриття вихідного файлу\n";
                        return false;
                    }
                    outFile.write(decrypted.data(), decrypted.size());
                    outFile.close();

                    success = true;
                    break;
                }
                catch (...) {
                    continue;
                }
            }

            if (!success) {
                wcerr << L"Не знайдено відповідного ключа для розшифрування\n";
                return false;
            }

            return true;
        }
        catch (const Exception& e) {
            wcerr << L"Помилка розшифрування: " << e.what() << endl;
            return false;
        }
    }

    bool encryptDirectory(const wstring& inputDir, const wstring& outputDir) {
        if (!InputValidator::validateDirectory(inputDir, true)) {
            wcerr << L"Вхідна директорія не існує або недоступна\n";
            return false;
        }

        try {
            if (!fs::exists(outputDir)) {
                if (!fs::create_directories(outputDir)) {
                    wcerr << L"Не вдалося створити вихідну директорію\n";
                    return false;
                }
            }

            for (const auto& entry : fs::recursive_directory_iterator(inputDir)) {
                if (!entry.is_regular_file()) continue;

                wstring relativePath = entry.path().wstring().substr(inputDir.length());
                wstring outputPath = outputDir + relativePath;

                fs::create_directories(fs::path(outputPath).parent_path());

                if (!encryptFile(entry.path().wstring(), outputPath + L".encrypted")) {
                    return false;
                }
            }

            return true;
        }
        catch (const fs::filesystem_error& e) {
            wcerr << L"Помилка файлової системи: " << e.what() << endl;
            return false;
        }
    }

    bool decryptDirectory(const wstring& inputDir, const wstring& outputDir) {
        if (!InputValidator::validateDirectory(inputDir, true)) {
            wcerr << L"Вхідна директорія не існує або недоступна\n";
            return false;
        }

        try {
            if (!fs::exists(outputDir)) {
                if (!fs::create_directories(outputDir)) {
                    wcerr << L"Не вдалося створити вихідну директорію\n";
                    return false;
                }
            }

            for (const auto& entry : fs::recursive_directory_iterator(inputDir)) {
                if (!entry.is_regular_file()) continue;
                if (entry.path().extension() != L".encrypted") continue;

                wstring relativePath = entry.path().wstring().substr(inputDir.length());
                relativePath = relativePath.substr(0, relativePath.length() - 10); // Remove .encrypted
                wstring outputPath = outputDir + relativePath;

                fs::create_directories(fs::path(outputPath).parent_path());

                if (!decryptFile(entry.path().wstring(), outputPath)) {
                    return false;
                }
            }

            return true;
        }
        catch (const fs::filesystem_error& e) {
            wcerr << L"Помилка файлової системи: " << e.what() << endl;
            return false;
        }
    }

    void showEncryptedFiles() {
        try {
            wstring keysDir = devicePath + L"\\.keys";
            if (!fs::exists(keysDir)) {
                wcout << L"Немає зашифрованих файлів\n";
                return;
            }

            wcout << L"Список зашифрованих файлів:\n";
            for (const auto& entry : fs::directory_iterator(keysDir)) {
                if (entry.is_regular_file()) {
                    wcout << L"- " << entry.path().filename().wstring() << L"\n";
                }
            }
        }
        catch (const fs::filesystem_error& e) {
            wcerr << L"Помилка при перегляді файлів: " << e.what() << endl;
        }
    }
};

vector<wstring> getFlashDrives() {
    vector<wstring> drives;
    wchar_t driveName[4] = L"A:\\";

    for (driveName[0] = L'A'; driveName[0] <= L'Z'; driveName[0]++) {
        if (GetDriveType(driveName) == DRIVE_REMOVABLE) {
            drives.push_back(wstring(driveName));
        }
    }

    return drives;
}

int main() {
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stdin), _O_U16TEXT);

    wcout << L"Система захисту даних на флеш-накопичувачах\n\n";

    vector<wstring> drives = getFlashDrives();
    if (drives.empty()) {
        wcout << L"Не знайдено жодного флеш-накопичувача.\n";
        return 1;
    }

    wcout << L"Знайдені флеш-накопичувачі:\n";
    for (size_t i = 0; i < drives.size(); i++) {
        wcout << i + 1 << L". " << drives[i] << endl;
    }

    int choice;
    do {
        wcout << L"\nВиберіть номер накопичувача (1-" << drives.size() << L"): ";
        if (!InputValidator::validateChoice(choice, 1, drives.size())) {
            wcout << L"Невірний вибір. Спробуйте ще раз.\n";
            continue;
        }
        if (choice < 1 || choice > drives.size()) {
            wcout << L"Невірний вибір. Спробуйте ще раз.\n";
            continue;
        }
        break;
    } while (true);

    FlashProtection protection;
    if (!protection.initialize(drives[choice - 1])) {
        wcout << L"Помилка ініціалізації захисту.\n";
        return 1;
    }

    while (true) {
        wcout << L"\nМеню:\n";
        wcout << L"1. Зашифрувати файл\n";
        wcout << L"2. Розшифрувати файл\n";
        wcout << L"3. Зашифрувати директорію\n";
        wcout << L"4. Розшифрувати директорію\n";
        wcout << L"5. Показати список зашифрованих файлів\n";
        wcout << L"6. Вийти\n";

        do {
            wcout << L"Виберіть опцію (1-6): ";
            if (!InputValidator::validateChoice(choice, 1, 6)) {
                wcout << L"Невірний вибір. Спробуйте ще раз.\n";
                continue;
            }
            if (choice < 1 || choice > 6) {
                wcout << L"Невірний вибір. Спробуйте ще раз.\n";
                continue;
            }
            break;
        } while (true);

        if (choice == 6) break;

        if (choice == 5) {
            protection.showEncryptedFiles();
            continue;
        }

        wstring inputPath, outputPath;
        bool validInput = false;

        wcin.ignore(1000, L'\n');

        do {
            wcout << L"Введіть шлях до вхідного " << (choice <= 2 ? L"файлу" : L"каталогу") << L": ";
            getline(wcin, inputPath);

            if (inputPath.empty()) {
                wcout << L"Шлях не може бути порожнім. Спробуйте ще раз.\n";
                continue;
            }

            if (choice <= 2) {
                validInput = InputValidator::validatePath(inputPath, true);
            }
            else {
                validInput = InputValidator::validateDirectory(inputPath, true);
            }

            if (!validInput) {
                wcout << L"Невірний шлях. Спробуйте ще раз.\n";
            }
        } while (!validInput);

        validInput = false;
        do {
            wcout << L"Введіть шлях до вихідного " << (choice <= 2 ? L"файлу" : L"каталогу") << L": ";
            getline(wcin, outputPath);

            if (outputPath.empty()) {
                wcout << L"Шлях не може бути порожнім. Спробуйте ще раз.\n";
                continue;
            }

            wstring parentPath = fs::path(outputPath).parent_path().wstring();
            if (!InputValidator::validateDirectory(parentPath, true)) {
                wcout << L"Директорія для виведення не існує. Спробуйте ще раз.\n";
                continue;
            }

            if (!InputValidator::hasWritePermission(parentPath)) {
                wcout << L"Немає прав на запис у вказану директорію. Спробуйте ще раз.\n";
                continue;
            }

            validInput = true;
        } while (!validInput);

        bool success = false;
        switch (choice) {
        case 1:
            success = protection.encryptFile(inputPath, outputPath);
            break;
        case 2:
            success = protection.decryptFile(inputPath, outputPath);
            break;
        case 3:
            success = protection.encryptDirectory(inputPath, outputPath);
            break;
        case 4:
            success = protection.decryptDirectory(inputPath, outputPath);
            break;
        }

        wcout << (success ? L"Операція виконана успішно.\n" : L"Помилка виконання операції.\n");
    }

    return 0;
}