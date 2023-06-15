#include <vector>
#include <openssl/evp.h>

void CryptoInitialize();
void CryptoTest();
bool AesEncryptForSend(const unsigned char* msg, size_t msg_len,
    std::vector<unsigned char>* encrypted_msg, size_t* encrypted_msg_len);
bool AesDecryptForRecieve(const unsigned char* msg, size_t msg_len,
    std::vector<unsigned char>* decrypted_msg, size_t* decrypted_msg_len);
bool LoadAesKeyFromFile(const std::string& filename, unsigned char* key, size_t keyLength);
bool SaveAesKeyToFile(const std::string& filename, const unsigned char* key, size_t keyLength);
EVP_PKEY* GetRsaKey(std::string& pubkey);
bool saveRSAKeyToFile(const std::string& filename, const EVP_PKEY* key, const std::string& passphrase = "");
EVP_PKEY* loadRSAKeyFromFile(const std::string& filename, const std::string& passphrase);
void GetAesKey(unsigned char* aes_key, size_t aes_key_len, std::string filename = "");
void GenerateAesKey(unsigned char* aes_key, size_t aes_key_len);
