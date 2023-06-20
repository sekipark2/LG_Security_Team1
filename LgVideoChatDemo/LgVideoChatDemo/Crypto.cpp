#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include "Crypto.h"
#include <string>
#include <iomanip>

#define AES_KEY_LENGTH 32
#define BUFFER_SIZE 64*1024
#define IV_SIZE 16

std::string g_recieved_rsa_pub_key;
std::string g_rsa_pub_key;
EVP_PKEY* g_rsa_key;
unsigned char g_aes_key[AES_KEY_LENGTH];
unsigned char g_recieved_aes_key[AES_KEY_LENGTH];

bool saveRSAKeyToFile(const std::string& filename, const EVP_PKEY* key,
    const std::string& passphrase, const std::string& pubkey);
EVP_PKEY* loadRSAKeyFromFile(const std::string& filename,
    const std::string& passphrase,
    std::string& pubkey);
bool GenerateEncryptedKeyData(const unsigned int call_status,
    unsigned char* encrypted_key_data,
    size_t* encrypted_key_data_size);
bool ParsingEncryptedKeyData(unsigned int& call_status,
    unsigned char* encrypted_key_data,
    size_t encrypted_key_data_size);

EVP_PKEY* GenerateRsaKey(std::string& pubkey) {
    int ret = 0;
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* ctx = NULL;
    BIO* publicBio = NULL;
    BIGNUM* e = NULL;
    int publicKeyLen = 0;

    int bits = 2048;

    // generate rsa key
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        std::cout << "Error during context creation" << std::endl;
        goto free_all;
    }

    ret = EVP_PKEY_keygen_init(ctx);
    if (ret != 1) {
        std::cout << "Error during keygen init" << std::endl;
        goto free_all;
    }

    ret = EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);
    if (ret != 1) {
        std::cout << "Error setting keygen bits" << std::endl;
        goto free_all;
    }

    e = BN_new();
    BN_set_word(e, RSA_F4);
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP, 0, e);

    ret = EVP_PKEY_keygen(ctx, &pkey);
    if (ret != 1) {
        std::cout << "Error during key generation" << std::endl;
        goto free_all;
    }

    publicBio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(publicBio, pkey);
    publicKeyLen = BIO_pending(publicBio);
    pubkey.resize(publicKeyLen);
    BIO_read(publicBio, &pubkey[0], publicKeyLen);
    BIO_free(publicBio);
free_all:

    EVP_PKEY_CTX_free(ctx);

    return pkey;

}

EVP_PKEY* GetRsaKey(std::string& pubkey) {
    std::string filename = "rsa_key.hex";
    std::string passphrase = "mypassword";
    BIO* publicBio = NULL;
    int publicKeyLen = 0;

    std::cout << "### LoadOrGenerateRsaKey" << std::endl;

    // Load RSA key from PEM file
    EVP_PKEY* rsaKey = loadRSAKeyFromFile(filename, passphrase, pubkey);
    if (!rsaKey) {
        std::cout << "### Failed to load RSA private key from file." << std::endl;

        rsaKey = GenerateRsaKey(pubkey);
        std::cout << "### GenerateRsaKey" << std::endl;

        // Save RSA key to PEM file
        if (!saveRSAKeyToFile(filename, rsaKey, passphrase, pubkey)) {
            std::cout << "### Failed to save RSA key to PEM file." << std::endl;
            EVP_PKEY_free(rsaKey);
            return nullptr;
        }

    }

    return rsaKey;
 
}
std::string rsaKeyToHex(const EVP_PKEY* evpKey) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, evpKey, nullptr, nullptr, 0, nullptr, nullptr);

    char* derKey;
    long keyLen = BIO_get_mem_data(bio, &derKey);
    std::string hexKey;

    for (int i = 0; i < keyLen; ++i) {
        std::ostringstream oss;
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)derKey[i];
        hexKey += oss.str();
    }

    BIO_free(bio);

    return hexKey;
}
EVP_PKEY* hexToRSAKey(const std::string& hexKey) {
    std::string derKey;
    derKey.reserve(hexKey.length() / 2);

    for (size_t i = 0; i < hexKey.length(); i += 2) {
        std::string byteString = hexKey.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::strtoul(byteString.c_str(), nullptr, 16));
        derKey.push_back(byte);
    }

    BIO* bio = BIO_new_mem_buf(derKey.c_str(), static_cast<int>(derKey.length()));
    EVP_PKEY* evpKey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);


    return evpKey;
}

EVP_PKEY* loadRSAKeyFromFile(const std::string& filename,
                             const std::string& passphrase,
                             std::string& pubkey) {
    EVP_PKEY* evpKey = NULL;
    std::ifstream file("rsa_key.hex");
    std::cout << "### try to load RSA key " << std::endl;

    if (file.is_open()) {
        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string hexKey = buffer.str();
        // 16진수로 저장된 키 출력
        std::cout <<"@@@@ hex from file :" << hexKey << std::endl;

        // 16진수 형식의 키를 EVP 형식으로 변환        
        evpKey = hexToRSAKey(hexKey);
        if (evpKey != nullptr) {
            std::cout << "### RSA key loaded successfully." << std::endl;
        }
        else {
            std::cerr << "### Failed to load RSA key." << std::endl;
            return NULL;
        }
    } 
    else {
        std::cerr << "### Failed to open file for reading." << std::endl;
    }
    std::ifstream pubfile("rsa_key.pub");
    std::cout << "### try to load RSA key " << std::endl;

    if (pubfile.is_open()) {
        std::stringstream buffer;
        buffer << pubfile.rdbuf();
        pubkey.resize(buffer.str().size());
        pubkey = buffer.str();
        std::cout << "@@@@ pub file :" << pubkey << std::endl;
    }
    return evpKey;
}

bool saveRSAKeyToFile(const std::string& filename, const EVP_PKEY* key,
                      const std::string& passphrase, const std::string& pubkey) {
    std::cout << "### saveRSAKeyToFile" << std::endl;
    
    // 키를 16진수로 저장
    std::string hexKey = rsaKeyToHex(key);

    // 16진수로 저장된 키 출력
    std::cout << "@@@@ hex save to file :" << hexKey << std::endl;

    // 파일에 16진수 형식의 키 저장
    std::ofstream file("rsa_key.hex");
    if (file.is_open()) {
        file << hexKey;
        file.close();
        std::cout << "### RSA key saved to rsa_key.hex" << std::endl;
    }
    else {
        std::cerr << "### Failed to open file for writing." << std::endl;
    }
    // 파일에 public key 저장
    std::ofstream pubfile("rsa_key.pub");
    if (pubfile.is_open()) {
        pubfile << pubkey;
        pubfile.close();
        std::cout << "### RSA key saved to rsa_key.pub" << std::endl;
    }
    else {
        std::cerr << "### Failed to open file for writing." << std::endl;
    }

    return true;
}
void GetAesKey(unsigned char* aes_key, size_t aes_key_len, std::string filename) {


    if (!LoadAesKeyFromFile(filename, aes_key, aes_key_len)) {
        std::cout << "## Failed to load AES key from file so Generate Aes key " << std::endl;

        GenerateAesKey(aes_key, aes_key_len);
        //    // 키 파일로 저장
        if (SaveAesKeyToFile(filename, aes_key, aes_key_len)) {
            std::cout << "## AES key saved to file: " << filename << std::endl;
        }
        else {
            std::cout << "## Failed to save AES key to file." << std::endl;
        }
    }
}
void GenerateAesKey(unsigned char* aes_key, size_t aes_key_len) {
    if (!RAND_bytes(aes_key, aes_key_len)) {
        std::cout << "Error during AES key generation" << std::endl;
    }
}

void RsaEncrypt(EVP_PKEY* pkey, const unsigned char* msg, size_t msg_len,
    unsigned char* encrypted_msg, size_t* encrypted_msg_len) {
    int ret = 0;
    EVP_PKEY_CTX* ctx = NULL;
    size_t encryptedLen = 0;
    std::cout << "RsaEncrypt" << std::endl;
    // encrypt msg with rsa public key
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        std::cout << "Error during context creation" << std::endl;
        goto free_all;
    }

    ret = EVP_PKEY_encrypt_init(ctx);
    if (ret != 1) {
        std::cout << "Error during encrypt init" << std::endl;
        goto free_all;
    }
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

    EVP_PKEY_encrypt(ctx, NULL, &encryptedLen, msg, msg_len);
    std::cout << "encryptedLen:" << encryptedLen << std::endl;
    ret = EVP_PKEY_encrypt(ctx, encrypted_msg, &encryptedLen,
        msg, msg_len);
    if (ret != 1) {
        std::cout << "Error during encryption" << std::endl;
        goto free_all;
    }
    *encrypted_msg_len = encryptedLen;
    std::cout << "encrypted_msg_len:" << *encrypted_msg_len << std::endl;

free_all:

    EVP_PKEY_CTX_free(ctx);

}

void encryptWithPublicKey(const std::string& publicKey, const unsigned char* msg, size_t msg_len,
                                 unsigned char* encrypted_msg, size_t* encrypted_msg_len)
{
    int ret = 0;
    size_t encryptedLen = 0;
    BIO* bio = BIO_new_mem_buf(publicKey.c_str(), -1);
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

    EVP_PKEY_encrypt(ctx, NULL, &encryptedLen, msg, msg_len);
    std::cout << "encryptedLen:" << encryptedLen << std::endl;
    if (EVP_PKEY_encrypt(ctx, encrypted_msg, encrypted_msg_len, msg, msg_len) <= 0)
    {
        std::cout << "Failed to encrypt" << std::endl;
    }
    //*encrypted_msg_len = encryptedLen;
    std::cout << "encrypted_msg_len:" << *encrypted_msg_len << std::endl;
    if (bio) BIO_free_all(bio);
    if (pkey) EVP_PKEY_free(pkey);
    if (ctx) EVP_PKEY_CTX_free(ctx);
}


void RsaDecrypt(EVP_PKEY* pkey, const unsigned char* msg, size_t msg_len,
    unsigned char* decrypted_msg, size_t* decrypted_msg_len) {
    int ret = 0;
    EVP_PKEY_CTX* ctx = NULL;
    size_t decryptedLen = 0;

    // decrypt msg with rsa private key
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        std::cout << "Error during context creation" << std::endl;
        goto free_all;
    }

    ret = EVP_PKEY_decrypt_init(ctx);
    if (ret != 1) {
        std::cout << "Error during decrypt init" << std::endl;
        goto free_all;
    }
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    
    EVP_PKEY_decrypt(ctx, NULL, &decryptedLen, msg, msg_len);
    std::cout << "decryptedLen1:" << decryptedLen << std::endl;
    ret = EVP_PKEY_decrypt(ctx, decrypted_msg, &decryptedLen,
        msg, msg_len);
    if (ret != 1) {
        std::cout << "Error during decryption" << std::endl;
        goto free_all;
    }
    std::cout << "decryptedLen2:" << decryptedLen << std::endl;
    *decrypted_msg_len = decryptedLen;
    std::cout << "decrypted_msg_len:" << *decrypted_msg_len << std::endl;

free_all:

    EVP_PKEY_CTX_free(ctx);

}

void AesEncrypt(const unsigned char* aes_key, size_t aes_key_len,
    const unsigned char* iv, size_t iv_len,
    const unsigned char* msg, size_t msg_len,
    unsigned char* encrypted_msg, size_t* encrypted_msg_len) {
    EVP_CIPHER_CTX* ctx = NULL;

    int len;

    int ret;

    // create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        std::cout << "Error during context creation" << std::endl;
        goto free_all;
    }

    // initialize the encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv)) {
        std::cout << "Error during encrypt init" << std::endl;
        goto free_all;
    }

    // provide the message to be encrypted, and obtain the encrypted output
    if (1 != EVP_EncryptUpdate(ctx, encrypted_msg, &len, msg, msg_len)) {
        std::cout << "Error during encryption" << std::endl;
        goto free_all;
    }

    *encrypted_msg_len = len;

    // finalize the encryption
    if (1 != EVP_EncryptFinal_ex(ctx, encrypted_msg + len, &len)) {
        std::cout << "Error during finalization of encryption" << std::endl;
        goto free_all;
    }

    *encrypted_msg_len += len;

free_all:

    EVP_CIPHER_CTX_free(ctx);

}

void AesDecrypt(const unsigned char* aes_key, size_t aes_key_len,
    const unsigned char* iv, size_t iv_len,
    const unsigned char* msg, size_t msg_len,
    unsigned char* decrypted_msg, size_t* decrypted_msg_len) {
    EVP_CIPHER_CTX* ctx = NULL;

    int len;

    int ret;

    // create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        std::cout << "Error during context creation" << std::endl;
        goto free_all;
    }

    // initialize the decryption operation
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv)) {
        std::cout << "Error during decrypt init" << std::endl;
        goto free_all;
    }

    // provide the message to be decrypted, and obtain the decrypted output
    if (1 != EVP_DecryptUpdate(ctx, decrypted_msg, &len, msg, msg_len)) {
        std::cout << "Error during decryption" << std::endl;
        goto free_all;
    }

    *decrypted_msg_len = len;

    // finalize the decryption
    if (1 != EVP_DecryptFinal_ex(ctx, decrypted_msg + len, &len)) {
        std::cout << "Error during finalization of decryption" << std::endl;
        goto free_all;
    }

    *decrypted_msg_len += len;

free_all:

    EVP_CIPHER_CTX_free(ctx);

}

bool AesEncryptForSend(const unsigned char* msg, size_t msg_len,
    std::vector<unsigned char>* encrypted_msg, size_t* encrypted_msg_len) {
    unsigned char iv[IV_SIZE] = { 0 };
    unsigned char encrypted_data[BUFFER_SIZE] = { 0 };
    std::vector<unsigned char> result;
    if (!RAND_bytes(iv, sizeof(iv))) {
        std::cout << "Error during IV generation" << std::endl;
    }
    encrypted_msg->insert(encrypted_msg->end(), iv, iv + sizeof(iv));
    AesEncrypt(g_aes_key, sizeof(g_aes_key), iv, sizeof(iv), msg, msg_len, encrypted_data, encrypted_msg_len);
    encrypted_msg->insert(encrypted_msg->end(), encrypted_data, encrypted_data + *encrypted_msg_len);
    *encrypted_msg_len += IV_SIZE;
    return true;
}

bool AesDecryptForRecieve(const unsigned char* msg, size_t msg_len,
    std::vector<unsigned char>* decrypted_msg, size_t* decrypted_msg_len) {
    unsigned char decrypted_data[BUFFER_SIZE] = { 0 };
    std::vector<unsigned char> iv(msg, msg + IV_SIZE);
    AesDecrypt(g_aes_key, sizeof(g_aes_key), iv.data(), iv.size(),
        msg + IV_SIZE, msg_len - IV_SIZE, decrypted_data, decrypted_msg_len);
    decrypted_msg->insert(decrypted_msg->end(), decrypted_data, decrypted_data + *decrypted_msg_len);
    return true;
}

bool SaveAesKeyToFile(const std::string& filename, const unsigned char* key, size_t keyLength) {
    std::cout << "## SaveAesKeyToFile" << std::endl;

    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return false;
    }

    file.write(reinterpret_cast<const char*>(key), keyLength);
    file.close();

    if (!file) {
        std::cerr << "Error occurred while writing the key to file." << std::endl;
        return false;
    }

    return true;
}

bool LoadAesKeyFromFile(const std::string& filename, unsigned char* key, size_t keyLength) {

    std::cout << "## LoadAesKeyFromFile" << std::endl;

    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return false;
    }

    file.read(reinterpret_cast<char*>(key), keyLength);
    file.close();

    if (!file) {
        std::cerr << "Error occurred while reading the key from file." << std::endl;
        return false;
    }

    return true;
}
void CryptoInitialize() {
    std::cout << "================ Crypto Initialize ==============" << std::endl;
    g_rsa_key = GenerateRsaKey(g_rsa_pub_key);
    GenerateAesKey(g_aes_key, sizeof(g_aes_key));

    const unsigned char* msg = (const unsigned char*)"Hello World!!!!!!!!!";
    size_t msg_len = strlen((const char*)msg);
    std::vector<unsigned char> encrypted_msg;
    std::vector<unsigned char> decrypted_msg;
    size_t encrypted_msg_len = 0;
    size_t decrypted_msg_len = 0;
    std::cout << "================ Encrypt Local Test ==============" << std::endl;
    AesEncryptForSend(msg, msg_len, &encrypted_msg, &encrypted_msg_len);
    std::cout << "encrypted_msg_len:"<< encrypted_msg_len <<"," << encrypted_msg.size() << std::endl;
    AesDecryptForRecieve(encrypted_msg.data(), encrypted_msg.size(), &decrypted_msg, &decrypted_msg_len);
    std::cout << "decrypted_msg_len:" << decrypted_msg_len << std::endl;
    std::cout << "decrypted_msg:" << decrypted_msg.data() << std::endl;

    std::string input = "Hello, World!";
    std::string encoded = Base64Encode(input);
    std::string decoded = Base64Decode(encoded);

    std::cout << "Original: " << input << std::endl;
    std::cout << "Encoded: " << encoded << std::endl;
    std::cout << "Decoded: " << decoded << std::endl;

    unsigned int callstatus = 1;
    unsigned char tempbuf[1000] = { 0 };
    size_t outsizse = 0;

    GenerateEncryptedKeyData(g_rsa_pub_key, callstatus, tempbuf, &outsizse);
    ParsingEncryptedKeyData(callstatus, tempbuf, outsizse);
}

void CryptoTest() {
    std::string rsa_pub_key;
    EVP_PKEY* rsa_key = GenerateRsaKey(rsa_pub_key);

    unsigned char aes_key[32];
    GenerateAesKey(aes_key, sizeof(aes_key));

    unsigned char encrypted_aes_key[256];
    size_t encrypted_aes_key_len;

    const unsigned char* msg = (const unsigned char*)"Hello World!!!!!!!!!";
    size_t msg_len = strlen((const char*)msg);

    unsigned char iv[16] = { 0 };
    if (!RAND_bytes(iv, sizeof(iv))) {
        std::cout << "Error during IV generation" << std::endl;
    }
    unsigned char encrypted_msg[1024];
    size_t encrypted_msg_len;
    std::cout << "================ Encrypt data using AES key ==============" << std::endl;
    AesEncrypt(aes_key, sizeof(aes_key), iv, sizeof(iv),
        msg, msg_len,
        encrypted_msg, &encrypted_msg_len);
    std::cout << "================ Encrypt AES key using RSA Public key ==============" << std::endl;
    encryptWithPublicKey(rsa_pub_key, aes_key, sizeof(aes_key),
        encrypted_aes_key, &encrypted_aes_key_len);

    std::cout << "================ Decrypt AES key using RSA key ==============" << std::endl;
    unsigned char decrypted_aes_key[256];
    size_t decrypted_aes_key_len;
    RsaDecrypt(rsa_key, encrypted_aes_key, encrypted_aes_key_len,
        decrypted_aes_key, &decrypted_aes_key_len);

    std::cout << "================ Decrypt data using AES key ==============" << std::endl;
    unsigned char decrypted_msg[1024] = { 0 };
    size_t decrypted_msg_len;
    AesDecrypt(decrypted_aes_key, decrypted_aes_key_len, iv, sizeof(iv),
        encrypted_msg, encrypted_msg_len,
        decrypted_msg, &decrypted_msg_len);

    std::cout << "Original message: " << msg << std::endl;
    std::cout << "Decrypted message: " << decrypted_msg << std::endl;

    EVP_PKEY_free(rsa_key);
}

bool SetRecievedRsaPublicKey(std::string publickey)
{
    if (!publickey.length()) return false;
    g_recieved_rsa_pub_key = publickey;
    return true;
}

bool GenerateEncryptedKeyData(std::string recieved_pub_key,
                              const unsigned int call_status,
                              unsigned char* encrypted_key_data,
                              size_t* encrypted_key_data_size)
{
     /*
     * | 4byte Call Status | 32byte aes key |
     * Total 36byte
     */
    std::vector<unsigned char> key_data;
    char* call_status_start = (char*)&call_status;
    char* call_status_end = (char*)&call_status + sizeof(unsigned int);
    std::string enc_pub_key = recieved_pub_key;

    if (!encrypted_key_data) return false;
    if (call_status > 2) return false;
    if (!enc_pub_key.length()) {
        if (!g_recieved_rsa_pub_key.length())
            return false;
        enc_pub_key = g_recieved_rsa_pub_key;
    }

    key_data.insert(key_data.end(), call_status_start, call_status_end);

    if (!call_status) {
        key_data.insert(key_data.end(), g_aes_key, g_aes_key + AES_KEY_LENGTH);
    }
    else {
        key_data.resize(key_data.size() + AES_KEY_LENGTH, 0);
    }
    std::cout << "key_data length:" << key_data.size() << std::endl;
    encryptWithPublicKey(enc_pub_key, (const unsigned char*)key_data.data(),
        key_data.size(), encrypted_key_data, encrypted_key_data_size);
    std::cout << "encrypted key_data length:" << *encrypted_key_data_size << std::endl;
    return true;
}

bool ParsingEncryptedKeyData(unsigned int& call_status,
                             unsigned char* encrypted_key_data,
                             size_t encrypted_key_data_size)
{
    /*
    * encrypted size is 256byte
    * | 4byte Call Status | 32byte aes key |
    * Total decrypted sizse is 36
    */
    unsigned char decrypt_data[1000] = { 0 };
    size_t decrypt_size = 0;
    RsaDecrypt(g_rsa_key, encrypted_key_data, encrypted_key_data_size,
        decrypt_data, &decrypt_size);
    call_status = (unsigned int)*decrypt_data;
    std::cout << "decrypted call_status:" << call_status << std::endl;
    return true;
}

std::string Base64Encode(const std::string& input) {
    BIO* bio, * b64;
    BUF_MEM* bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input.c_str(), static_cast<int>(input.length()));
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string encoded(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);

    return encoded;
}

std::string Base64Decode(const std::string& encoded) {
    BIO* bio, * b64;
    char* buffer = new char[encoded.size()];
    memset(buffer, 0, encoded.size());

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(encoded.c_str(), static_cast<int>(encoded.size()));
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int length = BIO_read(bio, buffer, static_cast<int>(encoded.size()));
    BIO_free_all(bio);

    std::string decoded(buffer, length);
    delete[] buffer;

    return decoded;
}

bool GetEncodedPublicKey(std::string& encoded_pub_key) {
    if (!g_rsa_pub_key.size()) {
        std::cout << "rsa public key doesn't generated" << std::endl;
        return false;
    }
    encoded_pub_key = Base64Encode(g_rsa_pub_key);
    return true;
}

void RsaEncryptWithKey(const unsigned char* msg, size_t msg_len,
    unsigned char* encrypted_msg, size_t* encrypted_msg_len) {
    if (g_rsa_pub_key.size() == 0) {
        std::cout << "rsa public key doesn't generated" << std::endl;
    }

    encryptWithPublicKey(g_rsa_pub_key, msg, msg_len,
        encrypted_msg, encrypted_msg_len);
}

void RsaDecryptWithKey(const unsigned char* msg, size_t msg_len,
    unsigned char* decrypted_msg, size_t* decrypted_msg_len) {

    if (g_rsa_key == 0) {
        std::cout << "rsa priv key doesn't generated" << std::endl;
    }
    RsaDecrypt(g_rsa_key, msg, msg_len,
        decrypted_msg, decrypted_msg_len);
}