
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <iostream>
#include <sstream>
#include <fstream>
//#include "Crypto.h"
#include <string>
#include <iomanip>

#define MAX_BUFFER        1024
#define CALL_STATUS_PORT 10002


#define AES_KEY_LENGTH 32
#define BUFFER_SIZE 64*1024
#define IV_SIZE 16

char hash_id[] = "6NSPYQESY2RT3AFJ";
std::string g_recieved_rsa_pub_key = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF4SWVDZGU0aW1iWlg4RzFHTzB4NgpiNHZHdDY2ZmVZbUZDNWZVWVBLM2VxMTJhVHkwNXh2K2NYTUlsTWkyUG9XclRobUYveStpcHJBMk5vNU5HblhNCllCNW1iaGJoTVlmRzVDK3BoUHpBOGVpNUZ0SHFVZDFPNU5JMWZQNzFPTVpFZGNQajBJUyttWWtWN2pVNG5lR3gKc3Vpa0N4dmFCaXNVcjEwa0dlc245MjE0VUtXQ003MEJ6QWZ2ZTJmcEpnN21vOUNtQUhHYWF6YkdZcUJaWlgrdwpXMHBBYm8rbWlpRmZPMmw3RUlIeGZMcnQwSzQ0QXpKNnNhSUJJZzVjc2tBUkpQRUR1SGg5T1B4YXFvMVBkRmRJCnZoWDZsdmxWbUtQd0NDTXBkemRvMUVxaytLYUpsN1p5QjJQMjZnRms2MmlzZVJEcktmbHVIM1pObTNYTjNpUHcKSlFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==";
std::string g_rsa_pub_key;
EVP_PKEY* g_rsa_key;
unsigned char g_aes_key[AES_KEY_LENGTH];



std::string base64_decode(const std::string& in) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new_mem_buf(in.c_str(), -1);
    BIO_push(b64, bio);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); //No newlines

    std::string out(in.length(), '\0'); // Resize output string to fit decoded data
    int decoded_size = BIO_read(b64, &out[0], in.length());
    out.resize(decoded_size); // Resize output string to fit decoded data exactly

    BIO_free_all(b64);

    return out;
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


void RsaEncryptWithRecievedKey(const unsigned char* msg, size_t msg_len, unsigned char* encrypted_msg, size_t* encrypted_msg_len) 
{
    // base64 decoding first
    std::cout << g_recieved_rsa_pub_key << std::endl;
    std::string rsa_pub_key = base64_decode(g_recieved_rsa_pub_key);
    std::cout << msg << std::endl;
    std::cout << rsa_pub_key << std::endl;
    if (rsa_pub_key.size() == 0) {
        std::cout << "rsa recieved public key doesn't generated" << std::endl;
    }

    encryptWithPublicKey(rsa_pub_key, msg, msg_len,
        encrypted_msg, encrypted_msg_len);
}

bool RsaDecrypt(EVP_PKEY* pkey, const unsigned char* msg, size_t msg_len,
    unsigned char* decrypted_msg, size_t* decrypted_msg_len) {
    int ret = 0;
    EVP_PKEY_CTX* ctx = NULL;
    size_t decryptedLen = 0;
    bool retval = true;

    // decrypt msg with rsa private key
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        std::cout << "Error during context creation" << std::endl;
        retval = false;
        goto free_all;
    }

    ret = EVP_PKEY_decrypt_init(ctx);
    if (ret != 1) {
        std::cout << "Error during decrypt init" << std::endl;
        retval = false;
        goto free_all;
    }
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

    EVP_PKEY_decrypt(ctx, NULL, &decryptedLen, msg, msg_len);
    std::cout << "decryptedLen1:" << decryptedLen << std::endl;
    ret = EVP_PKEY_decrypt(ctx, decrypted_msg, &decryptedLen,
        msg, msg_len);
    if (ret != 1) {
        std::cout << "Error during decryption" << std::endl;
        retval = false;
        goto free_all;
    }
    std::cout << "decryptedLen2:" << decryptedLen << std::endl;
    *decrypted_msg_len = decryptedLen;
    std::cout << "decrypted_msg_len:" << *decrypted_msg_len << std::endl;

free_all:

    EVP_PKEY_CTX_free(ctx);
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
    if (decrypt_size - sizeof(unsigned int) != AES_KEY_LENGTH) {
        std::cout << "ParsingEncryptedKeyData size error:" << decrypt_size - sizeof(unsigned int) << std::endl;
        return false;
    }
    memcpy(g_aes_key, decrypt_data + sizeof(unsigned int), AES_KEY_LENGTH);
    return true;
}

int CallRequest(const char* remotehostname, const char* message, unsigned int message_length)
{
    unsigned int callstatus = 1;
    unsigned char encrypted_data[1000] = { 0 };
    size_t encryted_data_size = 0;

    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET)
    {
        printf("Error - Invalid socket. Error code: %d\n", WSAGetLastError());
        return 1;
    }

    SOCKADDR_IN serverAddr;
    memset(&serverAddr, 0, sizeof(SOCKADDR_IN));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(CALL_STATUS_PORT);
    inet_pton(AF_INET, remotehostname, &serverAddr.sin_addr);

    RsaEncryptWithRecievedKey((const unsigned char*)message, message_length,
        encrypted_data, &encryted_data_size);

    //std::cout << encrypted_data << std::endl;

    if (connect(listenSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        printf("Error - Fail to connect\n");
        closesocket(listenSocket);
        return 1;
    }
    {
        char* messageBuffer;
        unsigned int bufferLen;

        messageBuffer = (char*)encrypted_data;
        bufferLen = encryted_data_size;
        //printf("Clinet message:%s, len:%u\n", message, message_length);
        printf("Encrypted(%d):%s\n", bufferLen, messageBuffer);

        int sendBytes = send(listenSocket, messageBuffer, bufferLen, 0);
        if (sendBytes > 0)
        {
            int receiveBytes = recv(listenSocket, messageBuffer, MAX_BUFFER, 0);
            if (receiveBytes > 0)
            {
                ParsingEncryptedKeyData(callstatus, (unsigned char*)messageBuffer, receiveBytes);
                std::cout << "Call Status:" << callstatus << std::endl;
            }
        }
    }

    closesocket(listenSocket);
    return callstatus;
}

int main(int argc, char *argv[])
{
    int call_status = 0;

    WSADATA wsaData;

    int res = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (res != NO_ERROR) {
        std::cout << "WSAStartup failed with error " << res << std::endl;
        return 1;
    }

    // argv[1] : ip addr
    // argv[2] : hash_id
    // argv[3] : public_rsa_key
    std::string pub_rsa_key = argv[3];
    g_recieved_rsa_pub_key = pub_rsa_key;

    if (argc == 4)
    {
        //if (call_status = CallRequest("127.0.0.1", (const char*)hash_id, strlen(hash_id))) {
        if (call_status = CallRequest(argv[1], (const char*)argv[2], strlen(argv[2]))) {
            if (call_status == 1)  printf("Your call is rejected by server refusal\n");
            if (call_status == 2)  printf("Your call is rejected by calling\n");
        }
    }
    else if (argc == 5)
    {
        int count = atoi(argv[4]);

        while (count--)
        {
            if (call_status = CallRequest(argv[1], (const char*)argv[2], strlen(argv[2]))) {
                if (call_status == 1)  printf("Your call is rejected by server refusal\n");
                if (call_status == 2)  printf("Your call is rejected by calling\n");
            }
        }
    }



    return 0;
}



