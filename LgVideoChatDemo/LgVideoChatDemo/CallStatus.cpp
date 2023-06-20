/*
## 소켓 서버 : 1 v n - multithread
1. socket()            : 소켓생성
2. bind()            : 소켓설정
3. listen()            : 수신대기열생성
4. accept()            : 연결대기
*. CreateThread        : 스레드 생성
5. read()&write()
    WIN recv()&send    : 데이터 읽고쓰기
6. close()
    WIN closesocket    : 소켓종료
*/

#include <iostream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <atlstr.h>
#include "Crypto.h"
#include "CallStatus.h"
#include "RESTful.h"
#include <cpprest/http_client.h>

#define MAX_BUFFER        1024
#define CALL_STATUS_PORT 10002

static DWORD ThreadCallStatusID;
static HANDLE hThreadCallStatus = INVALID_HANDLE_VALUE;

static DWORD WINAPI MakeThread(void* data);
static DWORD WINAPI WaitCallRequest(LPVOID ivalue);
static bool isServerEnabled = false;
static bool g_isCalling = false;

std::vector<std::wstring> missedCalls;

static void addMissedCall(const std::wstring& firstName, const std::wstring& lastName, const std::wstring& email)
{
    std::wstring missedCall;

    SYSTEMTIME time;
    GetLocalTime(&time);

    missedCall += std::to_wstring(time.wYear);
    missedCall += L"/";
    missedCall += std::to_wstring(time.wMonth);
    missedCall += L"/";
    missedCall += std::to_wstring(time.wDay);
    missedCall += L" ";
    missedCall += std::to_wstring(time.wHour);
    missedCall += L":";
    missedCall += std::to_wstring(time.wMinute);
    missedCall += L":";
    missedCall += std::to_wstring(time.wSecond);

    missedCall += L" - ";
    missedCall += firstName;
    missedCall += L" ";
    missedCall += lastName;
    missedCall += L" (";
    missedCall += email;
    missedCall += L")";

    missedCalls.push_back(missedCall);
}

void StartWaitCallThread(void) {
    isServerEnabled = true;
    if (hThreadCallStatus == INVALID_HANDLE_VALUE)
    {
        hThreadCallStatus = CreateThread(NULL, 0, WaitCallRequest, NULL, 0, &ThreadCallStatusID);
    }
}
void StopWaitCall(void) {
    isServerEnabled = false;
    if (hThreadCallStatus != INVALID_HANDLE_VALUE)
    {
        WaitForSingleObject(hThreadCallStatus, INFINITE);
        CloseHandle(hThreadCallStatus);
        hThreadCallStatus = INVALID_HANDLE_VALUE;
    }
}

static DWORD WINAPI WaitCallRequest(LPVOID ivalue)
{
    std::cout << "===== Waiting CallRequest Start ======" << std::endl;
    // Create socket   
    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSocket == INVALID_SOCKET)
    {
        std::cout << "socket() failed with error " << WSAGetLastError() << std::endl;
        return 1;
    }

    // Set server
    SOCKADDR_IN serverAddr;
    memset(&serverAddr, 0, sizeof(SOCKADDR_IN));
    serverAddr.sin_family = PF_INET;
    serverAddr.sin_port = htons(CALL_STATUS_PORT);
    serverAddr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);

    // Set socket
    if (bind(listenSocket, (struct sockaddr*)&serverAddr, sizeof(SOCKADDR_IN)) == SOCKET_ERROR)
    {
        printf("Error - Fail bind\n");
        // close socket
        closesocket(listenSocket);
        return 1;
    }

    // Set recieve
    if (listen(listenSocket, 5) == SOCKET_ERROR)
    {
        printf("Error - Fail listen\n");
        // close socket
        closesocket(listenSocket);
        return 1;
    }

    SOCKADDR_IN clientAddr;
    int addrLen = sizeof(SOCKADDR_IN);
    memset(&clientAddr, 0, addrLen);
    SOCKET clientSocket;

    // Set non-blocking
    unsigned long mode = 1;
    if (ioctlsocket(listenSocket, FIONBIO, &mode) != 0) {
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }

    HANDLE hThread;

    while (1)
    {
        clientSocket = accept(listenSocket, (struct sockaddr*)&clientAddr, &addrLen);

        if (clientSocket == -1) {
            if (!isServerEnabled) {
                std::cout << "close waiting " << std::endl;
                break;
            }
            Sleep(100);
        }
        else {
            std::cout << "Client request to connect" << std::endl;
            hThread = CreateThread(NULL, 0, MakeThread, (void*)clientSocket, 0, NULL);
            CloseHandle(hThread);
            std::cout << "Connenction done" << std::endl;
        }
    }

    closesocket(listenSocket);
    std::cout << "===== Waiting CallRequest End ======" << std::endl;
    return 0;
}

static DWORD WINAPI MakeThread(void* data)
{
    int call_status = 0;
    unsigned char decrypted_data[MAX_BUFFER] = { 0 };
    unsigned char encrypted_data[MAX_BUFFER] = { 0 };
    size_t decrypted_data_size = 0;
    size_t encrypted_data_size = 0;
    SOCKET socket = (SOCKET)data;

    char messageBuffer[MAX_BUFFER];
    int receiveBytes;
    int err = errno;
    while (receiveBytes = recv(socket, messageBuffer, MAX_BUFFER, 0))
    {
        if (receiveBytes > 0)
        {
            RsaDecryptWithKey((const unsigned char *)messageBuffer, receiveBytes, decrypted_data, &decrypted_data_size);
            printf("Server TRACE - Receive message (%d bytes)\n", decrypted_data_size);
            // TO-DO :
            // Request info to login server
            // Get info and if it was verified, store public key
            // if g_isCalling is true, store info to vector for missed call
            std::wstring peerHashId(decrypted_data, decrypted_data + decrypted_data_size);
            PEER peer;
            std::string pubkey = "";
            if (CheckPeer(peerHashId, peer) == 0) {
                std::cout << "peer is valid" << std::endl;
                addMissedCall(peer.firstName, peer.lastName, peer.email);
                if (g_isCalling) {
                    pubkey = Base64Decode(utility::conversions::to_utf8string(peer.key));
                    std::cout << "Server is calling" << std::endl;
                    call_status = 2;
                }
                else {
                    if (!SetRecievedRsaPublicKey(Base64Decode(utility::conversions::to_utf8string(peer.key)))) {
                        std::cout << "Failed to set pub key" << std::endl;
                    }
                    std::cout << "Request call is OK" << std::endl;
                    call_status = 0;
                }
                GenerateEncryptedKeyData(pubkey, call_status, encrypted_data, &encrypted_data_size);
                int sendBytes = send(socket, (const char*)encrypted_data, encrypted_data_size, 0);
                if (sendBytes > 0)
                {
                    printf("Server TRACE - Send message (%d bytes)\n", sendBytes);
                }
            }
            else {
                std::cout << "peer(caller ID) is invalid" << std::endl;
            }

        }
        else
        {
            if ((err == EAGAIN) || (err == EWOULDBLOCK) || (receiveBytes == -1)) {
                std::cout << "Wait recv :" << receiveBytes << std::endl;
                continue;
            }
            else {
                std::cout << "Stop recv :" << receiveBytes << std::endl;
                break;
            }
        }
    }
    closesocket(socket);
    printf("End - makeThread\n");
    return 0;
}

int CallRequest(const char* remotehostname, const char* message, unsigned int message_length)
{
    unsigned int callstatus = 1;
    unsigned char encrypted_data[1000] = { 0 };
    size_t encryted_data_size = 0;

    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET)
    {
        printf("Error - Invalid socket\n");
        return 1;
    }

    SOCKADDR_IN serverAddr;
    memset(&serverAddr, 0, sizeof(SOCKADDR_IN));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(CALL_STATUS_PORT);
    inet_pton(AF_INET, remotehostname, &serverAddr.sin_addr);

    RsaEncryptWithKey((const unsigned char*)message, message_length, encrypted_data, &encryted_data_size);

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
        printf("Clinet message:%s, len:%u\n", message, message_length);


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

void SetIsCalling(bool isCalling)
{
    g_isCalling = isCalling;
    if (g_isCalling) {
        std::cout << "Set calling enable" << std::endl;
    }
    else {
        std::cout << "Set calling disable" << std::endl;
    }
}
