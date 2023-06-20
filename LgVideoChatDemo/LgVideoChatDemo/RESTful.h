#pragma once
#include <windows.h>
#include "CallStatus.h"
int LoginFromApp(HWND hDlg);
int Contacts(HWND hDlg);
const char* GetContactIp(int index);
int SetServer(bool isServer);
int CheckPeer(const std::wstring& peerHashId, PEER& peer);
const std::string GetHashId(void);
