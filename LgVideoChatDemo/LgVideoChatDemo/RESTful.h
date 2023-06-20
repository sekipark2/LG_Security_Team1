#pragma once
#include <windows.h>
int LoginFromApp(HWND hDlg);
int Contacts(HWND hDlg);
const char* GetContactIp(int index);
int SetServer(bool isServer);
const std::string GetHashId(void);
