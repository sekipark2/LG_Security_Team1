#pragma once

#include "resource.h"
#include "VoipVoice.h"

#define WM_CLIENT_LOST         WM_USER+1
#define WM_REMOTE_CONNECT      WM_USER+2
#define WM_REMOTE_LOST         WM_USER+3
#define WM_VAD_STATE           WM_USER+4
#define WM_REMOTE_DISCONNECTED WM_USER+5

#define VIDEO_PORT       10000
#define VOIP_LOCAL_PORT  10001
#define VOIP_REMOTE_PORT 10001
#define VIDEO_FRAME_DELAY 100

#define CALL_STATUS_OK 0
#define CALL_STATUS_REJECT 1
#define CALL_STATUS_MISSING 2

extern HWND hWndMain;
extern TVoipAttr VoipAttr;
extern char LocalIpAddress[512];

int checkReceivedCall(void);
//-----------------------------------------------------------------
// END of File
//-----------------------------------------------------------------
