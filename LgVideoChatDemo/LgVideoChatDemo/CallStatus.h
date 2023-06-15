#pragma once

int CallRequest(const char* remotehostname, const char* message, unsigned int message_length);
void StartWaitCallThread(void);
void StopWaitCall(void);