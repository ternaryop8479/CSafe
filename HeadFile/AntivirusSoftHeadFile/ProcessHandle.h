/*
 * ProcessHandle.h
 * 包含杀毒软件在实现部分用到的进程处理
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#pragma once

#include <windows.h>
#include <tlhelp32.h>

PROCESSENTRY32 PIDtoEntry32(DWORD dwProcessId) {
	// 创建一个进程快照
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return {}; // 如果无法创建快照，返回空结构体
	}

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32); // 设置结构体的大小

	// 检索快照中的第一个进程条目
	if (!Process32First(hSnapshot, &pe)) {
		CloseHandle(hSnapshot); // 关闭快照句柄
		return {}; // 如果无法获取第一个条目，返回空结构体
	}

	// 遍历进程快照直到找到匹配的进程ID
	do {
		if (pe.th32ProcessID == dwProcessId) {
			// 找到匹配的进程，复制结构体并关闭快照句柄
			PROCESSENTRY32 foundEntry = pe;
			CloseHandle(hSnapshot);
			return foundEntry;
		}
	} while (Process32Next(hSnapshot, &pe));

	// 如果没有找到进程，关闭快照句柄并返回空结构体
	CloseHandle(hSnapshot);
	return {};
}

DWORD NameToPID(const char *ProcessName) {//获取进程PID
	HANDLE processAll = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	tagPROCESSENTRY32 processEntry = {};
	processEntry.dwSize = sizeof(tagPROCESSENTRY32);
	DWORD dwPID = 0;
	do {
		if (strcmp(ProcessName, processEntry.szExeFile) == 0) {
			// 获取到PID
			dwPID = processEntry.th32ProcessID;
			break;
		}
	} while (Process32Next(processAll, &processEntry));
	CloseHandle(processAll);

	TCHAR        szImagePath[MAX_PATH];
	HANDLE        hProcess;
	return dwPID;
}