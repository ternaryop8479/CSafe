/*
 * ProcessHandle.h
 * ����ɱ�������ʵ�ֲ����õ��Ľ��̴���
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#pragma once

#include <windows.h>
#include <tlhelp32.h>

PROCESSENTRY32 PIDtoEntry32(DWORD dwProcessId) {
	// ����һ�����̿���
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return {}; // ����޷��������գ����ؿսṹ��
	}

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32); // ���ýṹ��Ĵ�С

	// ���������еĵ�һ��������Ŀ
	if (!Process32First(hSnapshot, &pe)) {
		CloseHandle(hSnapshot); // �رտ��վ��
		return {}; // ����޷���ȡ��һ����Ŀ�����ؿսṹ��
	}

	// �������̿���ֱ���ҵ�ƥ��Ľ���ID
	do {
		if (pe.th32ProcessID == dwProcessId) {
			// �ҵ�ƥ��Ľ��̣����ƽṹ�岢�رտ��վ��
			PROCESSENTRY32 foundEntry = pe;
			CloseHandle(hSnapshot);
			return foundEntry;
		}
	} while (Process32Next(hSnapshot, &pe));

	// ���û���ҵ����̣��رտ��վ�������ؿսṹ��
	CloseHandle(hSnapshot);
	return {};
}

DWORD NameToPID(const char *ProcessName) {//��ȡ����PID
	HANDLE processAll = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	tagPROCESSENTRY32 processEntry = {};
	processEntry.dwSize = sizeof(tagPROCESSENTRY32);
	DWORD dwPID = 0;
	do {
		if (strcmp(ProcessName, processEntry.szExeFile) == 0) {
			// ��ȡ��PID
			dwPID = processEntry.th32ProcessID;
			break;
		}
	} while (Process32Next(processAll, &processEntry));
	CloseHandle(processAll);

	TCHAR        szImagePath[MAX_PATH];
	HANDLE        hProcess;
	return dwPID;
}