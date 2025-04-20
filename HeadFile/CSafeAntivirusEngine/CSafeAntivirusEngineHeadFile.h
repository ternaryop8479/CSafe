/*
 * CSafeAntivirusEngineHeadFile.h
 * ����CSafeAntivirusEngine.h���õ���һЩ�����ļ�����δ�������Ĺ��ܺ���
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#ifndef CSafeAntivirusEngineHeadFile_H
#define CSafeAntivirusEngineHeadFile_H

#include <set>
#include <string>
#include <Windows.h>
#include <tlHelp32.h>

std::set<DWORD> processIdList;//�����б�

void InitProcessList(void) {//��ʼ�������б���ʼ����
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		throw std::runtime_error("InitProcessList(): Failed to create process list handle.");
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnap, &pe32)) {
		CloseHandle(hProcessSnap);
		throw std::runtime_error("InitProcessList(): Failed to find process.");
	}

	do {
		if (processIdList.find(pe32.th32ProcessID) == processIdList.end()) {
			processIdList.insert(pe32.th32ProcessID);//�Ȱѽ���ˢһ�飬��ʼ����������
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
}

bool GetProcessListStart(PROCESSENTRY32 &peIn) {//��ȡ���������߳�
	(processIdList.empty()) ? InitProcessList() : void();
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		throw std::runtime_error("GetProcessListStart(): Failed to create process list handle.");
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnap, &pe32)) {
		CloseHandle(hProcessSnap);
		throw std::runtime_error("GetProcessListStart(): Failed to find process.");
	}

	do {
		if (processIdList.find(pe32.th32ProcessID) == processIdList.end()) {
			peIn = pe32;
			processIdList.insert(pe32.th32ProcessID);
			return true;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return false;
}

#endif