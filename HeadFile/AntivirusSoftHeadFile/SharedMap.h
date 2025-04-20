/*
 * SharedMap.h
 * CSafeɱ������������TOProtect�Ĺ����ڴ�API��װ
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#pragma once

#include <windows.h>
#include <string>

HANDLE CreateMap(const std::string &name, size_t size, DWORD dwProcessId) {
	// ����һ���������ڴ�ӳ���ļ�
	HANDLE hMapFile = CreateFileMapping(
	                      INVALID_HANDLE_VALUE,    // ʹ��ϵͳ��ҳ�ļ�
	                      NULL,                    // Ĭ�ϰ�ȫ����
	                      PAGE_READWRITE,          // ��дȨ��
	                      0,                       // �������С����λ��
	                      static_cast<DWORD>(size), // �������С����λ��
	                      (name + std::to_string(dwProcessId)).c_str()            // ���Ʊ�ʶ��
	                  );

	if (hMapFile == NULL) {
		return NULL;
	}
	return hMapFile;
}

HANDLE CreateMap_NoProcess(const std::string &name, size_t size) {
	// ����һ���������ڴ�ӳ���ļ�
	HANDLE hMapFile = CreateFileMapping(
	                      INVALID_HANDLE_VALUE,    // ʹ��ϵͳ��ҳ�ļ�
	                      NULL,                    // Ĭ�ϰ�ȫ����
	                      PAGE_READWRITE,          // ��дȨ��
	                      0,                       // �������С����λ��
	                      static_cast<DWORD>(size), // �������С����λ��
	                      name.c_str()            // ���Ʊ�ʶ��
	                  );

	if (hMapFile == NULL) {
		return NULL;
	}
	return hMapFile;
}

bool WriteMap(HANDLE hMapFile, const void *data, size_t size) {
	if (hMapFile == NULL || data == NULL) return false;

	// ӳ����ͼ���ļ�
	LPVOID pBuf = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (pBuf == NULL) {
		return false;
	}

	// д������
	memcpy(pBuf, data, size);

	// ͬ���ڴ�
	FlushViewOfFile(pBuf, size);

	// ȡ��ӳ��
	UnmapViewOfFile(pBuf);
	return true;
}

bool ReadMap(HANDLE hMapFile, void *buffer, size_t size) {
	if (hMapFile == NULL || buffer == NULL) return false;

	// ӳ����ͼ���ļ�
	LPVOID pBuf = MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, 0);
	if (pBuf == NULL) {
		return false;
	}

	// ��ȡ����
	memcpy(buffer, pBuf, size);

	// ȡ��ӳ��
	UnmapViewOfFile(pBuf);
	return true;
}

bool DeleteMap(HANDLE hMapFile) {
	if (hMapFile == NULL) return false;

	// �رվ��
	BOOL result = CloseHandle(hMapFile);
	return result != FALSE;
}