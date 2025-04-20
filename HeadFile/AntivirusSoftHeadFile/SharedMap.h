/*
 * SharedMap.h
 * CSafe杀毒引擎子引擎TOProtect的共享内存API封装
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#pragma once

#include <windows.h>
#include <string>

HANDLE CreateMap(const std::string &name, size_t size, DWORD dwProcessId) {
	// 创建一个命名的内存映射文件
	HANDLE hMapFile = CreateFileMapping(
	                      INVALID_HANDLE_VALUE,    // 使用系统分页文件
	                      NULL,                    // 默认安全属性
	                      PAGE_READWRITE,          // 读写权限
	                      0,                       // 最大对象大小（高位）
	                      static_cast<DWORD>(size), // 最大对象大小（低位）
	                      (name + std::to_string(dwProcessId)).c_str()            // 名称标识符
	                  );

	if (hMapFile == NULL) {
		return NULL;
	}
	return hMapFile;
}

HANDLE CreateMap_NoProcess(const std::string &name, size_t size) {
	// 创建一个命名的内存映射文件
	HANDLE hMapFile = CreateFileMapping(
	                      INVALID_HANDLE_VALUE,    // 使用系统分页文件
	                      NULL,                    // 默认安全属性
	                      PAGE_READWRITE,          // 读写权限
	                      0,                       // 最大对象大小（高位）
	                      static_cast<DWORD>(size), // 最大对象大小（低位）
	                      name.c_str()            // 名称标识符
	                  );

	if (hMapFile == NULL) {
		return NULL;
	}
	return hMapFile;
}

bool WriteMap(HANDLE hMapFile, const void *data, size_t size) {
	if (hMapFile == NULL || data == NULL) return false;

	// 映射视图到文件
	LPVOID pBuf = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (pBuf == NULL) {
		return false;
	}

	// 写入数据
	memcpy(pBuf, data, size);

	// 同步内存
	FlushViewOfFile(pBuf, size);

	// 取消映射
	UnmapViewOfFile(pBuf);
	return true;
}

bool ReadMap(HANDLE hMapFile, void *buffer, size_t size) {
	if (hMapFile == NULL || buffer == NULL) return false;

	// 映射视图到文件
	LPVOID pBuf = MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, 0);
	if (pBuf == NULL) {
		return false;
	}

	// 读取数据
	memcpy(buffer, pBuf, size);

	// 取消映射
	UnmapViewOfFile(pBuf);
	return true;
}

bool DeleteMap(HANDLE hMapFile) {
	if (hMapFile == NULL) return false;

	// 关闭句柄
	BOOL result = CloseHandle(hMapFile);
	return result != FALSE;
}