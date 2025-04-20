/*
 * toHandlesInfo.h
 * 负责处理进程句柄(文件句柄)的一个头文件(单文件库)，
 * 由Ternary_Operator编写，可用于针对单个进程的高效文件句柄查询
 * Copyright (C) 2025 Ternary_Operator.
*/

#ifndef toHandlesInfo_H
#define toHandlesInfo_H

#include <windows.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <stdexcept>
#include "TypeDeleter.h"

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// 不开放的API使用匿名命名空间
namespace {
	// 对象信息枚举类型
	typedef enum _OBJECT_INFORMATION_CLASS {
		ObjectBasicInformation,       // 用于查询对象的基本信息
		ObjectNameInformation,        // 用于查询对象的名称信息
		ObjectTypeInformation,        // 用于查询对象的类型信息
		ObjectAllInformation,         // 用于查询对象的所有信息
		ObjectDataInformation         // 用于查询对象的数据信息
	} OBJECT_INFORMATION_CLASS;

	// NtQuerySystemInformation函数原型
	typedef NTSTATUS (NTAPI *_NtQuerySystemInformation)(
	    ULONG SystemInformationClass,
	    PVOID SystemInformation,
	    ULONG SystemInformationLength,
	    PULONG ReturnLength
	);

	// NtDuplicateObject函数原型
	typedef NTSTATUS (NTAPI *pNtDuplicateObject)(
	    HANDLE SourceProcessHandle,
	    HANDLE SourceHandle,
	    HANDLE TargetProcessHandle,
	    PHANDLE TargetHandle,
	    ACCESS_MASK DesiredAccess,
	    ULONG HandleAttributes,
	    ULONG Options
	);

	// NtQueryObject函数原型
	typedef NTSTATUS (NTAPI *pNtQueryObject)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);

	// GetFinalPathNameByHandleA函数原型，由于我的WinAPI库里木的这个函数，所以加上防止别的编译环境也发生这样的惨剧
	typedef DWORD (WINAPI *GetFinalPathNameByHandleA_t)(HANDLE, LPSTR, DWORD, DWORD);

	// 所需结构体
	typedef struct _SYSTEM_HANDLE {
		ULONG ProcessId;
		BYTE ObjectTypeNumber;
		BYTE Flags;
		USHORT Handle;
		PVOID Object;
		ACCESS_MASK GrantedAccess;
	} SYSTEM_HANDLE, *PSYSTEM_HANDLE;
	typedef struct _SYSTEM_HANDLE_INFORMATION {
		ULONG HandleCount;
		SYSTEM_HANDLE Handles[1];
	} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

	using safePSYSTEM_HANDLE_INFORMATION = toSrcProtect<PSYSTEM_HANDLE_INFORMATION, deleter_free<PSYSTEM_HANDLE_INFORMATION>>;

	// 工具函数编写
	// NT路径转DOS路径
	std::string NTPathToDOSPath(const std::string &ntPath) {
		const char *ntPrefix = "\\\\?\\";
		size_t prefixLen = strlen(ntPrefix);

		if (ntPath.substr(0, prefixLen) != ntPrefix) {
			throw std::runtime_error("TOProtect-toHandlesInfo.h-NTPathToDOSPath(): Invalid NT path format.");
		}

		// 提取路径中的驱动器号和后续部分
		std::string dosPath = ntPath.substr(prefixLen);

		// 如果路径以盘符开头（如 C:\\），直接返回
		if (dosPath.size() >= 3 && dosPath[1] == ':' && dosPath[2] == '\\') {
			return dosPath;
		}

		// 如果路径以盘符开头但没有反斜杠，添加反斜杠
		if (dosPath.size() >= 2 && dosPath[1] == ':') {
			dosPath.insert(2, "\\");
			return dosPath;
		}

		// 如果路径不是以盘符开头，尝试解析为DOS路径
		char buffer[MAX_PATH];
		DWORD result = QueryDosDeviceA(NULL, buffer, MAX_PATH);

		if (result == 0) {
			throw std::runtime_error(std::string("TOProtect-toHandlesInfo.h-NTPathToDOSPath(): Failed to query DOS devices. Error: ") + std::to_string(GetLastError()));
		}

		// 遍历返回的设备映射，查找匹配的NT路径
		const char *device = buffer;
		while (*device) {
			size_t deviceLen = strlen(device);
			if (dosPath.find(device) == 0) {
				// 找到匹配的设备映射，替换为DOS路径
				dosPath.replace(0, deviceLen, device + deviceLen + 1);
				return dosPath;
			}
			device += deviceLen + 1;
		}

		throw std::runtime_error("TOProtect-toHandlesInfo.h-NTPathToDOSPath(): Failed to find a suitable path");
	}
	// 从句柄获取文件名(DOS路径)
	std::string GetFileNameFromHandle(HANDLE hFile) {
		static GetFinalPathNameByHandleA_t GetFinalPathNameByHandleA = (GetFinalPathNameByHandleA_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetFinalPathNameByHandleA");
		if (!GetFinalPathNameByHandleA) {
			throw std::runtime_error("TOProtect-toHandlesInfo.h-GetFileNameFromHandle(): Failed to load function GetFinalPathNameByHandleA from kernel32.dll");
		}

		char path[MAX_PATH];
		DWORD result = GetFinalPathNameByHandleA(hFile, path, MAX_PATH, FILE_NAME_NORMALIZED);

		if (result > 0 && result <= MAX_PATH) {
//			return path;
			return NTPathToDOSPath(path);
		}

		throw std::runtime_error("TOProtect-toHandlesInfo.h-GetFileNameFromHandle(): Failed to GetFinalPathNameByHandleA()");
	}
	// 检查文件句柄是否可用
	bool IsFileHandleValid(HANDLE hFile) {
		DWORD fileType = GetFileType(hFile);
		return fileType != FILE_TYPE_UNKNOWN;
	}
	// 获取文件句柄的ObjectTypeNumber
	UCHAR GetFileHandleType() {
		CHAR exePath[MAX_PATH];
		GetModuleFileNameA(nullptr, exePath, MAX_PATH);

		safeHANDLE hSelf = CreateFileA(
		                       exePath,
		                       GENERIC_READ,
		                       FILE_SHARE_READ,
		                       nullptr,
		                       OPEN_EXISTING,
		                       FILE_ATTRIBUTE_NORMAL,
		                       nullptr
		                   );

		static _NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQuerySystemInformation");
		if (!NtQuerySystemInformation) {
			throw std::runtime_error("TOProtect-toHandlesInfo.h-GetFileHandleType(): Failed to load function NtQuerySystemInformation from ntdll.dll");
		}

		ULONG handleInfoSize = 0x10000;
		ULONG neededSize;
		NTSTATUS status;
		safePSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

		while ((status = NtQuerySystemInformation(SystemHandleInformation, (handleInfo()), handleInfoSize, &neededSize)) == STATUS_INFO_LENGTH_MISMATCH) {
			(handleInfo()) = (PSYSTEM_HANDLE_INFORMATION)realloc((handleInfo()), handleInfoSize *= 2);
		}

		if (!NT_SUCCESS(status)) {
			throw std::runtime_error("TOProtect-toHandlesInfo.h-GetFileHandleType(): Failed to NtQuerySystemInformation()");
		}

		const DWORD processId = GetCurrentProcessId();
		UCHAR result = 0;

		for (ULONG i = 0; i < (handleInfo())->HandleCount; i++) {
			SYSTEM_HANDLE handle = (handleInfo())->Handles[i];
			if (handle.ProcessId == processId && reinterpret_cast<HANDLE>(handle.Handle) == (hSelf())) {
				result = handle.ObjectTypeNumber;
				break;
			}
		}

		return result;
	}

	const UCHAR fileHandleType = GetFileHandleType(); // 文件句柄的编号

	// 封装的API

	std::vector<HANDLE> _SearchTargetProcessHandle(DWORD processId) {
		std::vector<HANDLE> handles;

		_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQuerySystemInformation");
		if (!NtQuerySystemInformation) {
			throw std::runtime_error("TOProtect-toHandlesInfo.h-_SearchTargetProcessHandle(): Failed to load function NtQuerySystemInformation from ntdll.dll");
			return handles;
		}

		pNtDuplicateObject NtDuplicateObject = (pNtDuplicateObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDuplicateObject");
		if (!NtDuplicateObject) {
			throw std::runtime_error("TOProtect-toHandlesInfo.h-_SearchTargetProcessHandle(): Failed to load function NtDuplicateObject from ntdll.dll");
			return handles;
		}

		ULONG handleInfoSize = 0x10000;
		ULONG neededSize;
		NTSTATUS status;
		safePSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

		while ((status = NtQuerySystemInformation(SystemHandleInformation, (handleInfo()), handleInfoSize, &neededSize)) == STATUS_INFO_LENGTH_MISMATCH) {
			(handleInfo()) = (PSYSTEM_HANDLE_INFORMATION)realloc((handleInfo()), handleInfoSize *= 2);
		}

		if (!NT_SUCCESS(status)) {
			throw std::runtime_error("TOProtect-toHandlesInfo.h-_SearchTargetProcessHandle(): Failed to NtQuerySystemInformation()");
			return handles;
		}

		for (ULONG i = 0; i < (handleInfo())->HandleCount; i++) {
			SYSTEM_HANDLE handle = (handleInfo())->Handles[i];
			if (handle.ObjectTypeNumber == 7) { // ObjectTypeNumber 7 是进程句柄
				if (handle.ProcessId == processId) { // 你都有权限打开这个进程了还需要搜索它的句柄么？
					continue;
				}

				safeHANDLE ownerHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handle.ProcessId); // 句柄所有者的进程句柄
				if (!(ownerHandle())) {
//					throw std::runtime_error("TOProtect-toHandlesInfo.h-_SearchTargetProcessHandle(): Failed to OpenProcess()");
					continue;
				}

				// 如果没问题则拷贝句柄
				HANDLE duplicatedHandle;
				NTSTATUS status = NtDuplicateObject((ownerHandle()), reinterpret_cast<HANDLE>(handle.Handle), GetCurrentProcess(), &duplicatedHandle, GENERIC_ALL, 0, DUPLICATE_SAME_ACCESS);

				if (!NT_SUCCESS(status)) {
//					throw std::runtime_error("TOProtect-toHandlesInfo.h-_SearchTargetProcessHandle(): Failed to NtDuplicateObject()");
					continue;
				}

				if (GetProcessId(duplicatedHandle) == processId) { // 查找到目标进程
					handles.push_back(duplicatedHandle);
				}
			}
		}

		return handles;
	}
	std::vector<HANDLE> _GetProcessHandles(DWORD processId) {
		std::vector<HANDLE> handles;

		_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQuerySystemInformation");
		if (!NtQuerySystemInformation) {
			throw std::runtime_error("TOProtect-toHandlesInfo.h-_GetProcessHandles(): Failed to load function NtQuerySystemInformation from ntdll.dll");
			return handles;
		}

		ULONG handleInfoSize = 0x10000;
		ULONG neededSize;
		NTSTATUS status;
		safePSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

		while ((status = NtQuerySystemInformation(SystemHandleInformation, (handleInfo()), handleInfoSize, &neededSize)) == STATUS_INFO_LENGTH_MISMATCH) {
			(handleInfo()) = (PSYSTEM_HANDLE_INFORMATION)realloc((handleInfo()), handleInfoSize *= 2);
		}

		if (!NT_SUCCESS(status)) {
			throw std::runtime_error("TOProtect-toHandlesInfo.h-_GetProcessHandles(): Failed to NtQuerySystemInformation()");
			return handles;
		}

		for (ULONG i = 0; i < (handleInfo())->HandleCount; i++) {
			SYSTEM_HANDLE handle = (handleInfo())->Handles[i];
			if (handle.ProcessId == processId) {
				handles.push_back(reinterpret_cast<HANDLE>(handle.Handle));
			}
		}

		return handles;
	}
	std::vector<HANDLE> _GetTargetFileHandles(DWORD processId) {
		std::vector<HANDLE> handles;

		_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQuerySystemInformation");
		if (!NtQuerySystemInformation) {
			throw std::runtime_error("TOProtect-toHandlesInfo.h-_GetTargetFileHandles(): Failed to load function NtQuerySystemInformation from ntdll.dll");
		}

		ULONG handleInfoSize = 0x10000;
		ULONG neededSize;
		NTSTATUS status;
		safePSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

		while ((status = NtQuerySystemInformation(SystemHandleInformation, (handleInfo()), handleInfoSize, &neededSize)) == STATUS_INFO_LENGTH_MISMATCH) {
			(handleInfo()) = (PSYSTEM_HANDLE_INFORMATION)realloc((handleInfo()), handleInfoSize *= 2);
		}

		if (!NT_SUCCESS(status)) {
			throw std::runtime_error("TOProtect-toHandlesInfo.h-_GetTargetFileHandles(): Failed to NtQuerySystemInformation()");
		}

		for (ULONG i = 0; i < (handleInfo())->HandleCount; i++) {
			SYSTEM_HANDLE handle = (handleInfo())->Handles[i];
			if (handle.ProcessId == processId && handle.ObjectTypeNumber == fileHandleType) {
				handles.push_back(reinterpret_cast<HANDLE>(handle.Handle));
			}
		}

		return handles;
	}
	std::string _GetFilePathFromHandle(HANDLE targetHandle, DWORD targetProcessId) {
		if (IsFileHandleValid(targetHandle)) {
			return GetFileNameFromHandle(targetHandle);
		}
		std::string filePath;

		// 获取NtDuplicateObject函数指针
		pNtDuplicateObject NtDuplicateObject = (pNtDuplicateObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDuplicateObject");
		if (!NtDuplicateObject) {
			throw std::runtime_error("TOProtect-toHandlesInfo.h-_GetFilePathFromHandle(): Failed to load function NtDuplicateObject from ntdll.dll");
		}

		// 打开目标进程句柄
		safeHANDLE targetProcessHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, targetProcessId);
		if (!(targetProcessHandle())) {
//			throw std::runtime_error("TOProtect-toHandlesInfo.h-_GetFilePathFromHandle(): Failed to OpenProcess()");
		}

		// 复制句柄到当前进程
		safeHANDLE duplicatedHandle;
		NTSTATUS status = NtDuplicateObject((targetProcessHandle()), targetHandle, GetCurrentProcess(), &(duplicatedHandle()), GENERIC_READ, 0, DUPLICATE_SAME_ACCESS);

		if (!NT_SUCCESS(status)) {
//			throw std::runtime_error("TOProtect-toHandlesInfo.h-_GetFilePathFromHandle(): Failed to NtDuplicateObject()");
		}

		// 获取文件路径
		std::string finalPath = "";

		try {
			if (IsFileHandleValid(duplicatedHandle())) {
				finalPath = GetFileNameFromHandle(duplicatedHandle());
			}
		} catch (const std::runtime_error &e) {
			if (std::string(e.what()).find("GetFinalPathNameByHandleA()") == std::string::npos) {
				throw;
			}
		}

		return finalPath;
	}
}

//----------------以下是开放API，可以从外部调用

// 根据进程号(PID)在系统中所有句柄内搜索该进程的进程句柄(类似OpenProcess，但是不可以指定权限，可以用来越权操作进程)
inline std::vector<HANDLE> SearchTargetProcessHandle(DWORD processId) {
	return _SearchTargetProcessHandle(processId);
}

// 获取进程所有句柄 (会返回无效句柄)
inline std::vector<HANDLE> GetProcessHandles(DWORD processId) {
	return _GetProcessHandles(processId);
}

// 获取进程所有文件句柄 (会返回无效句柄)
inline std::vector<HANDLE> GetTargetFileHandles(DWORD processId) {
	return _GetTargetFileHandles(processId);
}

// 根据其他进程的文件句柄获取文件路径，失败返回false，采用DOS路径
inline std::string GetFilePathFromHandle(HANDLE targetHandle, DWORD targetProcessId) {
	return _GetFilePathFromHandle(targetHandle, targetProcessId);
}

// 获取进程打开的所有文件的全路径 (仅返回有效路径，但是需要注意的是若没有有效路径会返回空vector，同时返回的vector中默认包含文件夹路径，如果只希望返回文件可以将exportFolder参数传入false)
std::vector<std::string> GetTargetFilePaths(DWORD processId, bool exportFolder = true) {
	std::vector<HANDLE> processFileHandles = _GetTargetFileHandles(processId); // 进程打开的所有文件句柄
	std::vector<std::string> result(processFileHandles.size(), ""); // 返回的结果(进程打开的所有文件的全路径)

	int realSize = result.size(), i = 0;
	for (const HANDLE &h : processFileHandles) {
		try {
			result[i] = _GetFilePathFromHandle(h, processId);
			if (result[i] == "" || result[i][0] == '\0') { // 获取到的路径无效，该位置留给下一个元素
				--realSize;
				continue;
			} // 如果获取到的路径有效的话正常继续执行
			if (!exportFolder) { // 此处没有直接用与运算符是为了手动短路进行优化
				if (GetFileAttributesA(result[i].data()) & FILE_ATTRIBUTE_DIRECTORY) { // 是文件夹，包括无法访问的文件都不加进去
					--realSize;
					continue;
				}
			}
			++i; // 如果一切正常的话就写入下一个位置，如果出问题了就会continue掉这一段，下次循环写的还是这个位置，这么操作可以适当优化读写
		} catch (const std::runtime_error &e) {
			if (std::string(e.what()).find("NtDuplicateObject()") == std::string::npos &&
			        std::string(e.what()).find("GetFinalPathNameByHandleA()") == std::string::npos) { // 针对NtDuplicateObject和GetFinalPathNameByHandleA两个函数，因为程序突然崩掉或者路径突然不存在导致的error很常见，因此这里过滤
				throw;
			}
		}
	}

	result.resize(realSize);
	return result;
}

#endif