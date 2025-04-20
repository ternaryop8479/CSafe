/*
 * toHandlesInfo.h
 * ��������̾��(�ļ����)��һ��ͷ�ļ�(���ļ���)��
 * ��Ternary_Operator��д����������Ե������̵ĸ�Ч�ļ������ѯ
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

// �����ŵ�APIʹ�����������ռ�
namespace {
	// ������Ϣö������
	typedef enum _OBJECT_INFORMATION_CLASS {
		ObjectBasicInformation,       // ���ڲ�ѯ����Ļ�����Ϣ
		ObjectNameInformation,        // ���ڲ�ѯ�����������Ϣ
		ObjectTypeInformation,        // ���ڲ�ѯ�����������Ϣ
		ObjectAllInformation,         // ���ڲ�ѯ�����������Ϣ
		ObjectDataInformation         // ���ڲ�ѯ�����������Ϣ
	} OBJECT_INFORMATION_CLASS;

	// NtQuerySystemInformation����ԭ��
	typedef NTSTATUS (NTAPI *_NtQuerySystemInformation)(
	    ULONG SystemInformationClass,
	    PVOID SystemInformation,
	    ULONG SystemInformationLength,
	    PULONG ReturnLength
	);

	// NtDuplicateObject����ԭ��
	typedef NTSTATUS (NTAPI *pNtDuplicateObject)(
	    HANDLE SourceProcessHandle,
	    HANDLE SourceHandle,
	    HANDLE TargetProcessHandle,
	    PHANDLE TargetHandle,
	    ACCESS_MASK DesiredAccess,
	    ULONG HandleAttributes,
	    ULONG Options
	);

	// NtQueryObject����ԭ��
	typedef NTSTATUS (NTAPI *pNtQueryObject)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);

	// GetFinalPathNameByHandleA����ԭ�ͣ������ҵ�WinAPI����ľ��������������Լ��Ϸ�ֹ��ı��뻷��Ҳ���������ĲҾ�
	typedef DWORD (WINAPI *GetFinalPathNameByHandleA_t)(HANDLE, LPSTR, DWORD, DWORD);

	// ����ṹ��
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

	// ���ߺ�����д
	// NT·��תDOS·��
	std::string NTPathToDOSPath(const std::string &ntPath) {
		const char *ntPrefix = "\\\\?\\";
		size_t prefixLen = strlen(ntPrefix);

		if (ntPath.substr(0, prefixLen) != ntPrefix) {
			throw std::runtime_error("TOProtect-toHandlesInfo.h-NTPathToDOSPath(): Invalid NT path format.");
		}

		// ��ȡ·���е��������źͺ�������
		std::string dosPath = ntPath.substr(prefixLen);

		// ���·�����̷���ͷ���� C:\\����ֱ�ӷ���
		if (dosPath.size() >= 3 && dosPath[1] == ':' && dosPath[2] == '\\') {
			return dosPath;
		}

		// ���·�����̷���ͷ��û�з�б�ܣ���ӷ�б��
		if (dosPath.size() >= 2 && dosPath[1] == ':') {
			dosPath.insert(2, "\\");
			return dosPath;
		}

		// ���·���������̷���ͷ�����Խ���ΪDOS·��
		char buffer[MAX_PATH];
		DWORD result = QueryDosDeviceA(NULL, buffer, MAX_PATH);

		if (result == 0) {
			throw std::runtime_error(std::string("TOProtect-toHandlesInfo.h-NTPathToDOSPath(): Failed to query DOS devices. Error: ") + std::to_string(GetLastError()));
		}

		// �������ص��豸ӳ�䣬����ƥ���NT·��
		const char *device = buffer;
		while (*device) {
			size_t deviceLen = strlen(device);
			if (dosPath.find(device) == 0) {
				// �ҵ�ƥ����豸ӳ�䣬�滻ΪDOS·��
				dosPath.replace(0, deviceLen, device + deviceLen + 1);
				return dosPath;
			}
			device += deviceLen + 1;
		}

		throw std::runtime_error("TOProtect-toHandlesInfo.h-NTPathToDOSPath(): Failed to find a suitable path");
	}
	// �Ӿ����ȡ�ļ���(DOS·��)
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
	// ����ļ�����Ƿ����
	bool IsFileHandleValid(HANDLE hFile) {
		DWORD fileType = GetFileType(hFile);
		return fileType != FILE_TYPE_UNKNOWN;
	}
	// ��ȡ�ļ������ObjectTypeNumber
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

	const UCHAR fileHandleType = GetFileHandleType(); // �ļ�����ı��

	// ��װ��API

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
			if (handle.ObjectTypeNumber == 7) { // ObjectTypeNumber 7 �ǽ��̾��
				if (handle.ProcessId == processId) { // �㶼��Ȩ�޴���������˻���Ҫ�������ľ��ô��
					continue;
				}

				safeHANDLE ownerHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handle.ProcessId); // ��������ߵĽ��̾��
				if (!(ownerHandle())) {
//					throw std::runtime_error("TOProtect-toHandlesInfo.h-_SearchTargetProcessHandle(): Failed to OpenProcess()");
					continue;
				}

				// ���û�����򿽱����
				HANDLE duplicatedHandle;
				NTSTATUS status = NtDuplicateObject((ownerHandle()), reinterpret_cast<HANDLE>(handle.Handle), GetCurrentProcess(), &duplicatedHandle, GENERIC_ALL, 0, DUPLICATE_SAME_ACCESS);

				if (!NT_SUCCESS(status)) {
//					throw std::runtime_error("TOProtect-toHandlesInfo.h-_SearchTargetProcessHandle(): Failed to NtDuplicateObject()");
					continue;
				}

				if (GetProcessId(duplicatedHandle) == processId) { // ���ҵ�Ŀ�����
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

		// ��ȡNtDuplicateObject����ָ��
		pNtDuplicateObject NtDuplicateObject = (pNtDuplicateObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDuplicateObject");
		if (!NtDuplicateObject) {
			throw std::runtime_error("TOProtect-toHandlesInfo.h-_GetFilePathFromHandle(): Failed to load function NtDuplicateObject from ntdll.dll");
		}

		// ��Ŀ����̾��
		safeHANDLE targetProcessHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, targetProcessId);
		if (!(targetProcessHandle())) {
//			throw std::runtime_error("TOProtect-toHandlesInfo.h-_GetFilePathFromHandle(): Failed to OpenProcess()");
		}

		// ���ƾ������ǰ����
		safeHANDLE duplicatedHandle;
		NTSTATUS status = NtDuplicateObject((targetProcessHandle()), targetHandle, GetCurrentProcess(), &(duplicatedHandle()), GENERIC_READ, 0, DUPLICATE_SAME_ACCESS);

		if (!NT_SUCCESS(status)) {
//			throw std::runtime_error("TOProtect-toHandlesInfo.h-_GetFilePathFromHandle(): Failed to NtDuplicateObject()");
		}

		// ��ȡ�ļ�·��
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

//----------------�����ǿ���API�����Դ��ⲿ����

// ���ݽ��̺�(PID)��ϵͳ�����о���������ý��̵Ľ��̾��(����OpenProcess�����ǲ�����ָ��Ȩ�ޣ���������ԽȨ��������)
inline std::vector<HANDLE> SearchTargetProcessHandle(DWORD processId) {
	return _SearchTargetProcessHandle(processId);
}

// ��ȡ�������о�� (�᷵����Ч���)
inline std::vector<HANDLE> GetProcessHandles(DWORD processId) {
	return _GetProcessHandles(processId);
}

// ��ȡ���������ļ���� (�᷵����Ч���)
inline std::vector<HANDLE> GetTargetFileHandles(DWORD processId) {
	return _GetTargetFileHandles(processId);
}

// �����������̵��ļ������ȡ�ļ�·����ʧ�ܷ���false������DOS·��
inline std::string GetFilePathFromHandle(HANDLE targetHandle, DWORD targetProcessId) {
	return _GetFilePathFromHandle(targetHandle, targetProcessId);
}

// ��ȡ���̴򿪵������ļ���ȫ·�� (��������Ч·����������Ҫע�������û����Ч·���᷵�ؿ�vector��ͬʱ���ص�vector��Ĭ�ϰ����ļ���·�������ֻϣ�������ļ����Խ�exportFolder��������false)
std::vector<std::string> GetTargetFilePaths(DWORD processId, bool exportFolder = true) {
	std::vector<HANDLE> processFileHandles = _GetTargetFileHandles(processId); // ���̴򿪵������ļ����
	std::vector<std::string> result(processFileHandles.size(), ""); // ���صĽ��(���̴򿪵������ļ���ȫ·��)

	int realSize = result.size(), i = 0;
	for (const HANDLE &h : processFileHandles) {
		try {
			result[i] = _GetFilePathFromHandle(h, processId);
			if (result[i] == "" || result[i][0] == '\0') { // ��ȡ����·����Ч����λ��������һ��Ԫ��
				--realSize;
				continue;
			} // �����ȡ����·����Ч�Ļ���������ִ��
			if (!exportFolder) { // �˴�û��ֱ�������������Ϊ���ֶ���·�����Ż�
				if (GetFileAttributesA(result[i].data()) & FILE_ATTRIBUTE_DIRECTORY) { // ���ļ��У������޷����ʵ��ļ������ӽ�ȥ
					--realSize;
					continue;
				}
			}
			++i; // ���һ�������Ļ���д����һ��λ�ã�����������˾ͻ�continue����һ�Σ��´�ѭ��д�Ļ������λ�ã���ô���������ʵ��Ż���д
		} catch (const std::runtime_error &e) {
			if (std::string(e.what()).find("NtDuplicateObject()") == std::string::npos &&
			        std::string(e.what()).find("GetFinalPathNameByHandleA()") == std::string::npos) { // ���NtDuplicateObject��GetFinalPathNameByHandleA������������Ϊ����ͻȻ��������·��ͻȻ�����ڵ��µ�error�ܳ���������������
				throw;
			}
		}
	}

	result.resize(realSize);
	return result;
}

#endif