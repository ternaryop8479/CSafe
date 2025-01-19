/*
 * EngineHeadFile/TOProtect.h
 * CSafe杀毒引擎子引擎TOProtect的功能性函数定义
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#pragma once

#include <string>
#include <vector>
#include <Windows.h>
#include <tlHelp32.h>
#include <shellapi.h>
#include <comutil.h>
#include <shldisp.h>
#include <iphlpapi.h>
#include <shobjidl.h>
#include <psapi.h>
#include <tchar.h>

//DLL注入
bool InjectDLL(DWORD processID, const char *dllPath) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	if (!hProcess) {
		return false;
	}

	LPVOID pDllPath = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(hProcess, pDllPath, (LPVOID)dllPath, strlen(dllPath) + 1, NULL);

	FARPROC pLoadLibrary = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pDllPath, 0, NULL);
	if (!hThread) {
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	WaitForSingleObject(hThread, INFINITE);

	VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
	CloseHandle(hThread);
	CloseHandle(hProcess);
	return true;
}

BOOL DosPathToNtPath(LPTSTR pszDosPath, LPTSTR pszNtPath) {
	TCHAR            szDriveStr[500];
	TCHAR            szDrive[3];
	TCHAR            szDevName[100];
	INT                cchDevName;
	INT                i;

	//检查参数
	if (!pszDosPath || !pszNtPath )
		return FALSE;

	//获取本地磁盘字符串
	if (GetLogicalDriveStrings(sizeof(szDriveStr), szDriveStr)) {
		for (i = 0; szDriveStr[i]; i += 4) {
			if (!lstrcmpi(&(szDriveStr[i]), _T("A:\\")) || !lstrcmpi(&(szDriveStr[i]), _T("B:\\")))
				continue;

			szDrive[0] = szDriveStr[i];
			szDrive[1] = szDriveStr[i + 1];
			szDrive[2] = '\0';
			if (!QueryDosDevice(szDrive, szDevName, 100)) //查询 Dos 设备名
				return FALSE;

			cchDevName = lstrlen(szDevName);
			if (_tcsnicmp(pszDosPath, szDevName, cchDevName) == 0) { //命中
				lstrcpy(pszNtPath, szDrive);//复制驱动器
				lstrcat(pszNtPath, pszDosPath + cchDevName);//复制路径

				return TRUE;
			}
		}
	}

	lstrcpy(pszNtPath, pszDosPath);

	return FALSE;
}

BOOL GetProcessPath(DWORD dwPID, TCHAR pszFullPath[MAX_PATH]) {//获取程序全路径
	pszFullPath[0] = '\0';
	TCHAR szImagePath[MAX_PATH];
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, 0, dwPID);
	if (!hProcess)
		return FALSE;

	if (!GetProcessImageFileName(hProcess, szImagePath, MAX_PATH)) {
		CloseHandle(hProcess);
		return FALSE;
	}

	if (!DosPathToNtPath(szImagePath, pszFullPath)) {
		CloseHandle(hProcess);
		return FALSE;
	}

	CloseHandle(hProcess);

	return TRUE;
}

std::string GetProcessFullPath(const PROCESSENTRY32 process) {//获取指定程序全路径
	DWORD dwPID = process.th32ProcessID;
	TCHAR pszFullPath[MAX_PATH];

	pszFullPath[0] = '\0';
	TCHAR szImagePath[MAX_PATH];
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, 0, dwPID);
	if (!hProcess)
		return process.szExeFile;

	if (!GetProcessImageFileName(hProcess, szImagePath, MAX_PATH)) {
		CloseHandle(hProcess);
		return process.szExeFile;
	}

	if (!DosPathToNtPath(szImagePath, pszFullPath)) {
		CloseHandle(hProcess);
		return process.szExeFile;
	}

	CloseHandle(hProcess);

	return std::string(pszFullPath);
}

bool IsFileHidden(const std::string &filePath) {
	DWORD fileAttributes = GetFileAttributesA(filePath.c_str());
	if (fileAttributes == INVALID_FILE_ATTRIBUTES) {
		// 获取文件属性失败，可能是文件不存在或者路径错误
		return false;
	}

	// 检查文件是否标记为隐藏
	return (fileAttributes & FILE_ATTRIBUTE_HIDDEN) != 0;
}


std::string GetRegistryKeyValue(HKEY hKeyParent, std::string subkey, std::string keyName) {//获取注册表键值
	HKEY hKey;
	if (RegOpenKeyEx(hKeyParent, subkey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
		return "";
	}

	char value[1024];
	DWORD value_length = 1024;
	if (RegQueryValueEx(hKey, keyName.c_str(), NULL, NULL, (LPBYTE)&value, &value_length) != ERROR_SUCCESS) {
		RegCloseKey(hKey);
		return "";
	}

	RegCloseKey(hKey);
	return std::string(value);
}

void FilterProgramName(std::string &str) {//将带参数和双引号的程序过滤，只留下程序全路径
	size_t last_quote = str.find_last_of('\"');

	// 检查是否存在引号
	if (last_quote != std::string::npos) {
		str = str.substr(1, last_quote - 1);
	}
}

std::string GetShortcutPath(const std::string &shortcut_path) {//获取快捷方式源路径
	CoInitialize(NULL);

	IShellLinkW *psl;
	HRESULT hres = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (LPVOID *)&psl);
	std::string result;

	if (SUCCEEDED(hres)) {
		IPersistFile *ppf;
		hres = psl->QueryInterface(IID_IPersistFile, (void **)&ppf);

		if (SUCCEEDED(hres)) {
			WCHAR wsz[MAX_PATH];
			MultiByteToWideChar(CP_ACP, 0, shortcut_path.c_str(), -1, wsz, MAX_PATH);

			hres = ppf->Load(wsz, STGM_READ);

			if (SUCCEEDED(hres)) {
				WCHAR psz[MAX_PATH];
				WIN32_FIND_DATAW wfd;
				hres = psl->GetPath(psz, MAX_PATH, &wfd, SLGP_UNCPRIORITY);

				if (SUCCEEDED(hres)) {
					char ch[MAX_PATH];
					WideCharToMultiByte(CP_ACP, 0, psz, -1, ch, MAX_PATH, NULL, NULL);
					result = ch;
				}
			}

			ppf->Release();
		}

		psl->Release();
	}

	CoUninitialize();

	return result;
}

std::vector<std::string> getStartupItems() {
	std::vector<std::string> startupItems;
	// 获取注册表启动项
	HKEY hKey;
	LONG result = RegOpenKeyEx(HKEY_CURRENT_USER, TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Run"), 0, KEY_READ,
	                           &hKey);

	if (result == ERROR_SUCCESS) {
		TCHAR    achKey[MAX_PATH];
		DWORD    cbName;
		TCHAR    achClass[MAX_PATH] = TEXT("");
		DWORD    cchClassName = MAX_PATH;
		DWORD    cSubKeys = 0;
		DWORD    cbMaxSubKey;
		DWORD    cchMaxClass;
		DWORD    cValues;
		DWORD    cchMaxValue;
		DWORD    cbMaxValueData;
		DWORD    cbSecurityDescriptor;
		FILETIME ftLastWriteTime;

		DWORD i, retCode;

		TCHAR  achValue[MAX_PATH];
		DWORD cchValue = MAX_PATH;

		// 获取信息关于顶级键
		retCode = RegQueryInfoKey(
		              hKey,
		              achClass,
		              &cchClassName,
		              NULL,
		              &cSubKeys,
		              &cbMaxSubKey,
		              &cchMaxClass,
		              &cValues,
		              &cchMaxValue,
		              &cbMaxValueData,
		              &cbSecurityDescriptor,
		              &ftLastWriteTime);

		if (cValues) {
			for (i = 0, retCode = ERROR_SUCCESS; i < cValues; i++) {
				cchValue = MAX_PATH;
				achValue[0] = '\0';
				retCode = RegEnumValue(hKey, i,
				                       achValue,
				                       &cchValue,
				                       NULL,
				                       NULL,
				                       NULL,
				                       NULL);

				if (retCode == ERROR_SUCCESS) {
					std::string pusb = GetRegistryKeyValue(HKEY_CURRENT_USER, TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
					                                       achValue);
					FilterProgramName(pusb);
					startupItems.push_back(pusb);
				}
			}
		}
	}

	//加载位于HKEY_LOCAL_MACHINE的启动项

	result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Run"), 0, KEY_READ,
	                      &hKey);

	if (result == ERROR_SUCCESS) {
		TCHAR    achKey[MAX_PATH];
		DWORD    cbName;
		TCHAR    achClass[MAX_PATH] = TEXT("");
		DWORD    cchClassName = MAX_PATH;
		DWORD    cSubKeys = 0;
		DWORD    cbMaxSubKey;
		DWORD    cchMaxClass;
		DWORD    cValues;
		DWORD    cchMaxValue;
		DWORD    cbMaxValueData;
		DWORD    cbSecurityDescriptor;
		FILETIME ftLastWriteTime;

		DWORD i, retCode;

		TCHAR  achValue[MAX_PATH];
		DWORD cchValue = MAX_PATH;

		// 获取信息关于顶级键
		retCode = RegQueryInfoKey(
		              hKey,
		              achClass,
		              &cchClassName,
		              NULL,
		              &cSubKeys,
		              &cbMaxSubKey,
		              &cchMaxClass,
		              &cValues,
		              &cchMaxValue,
		              &cbMaxValueData,
		              &cbSecurityDescriptor,
		              &ftLastWriteTime);

		if (cValues) {
			for (i = 0, retCode = ERROR_SUCCESS; i < cValues; i++) {
				cchValue = MAX_PATH;
				achValue[0] = '\0';
				retCode = RegEnumValue(hKey, i,
				                       achValue,
				                       &cchValue,
				                       NULL,
				                       NULL,
				                       NULL,
				                       NULL);

				if (retCode == ERROR_SUCCESS) {
					std::string pusb = GetRegistryKeyValue(HKEY_LOCAL_MACHINE, TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
					                                       achValue);
					FilterProgramName(pusb);
					startupItems.push_back(pusb);
				}
			}
		}
	}

	// 获取快速启动目录的启动项
	WIN32_FIND_DATA findFileData;
	TCHAR *AppDataPath = getenv("appdata");
	TCHAR hfIn[MAX_PATH];
	sprintf(hfIn, "%s\\Microsoft\\Internet Explorer\\Quick Launch\\*", AppDataPath);
	HANDLE hFind = FindFirstFile(hfIn, &findFileData);

	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
				startupItems.push_back(GetShortcutPath((std::string)(AppDataPath) +
				                                       (std::string)"\\Microsoft\\Internet Explorer\\Quick Launch\\" +
				                                       (findFileData.cFileName)));
			}
		} while (FindNextFile(hFind, &findFileData));
		FindClose(hFind);
	}

	return startupItems;
}

///////////////////////////////////////////////
//IEFO映像劫持检测

std::vector<std::string> ScanIEFO(void) {
	const std::string keyPath = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
	HKEY hKey;
	std::vector<std::string> ValueReturn;
	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
		DWORD index = 0;
		CHAR subKeyName[256];
		while (RegEnumKeyA(hKey, index, subKeyName, sizeof(subKeyName)) == ERROR_SUCCESS) {
			std::string subKeyPath = keyPath + "\\" + subKeyName;

			HKEY hSubKey;
			if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKeyPath.c_str(), 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
				DWORD valueType;
				DWORD valueSize;
				if (RegQueryValueExA(hSubKey, "Debugger", nullptr, &valueType, nullptr, &valueSize) == ERROR_SUCCESS) {
					if (valueType == REG_SZ || valueType == REG_EXPAND_SZ) {
						CHAR debuggerValue[256];
						if (RegQueryValueExA(hSubKey, "Debugger", nullptr, nullptr, reinterpret_cast<LPBYTE>(debuggerValue),
						                     &valueSize) == ERROR_SUCCESS) {
							std::string str_debuggerValue = debuggerValue;
							ValueReturn.push_back(str_debuggerValue);
						}
					}
				}

				RegCloseKey(hSubKey);
			}

			index++;
		}

		RegCloseKey(hKey);
	}
	return ValueReturn;
}

bool IsProcessElevatedForProcessID(DWORD ProcessID) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);
	HANDLE hToken;
	TOKEN_ELEVATION elevation;
	DWORD dwSize;

	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
		return false;
	}

	if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
		CloseHandle(hToken);
		return false;
	}

	CloseHandle(hToken);
	return (elevation.TokenIsElevated != 0);
}