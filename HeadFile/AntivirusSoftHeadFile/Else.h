/*
 * Else.h
 * 包含杀毒软件处理时的一些其他杂项(关机等)
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#pragma once

#include <windows.h>
#include <fstream>
#include <exception>
#include <mutex>
#include <atomic>
#include <condition_variable>
#define SELFSTART_REGEDIT_PATH "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"//定义写入的注册表路径

class MultiMutex {
	private:
		std::mutex opMutex; // 用来保证 lock 与 unlock 函数原子性的 mutex
		std::condition_variable cv; // 用来阻塞进程运行的 condition_variable
		std::atomic<unsigned long> usingNum; // 正在使用该互斥锁的进程的数量
		std::atomic<unsigned long> maxUsingNum; // 可以使用该锁的进程总数
		std::atomic_bool isAvailable; // 互斥量是否可用(即是否初始化，能否调用lock与unlock)

	public:
		MultiMutex() : isAvailable(false), usingNum(0) {}
		MultiMutex(unsigned long maxNum) : isAvailable(true), usingNum(0), maxUsingNum(maxNum) {}
		void init(unsigned long maxNum) {
			if (isAvailable) {
				throw std::runtime_error("Mutex is already inited.");
				return;
			}
			isAvailable = true;
			usingNum = 0;
			maxUsingNum = maxNum;
		}

		void lock() {
			if (!isAvailable) {
				throw std::runtime_error("Mutex is not init yet.");
				return;
			}
			std::unique_lock<std::mutex> lock(opMutex);
			// 等待直到使用数小于最大允许数
			cv.wait(lock, [this] { return usingNum < maxUsingNum; });
			// 增加正在使用的数量
			usingNum++;
		}

		void unlock() {
			if (!isAvailable) {
				throw std::runtime_error("Mutex is not init yet.");
				return;
			}
			std::unique_lock<std::mutex> lock(opMutex);
			// 减少正在使用的数量
			if (usingNum == 0) {
				//throw std::logic_error("There is no thread using the mutex.");
				return;
			}
			usingNum--;
			// 通知一个等待的进程
			cv.notify_one();
		}
};

std::string toCAP(std::string str) {
	for (int i = 0; i < str.size(); (str[i] >= 'a' && str[i] <= 'z') ? (str[i] -= 32) : 0, ++i);
	return str;
}

std::string GetFileExtension(const std::string &filePath) {
	// 查找文件路径中最后一个"."的位置
	size_t pos = filePath.rfind('.');
	// 如果没有找到"."或者"."是最后一个字符，则没有扩展名
	if (pos == std::string::npos || pos == filePath.length() - 1) {
		return "";
	}
	// 从最后一个"."之后开始截取字符串作为扩展名
	return filePath.substr(pos + 1);
}

bool IsUserAnAdmin() {
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;  //判断是否有管理员权限
	PSID AdministratorsGroup;
	BOOL b = AllocateAndInitializeSid(
	             &NtAuthority,
	             2,
	             SECURITY_BUILTIN_DOMAIN_RID,
	             DOMAIN_ALIAS_RID_ADMINS,
	             0, 0, 0, 0, 0, 0,
	             &AdministratorsGroup);
	if (b) {
		CheckTokenMembership(NULL, AdministratorsGroup, &b);
		FreeSid(AdministratorsGroup);
	}

	return (b == TRUE) ? true : false;
}

bool SetStart(bool bKey) {//设置启动项
	//获取程序完整路径
	char pName[MAX_PATH] = { 0 };
	GetModuleFileNameA(NULL, pName, MAX_PATH);
	//在注册表中写入启动信息
	HKEY hKey = NULL;
	LONG lRet = 0;
	if ( bKey) {
		//打开注册表
		lRet = RegOpenKeyExA(HKEY_LOCAL_MACHINE, SELFSTART_REGEDIT_PATH, 0, KEY_ALL_ACCESS, &hKey);
		//判断是否成功
		if (lRet != ERROR_SUCCESS) {
			return false;
		} else {

			//写入注册表，名为Cdun.
			RegSetValueExA(hKey, "CSafe", 0, REG_SZ, (const unsigned char *)pName, strlen(pName) + sizeof(char));

			//关闭注册表
			RegCloseKey(hKey);
			return true;
		}
	} else {
		lRet = RegOpenKeyExA(HKEY_LOCAL_MACHINE, SELFSTART_REGEDIT_PATH, 0, KEY_ALL_ACCESS, &hKey);
		//判断是否成功
		if (lRet != ERROR_SUCCESS) {
			return false;
		} else {

			//删除名为Cdun的注册表信息
			RegDeleteValueA(hKey, "CSafe");

			//关闭注册表
			RegCloseKey(hKey);
			return true;
		}
	}
}

void DisableFastMake() {
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
	DWORD mode;
	GetConsoleMode(hStdin, &mode);
	mode &= ~ENABLE_QUICK_EDIT_MODE;  // 移除快速编辑模式
	mode |= ENABLE_INSERT_MODE;       // 开启插入模式
	mode &= ~ENABLE_MOUSE_INPUT;      // 禁用鼠标编辑
	SetConsoleMode(hStdin, mode);
}

unsigned long getFileSize(const std::string &filePath) {
	std::ifstream file(filePath, std::ifstream::in | std::ifstream::binary);
	if (file.is_open()) {
		file.seekg(0, std::ios::end);
		return file.tellg(); // tellg 获取文件大小
	}
	return 0;
}

bool ShutdownSystem(void) {
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;

	if (!OpenProcessToken(GetCurrentProcess(),
	                      TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return false;

	LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME,
	                     &tkp.Privileges[0].Luid);

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(hToken, FALSE, &tkp, 0,
	                      (PTOKEN_PRIVILEGES)NULL, 0);

	if (GetLastError() != ERROR_SUCCESS)
		return false;

	if (!ExitWindowsEx(EWX_SHUTDOWN | EWX_FORCE,
	                   SHTDN_REASON_MAJOR_OPERATINGSYSTEM |
	                   SHTDN_REASON_FLAG_PLANNED))
		return false;

	return true;
}

bool RebootSystem(void) {
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;

	if (!OpenProcessToken(GetCurrentProcess(),
	                      TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return false;

	LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME,
	                     &tkp.Privileges[0].Luid);

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(hToken, FALSE, &tkp, 0,
	                      (PTOKEN_PRIVILEGES)NULL, 0);

	if (GetLastError() != ERROR_SUCCESS)
		return false;

	if (!ExitWindowsEx(EWX_REBOOT | EWX_FORCE,
	                   SHTDN_REASON_MAJOR_OPERATINGSYSTEM |
	                   SHTDN_REASON_FLAG_PLANNED))
		return false;

	return true;
}