/*
 * LSProtect.h
 * CSafe杀毒引擎子引擎LSProtect的API封装及定义(LSProtect为基于导入表的启发引擎)
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#pragma once

#include <unordered_map>
#include <string>
#include <fstream>
#include "EngineHeadFile/LSProtect.h"

//主黑名单(导入表)
#include "EngineHeadFile/ImportBlackList.h"

//病毒种类分类列表

/*
//后门木马常见函数(提权->隐藏->cmd执行/键鼠获取/网络连接)
const std::unordered_map<std::string, short> Black_List_Backdoor {
	{"GetRawInputData", 12},//获取键鼠
	{"GetAsyncKeyState", 12},//获取键盘输入
	{"SetWindowsHookEx", 8},//获取键鼠输入&dll注入
	{"CreateRemoteThread", 5},//创建远程线程(注入)
	{"GetProcAddress", 5},//获取程序地址(使用未声明的关键字)
	{"WinHttpConnect", 5},//网络端
	{"socket", 4},
	{"connect", 4},
	{"GetWindow", 2}
};
*/

//DDoS木马常见函数(提权->隐藏->发包)
const std::unordered_map<std::string, short> Black_List_DDoS_LSProtect {
	{"WinHttpConnect", 14},//攻击网站
	{"sendto", 12},
	{"IcmpSendEcho", 14}
};

//勒索木马常见函数(提权->访问文件系统/弹窗&置顶)
const std::unordered_map<std::string, short> Black_List_BlackMail_LSProtect {
	{"CreateFile", 14},
	{"CreateFileA", 14},//打开文件
	{"CreateFileW", 14},
	{"fopen", 14},
	{"CreateWindowA", 8},
	{"CreateWindowW", 8},
	{"CreateWindowExA", 8},
	{"CreateWindowExW", 8},
	{"MessageBoxA", 8},
	{"MessageBoxW", 8},
	{"SetWindowPos", 10}
};

//远控木马常见函数(提权->隐藏->cmd执行/键鼠控制&获取/网络连接/注册表/屏幕快照)
const std::unordered_map<std::string, short> Black_List_RemoteControl_LSProtect {
	{"system", 4},
	{"GetRawInputData", 18},//获取键鼠
	{"GetAsyncKeyState", 18},//获取键盘输入
	{"SetWindowsHookEx", 14},//获取键鼠输入&dll注入
	{"socket", 2},
	{"connect", 2},
	{"BitBlt", 18},//截图
	{"CreateCompatibleDC", 10},//截图
	{"CreateCompatibleBitmap", 10},//截图
	{"SetCursorPos", 18},//控制鼠标
	{"keybd_event", 18}//控制键盘
};


//蠕虫拉黑列表

//蠕虫病毒常见函数(提权->复制->运行核心处理程序->更改&破坏&删除文件/更改系统设置)
const std::unordered_map<std::string, short> Black_List_Worm_LSProtect {
	{"URLDownloadToFile", 8},//下载文件
	{"SetFileAttributes", 10},
	{"SetFileAttributesW", 10},//设置文件属性
	{"SetFileAttributesA", 10},
	{"fopen", 10},
	{"RegOpenKey", 4},
	{"RegOpenKeyA", 4},
	{"RegOpenKeyW", 4},
	{"RegOpenKeyEx", 4},
	{"RegOpenKeyExA", 4},//注册表访问
	{"RegOpenKeyExW", 4},
	{"RegCloseKey", 4},
	{"RegCloseKeyA", 4},
	{"RegCloseKeyW", 4},
	{"CreateFile", 10},
	{"CreateFileA", 10},//打开文件
	{"CreateFileW", 10},
	{"ShellExecute", 8},
	{"ShellExecuteA", 8},
	{"ShellExecuteW", 8}
};


//其他拉黑列表

//破坏性病毒常见函数(提权->杀进程/删文件/删注册表/禁用一系列东东/执行cmd)
const std::unordered_map<std::string, short> Black_List_Killer_LSProtect {
	{"TerminateProcess", 14},//杀进程
	{"NtTerminateProcess", 14},
	{"ZwTerminateProcess", 14},
	{"PsTerminateProcess", 14},
	{"PspTerminateProcess", 14},
	{"PspTerminateThreadByPoint", 14},
	{"PspExitThread", 14},
	{"GetProcAddress", 14},//获取程序地址(使用未声明的关键字)，同样可以用于隐藏
	{"remove", 14},//删文件
	{"DeleteFile", 14},
	{"ZwDeleteFile", 14},
	{"DeviceIoControl", 14},
	{"LockFile", 14},
	{"RaiseFailFastException", 14}
};

//恶搞病毒常见函数(提权->置顶&弹窗)
//不是谁他喵闲的没事做破坏类恶搞啊？这玩意有用？你还得让我再给你开个分类，这不是为难人么？写恶搞没技术的都是滞涨，我说的！！
const std::unordered_map<std::string, short> Black_List_Kidding_LSProtect {
	{"MessageBox", 1},
	{"SetWindowPos", 1}//行了差不多得了你做个恶搞还要什么nb的东西
};

std::string _LSProtect(const std::string TargetPath, const bool EnableSensitiveMode = false) {
	short AllRiskLevel = 0;//总危险等级

	//获取导入表
	std::vector<std::pair<std::string, std::string>> TargetIn = calculatePEImportMap(TargetPath);

	if (TargetIn[0].first.find("Error_") != std::string::npos && TargetIn[0].first.find("Import") == std::string::npos) {//获取导入表失败
		const std::string errorCode = "[" + TargetIn[0].first + "]";
		return errorCode;
	}

	for (int i = 0; i < TargetIn.size(); ++i)
		if (TargetIn[i].second.size() <= 2)
			TargetIn.erase(TargetIn.begin() + i);

	if (TargetIn.size() <= 6) { //在导入表较少的情况下
		bool LoadLibraryFlag = false, GetProcAddressFlag = false;
		for (int i = 0; i < TargetIn.size(); ++i) {
			if (TargetIn[i].second.find("LoadLibrary") != std::string::npos)
				LoadLibraryFlag = true;
			if (TargetIn[i].second.find("GetProcAddress") != std::string::npos)
				GetProcAddressFlag = true;
		}
		if (LoadLibraryFlag && GetProcAddressFlag)
			return "Malware.VirusBox";//简单的病毒加壳检测
	}

	for (int i = 0; i < TargetIn.size(); ++i) {//获取总危险等级
		auto Result = Main_Black_List_LSProtect.find(TargetIn[i].second);
		if (Result != Main_Black_List_LSProtect.end()) {
			AllRiskLevel += Result->second;
		}
	}

	if (EnableSensitiveMode) { //如果启用高敏感度模式
		if (AllRiskLevel >= 668) {
			short RiskLevel = 0;

			//DDoS木马
			for (int i = 0; i < TargetIn.size(); ++i) {//获取总危险等级
				auto Result = Black_List_DDoS_LSProtect.find(TargetIn[i].second);
				if (Result != Black_List_DDoS_LSProtect.end()) {
					RiskLevel += Result->second;
				}
			}

			if (RiskLevel >= 14) {
				return "Malware.Trojan.DDoS";
			}
			RiskLevel = 0;

			//远控木马
			for (int i = 0; i < TargetIn.size(); ++i) {//获取总危险等级
				auto Result = Black_List_RemoteControl_LSProtect.find(TargetIn[i].second);
				if (Result != Black_List_RemoteControl_LSProtect.end()) {
					RiskLevel += Result->second;
				}
			}

			if (RiskLevel >= 21) {
				return "Malware.Trojan.RemoteControl";
			}
			RiskLevel = 0;

			//勒索木马
			for (int i = 0; i < TargetIn.size(); ++i) {//获取总危险等级
				auto Result = Black_List_BlackMail_LSProtect.find(TargetIn[i].second);
				if (Result != Black_List_BlackMail_LSProtect.end()) {
					RiskLevel += Result->second;
				}
			}

			if (RiskLevel >= 22) {
				return "Malware.Trojan.Blackmail";
			}
			RiskLevel = 0;

			//破坏性病毒
			for (int i = 0; i < TargetIn.size(); ++i) {//获取总危险等级
				auto Result = Black_List_Killer_LSProtect.find(TargetIn[i].second);
				if (Result != Black_List_Killer_LSProtect.end()) {
					RiskLevel += Result->second;
				}
			}

			if (RiskLevel >= 14) {
				return "Malware.Killer";
			}
			RiskLevel = 0;

			//蠕虫病毒
			for (int i = 0; i < TargetIn.size(); ++i) {//获取总危险等级
				auto Result = Black_List_Worm_LSProtect.find(TargetIn[i].second);
				if (Result != Black_List_Worm_LSProtect.end()) {
					RiskLevel += Result->second;
				}
			}

			if (RiskLevel >= 22) {
				return "Malware.Worm";
			}
			RiskLevel = 0;

			//恶搞病毒
			for (int i = 0; i < TargetIn.size(); ++i) {//获取总危险等级
				auto Result = Black_List_Kidding_LSProtect.find(TargetIn[i].second);
				if (Result != Black_List_Kidding_LSProtect.end()) {
					RiskLevel += Result->second;
				}
			}

			if (RiskLevel >= 1) {
				return "Malware.Kidding";
			}
			RiskLevel = 0;
		} else {
			return "disVirus";
		}
	} else {//禁用高敏感模式
		if (AllRiskLevel >= 700) {
			short RiskLevel = 0;

			//DDoS木马
			for (int i = 0; i < TargetIn.size(); ++i) {//获取总危险等级
				auto Result = Black_List_DDoS_LSProtect.find(TargetIn[i].second);
				if (Result != Black_List_DDoS_LSProtect.end()) {
					RiskLevel += Result->second;
				}
			}

			if (RiskLevel >= 14) {
				return "Malware.Trojan.DDoS";
			}
			RiskLevel = 0;

			//远控木马
			for (int i = 0; i < TargetIn.size(); ++i) {//获取总危险等级
				auto Result = Black_List_RemoteControl_LSProtect.find(TargetIn[i].second);
				if (Result != Black_List_RemoteControl_LSProtect.end()) {
					RiskLevel += Result->second;
				}
			}

			if (RiskLevel >= 21) {
				return "Malware.Trojan.RemoteControl";
			}
			RiskLevel = 0;

			//勒索木马
			for (int i = 0; i < TargetIn.size(); ++i) {//获取总危险等级
				auto Result = Black_List_BlackMail_LSProtect.find(TargetIn[i].second);
				if (Result != Black_List_BlackMail_LSProtect.end()) {
					RiskLevel += Result->second;
				}
			}

			if (RiskLevel >= 22) {
				return "Malware.Trojan.Blackmail";
			}
			RiskLevel = 0;

			//破坏性病毒
			for (int i = 0; i < TargetIn.size(); ++i) {//获取总危险等级
				auto Result = Black_List_Killer_LSProtect.find(TargetIn[i].second);
				if (Result != Black_List_Killer_LSProtect.end()) {
					RiskLevel += Result->second;
				}
			}

			if (RiskLevel >= 14) {
				return "Malware.Killer";
			}
			RiskLevel = 0;

			//蠕虫病毒
			for (int i = 0; i < TargetIn.size(); ++i) {//获取总危险等级
				auto Result = Black_List_Worm_LSProtect.find(TargetIn[i].second);
				if (Result != Black_List_Worm_LSProtect.end()) {
					RiskLevel += Result->second;
				}
			}

			if (RiskLevel >= 22) {
				return "Malware.Worm";
			}
			RiskLevel = 0;

			//恶搞病毒
			for (int i = 0; i < TargetIn.size(); ++i) {//获取总危险等级
				auto Result = Black_List_Kidding_LSProtect.find(TargetIn[i].second);
				if (Result != Black_List_Kidding_LSProtect.end()) {
					RiskLevel += Result->second;
				}
			}

			if (RiskLevel >= 1) {
				return "Malware.Kidding";
			}
			RiskLevel = 0;
		} else {
			return "disVirus";
		}
	}

	return "Virus.UnknownVirus";
}