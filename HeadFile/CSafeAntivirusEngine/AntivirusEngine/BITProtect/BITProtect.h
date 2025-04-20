/*
 * BITProtect.h
 * CSafe杀毒引擎子引擎BITProtect的API封装及定义(BITProtect为基于PE文件函数特征的启发式引擎)
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#pragma once

#include <unordered_map>
#include <string>
#include <fstream>
#include "EngineHeadFile/BITProtect.h"
#include "EngineHeadFile/MalwarePEList.h"
#include "EngineHeadFile/WhitePEList_System.h"
#include "EngineHeadFile/WhitePEList_Normal.h"

//DDoS木马常见函数(提权->隐藏->发包)
const std::unordered_map<std::string, short> Black_List_DDoS_BITProtect {
	{"WinHttpConnect", 14},//攻击网站
	{"sendto", 12},
	{"IcmpSendEcho", 14}
};

//勒索木马常见函数(提权->访问文件系统/弹窗&置顶)
const std::unordered_map<std::string, short> Black_List_BlackMail_BITProtect {
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
const std::unordered_map<std::string, short> Black_List_RemoteControl_BITProtect {
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
const std::unordered_map<std::string, short> Black_List_Worm_BITProtect {
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
const std::unordered_map<std::string, short> Black_List_Killer_BITProtect {
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
const std::unordered_map<std::string, short> Black_List_Kidding_BITProtect {
	{"MessageBox", 1},
	{"SetWindowPos", 1}//行了差不多得了你做个恶搞还要什么nb的东西
};

std::string _BITProtect(const std::string TargetPath, const float BlackWeight = 1.0, const float WhiteWeight = 1.0) {
	//获取导入表
	std::vector<std::string> TargetIn = getPEFileReadableStrings(TargetPath);

	if (TargetIn[0].find("Error_") != std::string::npos) {//获取PE可读信息失败
		const std::string errorCode = "[" + TargetIn[0] + "]";
		return errorCode;
	}

	long AllRiskLevel = 0;//总危险等级
	long AllWhiteLevel_System = 0, AllWhiteLevel_Normal = 0;//白名单等级

	for (int i = 0; i < TargetIn.size(); ++i) {
		for (const auto &TargetErgo : BITProtect_Main_BlackList) {
			if (TargetIn[i].find(TargetErgo.first) != std::string::npos) {
				AllRiskLevel += TargetErgo.second;
				break;
			}
		}
		for (const auto &TargetErgo : BITProtect_Main_WhiteList_System) {
			if (TargetIn[i].find(TargetErgo.first) != std::string::npos) {
				AllWhiteLevel_System += TargetErgo.second;
				break;
			}
		}
		for (const auto &TargetErgo : BITProtect_Main_WhiteList_Normal) {
			if (TargetIn[i].find(TargetErgo.first) != std::string::npos) {
				AllWhiteLevel_Normal += TargetErgo.second;//这里本来是因为Normal的等级更高，但是因为Normal的条目被砍掉的比较多，故原size处理
				break;
			}
		}
		if ((AllWhiteLevel_System + AllWhiteLevel_Normal) / 2.0 >= 644810) {//此处计算出的值更加偏向系统文件
			return "disVirus";
		}
	}
	long AllWhiteLevel = (AllWhiteLevel_System + AllWhiteLevel_Normal) / 2.0;
	long DecideLevel = (AllRiskLevel * BlackWeight * 2.87) - (AllWhiteLevel * WhiteWeight * 1.94);//根据权重计算出最终决断等级, 2.87和1.94是在原始样本基础上加的权重

	if (DecideLevel >= 110552) {//沿袭无普通文件版计算结果
		short RiskLevel = 0;

		//DDoS木马
		for (int i = 0; i < TargetIn.size(); ++i) {
			for (const auto &TargetErgo : Black_List_DDoS_BITProtect) {
				if (TargetIn[i].find(TargetErgo.first) != std::string::npos) {
					RiskLevel += TargetErgo.second;
				}
			}
		}
		if (RiskLevel >= 14) {
			return "Malware.Trojan.DDoS";
		}
		RiskLevel = 0;

		//远控木马
		for (int i = 0; i < TargetIn.size(); ++i) {
			for (const auto &TargetErgo : Black_List_RemoteControl_BITProtect) {
				if (TargetIn[i].find(TargetErgo.first) != std::string::npos) {
					RiskLevel += TargetErgo.second;
				}
			}
		}
		if (RiskLevel >= 21) {
			return "Malware.Trojan.RemoteControl";
		}
		RiskLevel = 0;

		//勒索木马
		for (int i = 0; i < TargetIn.size(); ++i) {
			for (const auto &TargetErgo : Black_List_BlackMail_BITProtect) {
				if (TargetIn[i].find(TargetErgo.first) != std::string::npos) {
					RiskLevel += TargetErgo.second;
				}
			}
		}
		if (RiskLevel >= 22) {
			return "Malware.Trojan.Blackmail";
		}
		RiskLevel = 0;

		//破坏性病毒
		for (int i = 0; i < TargetIn.size(); ++i) {
			for (const auto &TargetErgo : Black_List_Killer_BITProtect) {
				if (TargetIn[i].find(TargetErgo.first) != std::string::npos) {
					RiskLevel += TargetErgo.second;
				}
			}
		}
		if (RiskLevel >= 14) {
			return "Malware.Killer";
		}
		RiskLevel = 0;

		//蠕虫病毒
		for (int i = 0; i < TargetIn.size(); ++i) {
			for (const auto &TargetErgo : Black_List_Worm_BITProtect) {
				if (TargetIn[i].find(TargetErgo.first) != std::string::npos) {
					RiskLevel += TargetErgo.second;
				}
			}
		}
		if (RiskLevel >= 22) {
			return "Malware.Worm";
		}
		RiskLevel = 0;

		//恶搞病毒
		for (int i = 0; i < TargetIn.size(); ++i) {
			for (const auto &TargetErgo : Black_List_Kidding_BITProtect) {
				if (TargetIn[i].find(TargetErgo.first) != std::string::npos) {
					RiskLevel += TargetErgo.second;
				}
			}
		}
		if (RiskLevel >= 1) {
			return "Malware.Kidding";
		}

		return "Malware.Unknown";
	}

	return "disVirus";
}