/*
 * BITProtect.h
 * CSafeɱ������������BITProtect��API��װ������(BITProtectΪ����PE�ļ���������������ʽ����)
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

//DDoSľ��������(��Ȩ->����->����)
const std::unordered_map<std::string, short> Black_List_DDoS_BITProtect {
	{"WinHttpConnect", 14},//������վ
	{"sendto", 12},
	{"IcmpSendEcho", 14}
};

//����ľ��������(��Ȩ->�����ļ�ϵͳ/����&�ö�)
const std::unordered_map<std::string, short> Black_List_BlackMail_BITProtect {
	{"CreateFile", 14},
	{"CreateFileA", 14},//���ļ�
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

//Զ��ľ��������(��Ȩ->����->cmdִ��/�������&��ȡ/��������/ע���/��Ļ����)
const std::unordered_map<std::string, short> Black_List_RemoteControl_BITProtect {
	{"system", 4},
	{"GetRawInputData", 18},//��ȡ����
	{"GetAsyncKeyState", 18},//��ȡ��������
	{"SetWindowsHookEx", 14},//��ȡ��������&dllע��
	{"socket", 2},
	{"connect", 2},
	{"BitBlt", 18},//��ͼ
	{"CreateCompatibleDC", 10},//��ͼ
	{"CreateCompatibleBitmap", 10},//��ͼ
	{"SetCursorPos", 18},//�������
	{"keybd_event", 18}//���Ƽ���
};


//��������б�

//��没����������(��Ȩ->����->���к��Ĵ������->����&�ƻ�&ɾ���ļ�/����ϵͳ����)
const std::unordered_map<std::string, short> Black_List_Worm_BITProtect {
	{"URLDownloadToFile", 8},//�����ļ�
	{"SetFileAttributes", 10},
	{"SetFileAttributesW", 10},//�����ļ�����
	{"SetFileAttributesA", 10},
	{"fopen", 10},
	{"RegOpenKey", 4},
	{"RegOpenKeyA", 4},
	{"RegOpenKeyW", 4},
	{"RegOpenKeyEx", 4},
	{"RegOpenKeyExA", 4},//ע������
	{"RegOpenKeyExW", 4},
	{"RegCloseKey", 4},
	{"RegCloseKeyA", 4},
	{"RegCloseKeyW", 4},
	{"CreateFile", 10},
	{"CreateFileA", 10},//���ļ�
	{"CreateFileW", 10},
	{"ShellExecute", 8},
	{"ShellExecuteA", 8},
	{"ShellExecuteW", 8}
};


//���������б�

//�ƻ��Բ�����������(��Ȩ->ɱ����/ɾ�ļ�/ɾע���/����һϵ�ж���/ִ��cmd)
const std::unordered_map<std::string, short> Black_List_Killer_BITProtect {
	{"TerminateProcess", 14},//ɱ����
	{"NtTerminateProcess", 14},
	{"ZwTerminateProcess", 14},
	{"PsTerminateProcess", 14},
	{"PspTerminateProcess", 14},
	{"PspTerminateThreadByPoint", 14},
	{"PspExitThread", 14},
	{"GetProcAddress", 14},//��ȡ�����ַ(ʹ��δ�����Ĺؼ���)��ͬ��������������
	{"remove", 14},//ɾ�ļ�
	{"DeleteFile", 14},
	{"ZwDeleteFile", 14},
	{"DeviceIoControl", 14},
	{"LockFile", 14},
	{"RaiseFailFastException", 14}
};

//��㲡����������(��Ȩ->�ö�&����)
const std::unordered_map<std::string, short> Black_List_Kidding_BITProtect {
	{"MessageBox", 1},
	{"SetWindowPos", 1}//���˲�������������㻹Ҫʲônb�Ķ���
};

std::string _BITProtect(const std::string TargetPath, const float BlackWeight = 1.0, const float WhiteWeight = 1.0) {
	//��ȡ�����
	std::vector<std::string> TargetIn = getPEFileReadableStrings(TargetPath);

	if (TargetIn[0].find("Error_") != std::string::npos) {//��ȡPE�ɶ���Ϣʧ��
		const std::string errorCode = "[" + TargetIn[0] + "]";
		return errorCode;
	}

	long AllRiskLevel = 0;//��Σ�յȼ�
	long AllWhiteLevel_System = 0, AllWhiteLevel_Normal = 0;//�������ȼ�

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
				AllWhiteLevel_Normal += TargetErgo.second;//���ﱾ������ΪNormal�ĵȼ����ߣ�������ΪNormal����Ŀ�������ıȽ϶࣬��ԭsize����
				break;
			}
		}
		if ((AllWhiteLevel_System + AllWhiteLevel_Normal) / 2.0 >= 644810) {//�˴��������ֵ����ƫ��ϵͳ�ļ�
			return "disVirus";
		}
	}
	long AllWhiteLevel = (AllWhiteLevel_System + AllWhiteLevel_Normal) / 2.0;
	long DecideLevel = (AllRiskLevel * BlackWeight * 2.87) - (AllWhiteLevel * WhiteWeight * 1.94);//����Ȩ�ؼ�������վ��ϵȼ�, 2.87��1.94����ԭʼ���������ϼӵ�Ȩ��

	if (DecideLevel >= 110552) {//��Ϯ����ͨ�ļ��������
		short RiskLevel = 0;

		//DDoSľ��
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

		//Զ��ľ��
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

		//����ľ��
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

		//�ƻ��Բ���
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

		//��没��
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

		//��㲡��
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