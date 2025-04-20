/*
 * LSProtect.h
 * CSafeɱ������������LSProtect��API��װ������(LSProtectΪ���ڵ�������������)
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#pragma once

#include <unordered_map>
#include <string>
#include <fstream>
#include "EngineHeadFile/LSProtect.h"

//��������(�����)
#include "EngineHeadFile/ImportBlackList.h"

//������������б�

/*
//����ľ��������(��Ȩ->����->cmdִ��/�����ȡ/��������)
const std::unordered_map<std::string, short> Black_List_Backdoor {
	{"GetRawInputData", 12},//��ȡ����
	{"GetAsyncKeyState", 12},//��ȡ��������
	{"SetWindowsHookEx", 8},//��ȡ��������&dllע��
	{"CreateRemoteThread", 5},//����Զ���߳�(ע��)
	{"GetProcAddress", 5},//��ȡ�����ַ(ʹ��δ�����Ĺؼ���)
	{"WinHttpConnect", 5},//�����
	{"socket", 4},
	{"connect", 4},
	{"GetWindow", 2}
};
*/

//DDoSľ��������(��Ȩ->����->����)
const std::unordered_map<std::string, short> Black_List_DDoS_LSProtect {
	{"WinHttpConnect", 14},//������վ
	{"sendto", 12},
	{"IcmpSendEcho", 14}
};

//����ľ��������(��Ȩ->�����ļ�ϵͳ/����&�ö�)
const std::unordered_map<std::string, short> Black_List_BlackMail_LSProtect {
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
const std::unordered_map<std::string, short> Black_List_RemoteControl_LSProtect {
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
const std::unordered_map<std::string, short> Black_List_Worm_LSProtect {
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
const std::unordered_map<std::string, short> Black_List_Killer_LSProtect {
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
//����˭�����е�û�����ƻ����㰡�����������ã��㻹�������ٸ��㿪�����࣬�ⲻ��Ϊ����ô��д���û�����Ķ������ǣ���˵�ģ���
const std::unordered_map<std::string, short> Black_List_Kidding_LSProtect {
	{"MessageBox", 1},
	{"SetWindowPos", 1}//���˲�������������㻹Ҫʲônb�Ķ���
};

std::string _LSProtect(const std::string TargetPath, const bool EnableSensitiveMode = false) {
	short AllRiskLevel = 0;//��Σ�յȼ�

	//��ȡ�����
	std::vector<std::pair<std::string, std::string>> TargetIn = calculatePEImportMap(TargetPath);

	if (TargetIn[0].first.find("Error_") != std::string::npos && TargetIn[0].first.find("Import") == std::string::npos) {//��ȡ�����ʧ��
		const std::string errorCode = "[" + TargetIn[0].first + "]";
		return errorCode;
	}

	for (int i = 0; i < TargetIn.size(); ++i)
		if (TargetIn[i].second.size() <= 2)
			TargetIn.erase(TargetIn.begin() + i);

	if (TargetIn.size() <= 6) { //�ڵ������ٵ������
		bool LoadLibraryFlag = false, GetProcAddressFlag = false;
		for (int i = 0; i < TargetIn.size(); ++i) {
			if (TargetIn[i].second.find("LoadLibrary") != std::string::npos)
				LoadLibraryFlag = true;
			if (TargetIn[i].second.find("GetProcAddress") != std::string::npos)
				GetProcAddressFlag = true;
		}
		if (LoadLibraryFlag && GetProcAddressFlag)
			return "Malware.VirusBox";//�򵥵Ĳ����ӿǼ��
	}

	for (int i = 0; i < TargetIn.size(); ++i) {//��ȡ��Σ�յȼ�
		auto Result = Main_Black_List_LSProtect.find(TargetIn[i].second);
		if (Result != Main_Black_List_LSProtect.end()) {
			AllRiskLevel += Result->second;
		}
	}

	if (EnableSensitiveMode) { //������ø����ж�ģʽ
		if (AllRiskLevel >= 668) {
			short RiskLevel = 0;

			//DDoSľ��
			for (int i = 0; i < TargetIn.size(); ++i) {//��ȡ��Σ�յȼ�
				auto Result = Black_List_DDoS_LSProtect.find(TargetIn[i].second);
				if (Result != Black_List_DDoS_LSProtect.end()) {
					RiskLevel += Result->second;
				}
			}

			if (RiskLevel >= 14) {
				return "Malware.Trojan.DDoS";
			}
			RiskLevel = 0;

			//Զ��ľ��
			for (int i = 0; i < TargetIn.size(); ++i) {//��ȡ��Σ�յȼ�
				auto Result = Black_List_RemoteControl_LSProtect.find(TargetIn[i].second);
				if (Result != Black_List_RemoteControl_LSProtect.end()) {
					RiskLevel += Result->second;
				}
			}

			if (RiskLevel >= 21) {
				return "Malware.Trojan.RemoteControl";
			}
			RiskLevel = 0;

			//����ľ��
			for (int i = 0; i < TargetIn.size(); ++i) {//��ȡ��Σ�յȼ�
				auto Result = Black_List_BlackMail_LSProtect.find(TargetIn[i].second);
				if (Result != Black_List_BlackMail_LSProtect.end()) {
					RiskLevel += Result->second;
				}
			}

			if (RiskLevel >= 22) {
				return "Malware.Trojan.Blackmail";
			}
			RiskLevel = 0;

			//�ƻ��Բ���
			for (int i = 0; i < TargetIn.size(); ++i) {//��ȡ��Σ�յȼ�
				auto Result = Black_List_Killer_LSProtect.find(TargetIn[i].second);
				if (Result != Black_List_Killer_LSProtect.end()) {
					RiskLevel += Result->second;
				}
			}

			if (RiskLevel >= 14) {
				return "Malware.Killer";
			}
			RiskLevel = 0;

			//��没��
			for (int i = 0; i < TargetIn.size(); ++i) {//��ȡ��Σ�յȼ�
				auto Result = Black_List_Worm_LSProtect.find(TargetIn[i].second);
				if (Result != Black_List_Worm_LSProtect.end()) {
					RiskLevel += Result->second;
				}
			}

			if (RiskLevel >= 22) {
				return "Malware.Worm";
			}
			RiskLevel = 0;

			//��㲡��
			for (int i = 0; i < TargetIn.size(); ++i) {//��ȡ��Σ�յȼ�
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
	} else {//���ø�����ģʽ
		if (AllRiskLevel >= 700) {
			short RiskLevel = 0;

			//DDoSľ��
			for (int i = 0; i < TargetIn.size(); ++i) {//��ȡ��Σ�յȼ�
				auto Result = Black_List_DDoS_LSProtect.find(TargetIn[i].second);
				if (Result != Black_List_DDoS_LSProtect.end()) {
					RiskLevel += Result->second;
				}
			}

			if (RiskLevel >= 14) {
				return "Malware.Trojan.DDoS";
			}
			RiskLevel = 0;

			//Զ��ľ��
			for (int i = 0; i < TargetIn.size(); ++i) {//��ȡ��Σ�յȼ�
				auto Result = Black_List_RemoteControl_LSProtect.find(TargetIn[i].second);
				if (Result != Black_List_RemoteControl_LSProtect.end()) {
					RiskLevel += Result->second;
				}
			}

			if (RiskLevel >= 21) {
				return "Malware.Trojan.RemoteControl";
			}
			RiskLevel = 0;

			//����ľ��
			for (int i = 0; i < TargetIn.size(); ++i) {//��ȡ��Σ�յȼ�
				auto Result = Black_List_BlackMail_LSProtect.find(TargetIn[i].second);
				if (Result != Black_List_BlackMail_LSProtect.end()) {
					RiskLevel += Result->second;
				}
			}

			if (RiskLevel >= 22) {
				return "Malware.Trojan.Blackmail";
			}
			RiskLevel = 0;

			//�ƻ��Բ���
			for (int i = 0; i < TargetIn.size(); ++i) {//��ȡ��Σ�յȼ�
				auto Result = Black_List_Killer_LSProtect.find(TargetIn[i].second);
				if (Result != Black_List_Killer_LSProtect.end()) {
					RiskLevel += Result->second;
				}
			}

			if (RiskLevel >= 14) {
				return "Malware.Killer";
			}
			RiskLevel = 0;

			//��没��
			for (int i = 0; i < TargetIn.size(); ++i) {//��ȡ��Σ�յȼ�
				auto Result = Black_List_Worm_LSProtect.find(TargetIn[i].second);
				if (Result != Black_List_Worm_LSProtect.end()) {
					RiskLevel += Result->second;
				}
			}

			if (RiskLevel >= 22) {
				return "Malware.Worm";
			}
			RiskLevel = 0;

			//��㲡��
			for (int i = 0; i < TargetIn.size(); ++i) {//��ȡ��Σ�յȼ�
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