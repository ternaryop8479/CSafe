/*
 * CSafeAntivirusEngine.h
 * CSafeɱ��������ͷ�ļ�����װ��һЩ��������ֱ�ӵ��õĲ���API
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#ifndef CSafeAntivirusEngine_H
#define CSafeAntivirusEngine_H

#include <vector>
#include <string>
#include <sstream>
#include <fstream>
#include "CSafeAntivirusEngineHeadFile.h"

//��ɱ����
#include "AntivirusEngine/TOProtect.h"//��̬����
#include "AntivirusEngine/LSProtect.h"//�����̬����
#include "AntivirusEngine/BITProtect.h"//PE�ļ���ʶ���ַ�����̬����
#include "AntivirusEngine/WhiteProtect.h"//����������

namespace CSafeAntivirusEngine {
	//���ñ���
	bool LSProtectEnableSensitiveMode = true;//Ĭ�����ø�����
	bool EnableLSProtect = true;
	float BITProtectBlackWeight = 1.0F;
	double WhiteProtectSensitiveValue = 1.0;


	//���ߺ���
	std::string getProcessPath(DWORD dwProcessId) {//��ȡ����·��
		return GetProcessFullPath(dwProcessId);
	}
	bool getNewProcess(PROCESSENTRY32 &targetProcess) {//��ȡ�������Ľ��̣�������������Ľ����򽫽�����Ϣ����targetProcess������true����֮����false
		return GetProcessListStart(targetProcess);
	}


	//���̲�ɱ��API
	TOProtectInfo detectProcess(PROCESSENTRY32 targetProcess, std::stringstream *logStreamPtr = nullptr, unsigned short maxDelayMS = 3200) {
		return TOProtect(targetProcess, logStreamPtr, maxDelayMS);
	}


	//�ļ���ɱ��API
	std::string detectFile(std::string targetFile, const bool &EnableFastMode = false) {
		if (WhiteProtect(targetFile, WhiteProtectSensitiveValue) == WPCODE_WHITE) { // ������LSProtect
			return "CSafe.BITProtect." + BITProtect(targetFile, BITProtectBlackWeight);
//			return "CSafe.WhiteProtect.disVirus";
		}
		if (!EnableFastMode) {
			if (!EnableLSProtect) {
				return "CSafe.BITProtect." + BITProtect(targetFile, BITProtectBlackWeight);
			}
			std::string LSProtectResult = LSProtect(targetFile, LSProtectEnableSensitiveMode);
			if (LSProtectResult.find("Error") == std::string::npos && LSProtectResult.find("disVirus") == std::string::npos) { //δError���ǲ���
				return "CSafe.LSProtect." + LSProtectResult;
			}
			return "CSafe.BITProtect." + BITProtect(targetFile, BITProtectBlackWeight);
		}
		/*else*/
		return "CSafe.LSProtect." + LSProtect(targetFile, LSProtectEnableSensitiveMode);
	}
	std::string detectFile_fast(std::string targetFile) {//���ټ���ļ�
		if (!EnableLSProtect) {
			return "CSafe.disVirus";
		}
		if (WhiteProtect(targetFile, WhiteProtectSensitiveValue) == WPCODE_WHITE) {
			return "CSafe.WhiteProtect.disVirus";
		}
		return "CSafe.LSProtect." + LSProtect(targetFile, LSProtectEnableSensitiveMode);
	}
	void enableLSProtectSensitiveMode() {
		LSProtectEnableSensitiveMode = true;
	}
	void disableLSProtectSensitiveMode() {
		LSProtectEnableSensitiveMode = false;
	}
	void setBITProtectWeight(float BlackWeight) {
		BITProtectBlackWeight = BlackWeight;
	}
	void setWhiteProtectWeight(double WhiteListValue) {
		WhiteProtectSensitiveValue = WhiteListValue;
	}
	void disableLSProtect() {
		EnableLSProtect = false;
	}
	void enableLSProtect() {
		EnableLSProtect = true;
	}
	void scanFolder(const std::string path, void (*HandleFunction)(std::string, std::string), const bool &EnableFastMode = false) {//ɨ���ļ���
		long hFile = 0;
		struct _finddata_t fileinfo;
		std::string pathp;
		if ((hFile = _findfirst(pathp.assign(path).append("\\*").c_str(), &fileinfo)) != -1) {
			do {
				if ((fileinfo.attrib &  _A_SUBDIR)) {
					if (strcmp(fileinfo.name, ".") != 0 && strcmp(fileinfo.name, "..") != 0) {
						scanFolder(pathp.assign(path).append("\\").append(fileinfo.name), HandleFunction, EnableFastMode);
					}
				} else {
					std::string filestr = pathp.assign(path).append("\\").append(fileinfo.name);
					HandleFunction(filestr, detectFile(filestr, EnableFastMode));
				}
			} while (_findnext(hFile, &fileinfo) == 0);
			_findclose(hFile);
		} else {
			throw std::runtime_error("CSafeAntivirusEngine.h-scanFolder(): Failed to ergodic the folder");
		}
	}
};

#endif