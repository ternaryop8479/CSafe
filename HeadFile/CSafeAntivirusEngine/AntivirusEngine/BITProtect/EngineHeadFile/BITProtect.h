/*
 * BITProtect.h
 * CSafeɱ������������BITProtect�Ĺ����Ժ���
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <fstream>
#include <unordered_set>

std::vector<std::string> getPEFileReadableStrings(std::string filePath) {
	struct {
		bool isFunctionName(std::string functionName) {
			if (functionName.size() <= 3 || functionName.size() >= 42)
				return false;
			if (functionName[0] >= '0' && functionName[0] <= '9') {
				return false;
			}
			bool bFlag = true;
			unsigned long charSize = 0;
			for (int i = 0; i < functionName.size(); ++i) {
				if (!
				        (
				            (functionName[i] >= 'A' && functionName[i] <= 'Z') ||
				            (functionName[i] >= 'a' && functionName[i] <= 'z') ||
				            (functionName[i] >= '0' && functionName[i] <= '9') ||
				            (functionName[i] == '_')
				        )
				   ) {
					bFlag = false;
				} else {
					++charSize;
				}
			}
			if (charSize <= 2 || charSize >= 40)
				return false;
			if (bFlag)
				return true;
			return false;
		}
		bool isFunctionNameCh(unsigned char c) {
			return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c == '_');
		}
		unsigned long long getFileSize(const std::string &filePath) {
			std::ifstream fileStream(filePath, std::ios::in | std::ios::binary);
			if (!fileStream.is_open()) {
				return 0;
			}

			fileStream.seekg(0, std::ios::end);
			unsigned long long size = fileStream.tellg();
			fileStream.close();
			return size;
		}
	} inTools;

	if (filePath.empty()) { //·�����
		return {"Error_FilePath"};
	}

	unsigned long long fileSize = inTools.getFileSize(filePath);
	if (fileSize == 0) {
		return {"Error_OpenFile"};
	}

	HANDLE hFile = CreateFile(filePath.data(), GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0);//���ļ�
	if (hFile == NULL) {//������
		return {"Error_OpenFile"};
	}

	HANDLE hMapObject = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);//�����ڴ�ӳ��
	if (hMapObject == NULL) {//������
		CloseHandle(hFile);
		return {"Error_FileMapping"};
	}

	//PE��ַ
	PUCHAR uFileMap = (PUCHAR)MapViewOfFile(hMapObject, FILE_MAP_READ, 0, 0, 0);//ӳ���ļ�
	if (uFileMap == NULL) {//���ӳ��
		CloseHandle(hMapObject);
		CloseHandle(hFile);
		return {"Error_FileMapping"};
	}

	std::unordered_set<std::string> result(128);

	std::string functionStr;
	for (int i = 0; i < fileSize; ++i) {
		if (inTools.isFunctionNameCh(uFileMap[i])) {
			functionStr.push_back(uFileMap[i]);
		} else {
			if (inTools.isFunctionName(functionStr) && result.find(functionStr) == result.end()) {
				result.insert(functionStr);
			}
			functionStr.clear();
		}
	}

	UnmapViewOfFile(uFileMap);
	CloseHandle(hMapObject);
	CloseHandle(hFile);

	std::vector<std::string> resultVector(result.begin(), result.end());
	if (resultVector.empty()) {
		return {"Error_No_Information"};
	}

	return resultVector;
}