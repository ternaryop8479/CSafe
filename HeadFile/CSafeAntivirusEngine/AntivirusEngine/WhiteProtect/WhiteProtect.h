/*
 * WhiteProtect.h
 * CSafeɱ��������ļ�ʶ������WhiteProtect��API��װ������(WhiteProtect���ڵ����)
 * Made By Ternary_Operator
 * Copyright (c) 2024 Ternary_Operator
*/

#pragma once

#include <unordered_map>
#include <string>
#include <fstream>
#include "EngineHeadFile/WhiteProtect.h"

//��������(�����)
#include "EngineHeadFile/ImportWhiteList.h"

typedef unsigned char WPCODE;

const WPCODE WPCODE_WHITE = 1;
const WPCODE WPCODE_ELSE  = 2;
const WPCODE WPCODE_ERR   = 0;

WPCODE _WhiteProtect(const std::string TargetPath, const double SensitiveValue = 1.0) {
	short AllWhiteLevel = 0;//�ܵȼ�

	//��ȡ�����
	std::vector<std::pair<std::string, std::string>> TargetIn = calculatePEImportMap(TargetPath);

	if (TargetIn[0].first.find("Error_") != std::string::npos && TargetIn[0].first.find("Import") == std::string::npos) {//��ȡ�����ʧ��
		return WPCODE_ERR;
	}

	for (int i = 0; i < TargetIn.size(); ++i)
		if (TargetIn[i].second.size() <= 2)
			TargetIn.erase(TargetIn.begin() + i);

	for (int i = 0; i < TargetIn.size(); ++i) {//��ȡ��Σ�յȼ�
		auto Result = FunctionWhiteLists.find(TargetIn[i].second);
		if (Result != FunctionWhiteLists.end()) {
			AllWhiteLevel += Result->second;
		}
	}

	AllWhiteLevel *= SensitiveValue;

	if (AllWhiteLevel >= 3142) {
		return WPCODE_WHITE;
	}
	return WPCODE_ELSE;
}