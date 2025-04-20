/*
 * BITProtect.h
 * CSafeɱ������������BITProtect��DLL����&��װAPI(BITProtectΪ����PE�ļ���������������ʽ����)
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#ifndef BITProtect_PACK_H
#define BITProtect_PACK_H

#include "EngineHeadFile/DLLFunction.h"

char detectBITProtectDLL() {
	toDLLFunction dllBITProtect("BITProtect.dll", "BITProtect");
	return 0;
}

static const char BITProtectDetectLoader = detectBITProtectDLL();//���ñ����ĳ�ʼ��ʵ����������ִ��֮ǰִ�иú���

std::string BITProtect(const std::string TargetPath, const float BlackWeight = 1.0, const float WhiteWeight = 1.0) {
	static toDLLFunction dllBITProtect("BITProtect.dll", "BITProtect");
	typedef std::string (*funcBITProtect)(std::string, float, float);
	funcBITProtect functionBITProtect = (funcBITProtect)dllBITProtect.getFuntion();
	return functionBITProtect(TargetPath, BlackWeight, WhiteWeight);
}

#endif