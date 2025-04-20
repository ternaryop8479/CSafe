/*
 * LSProtect.h
 * CSafeɱ������������LSProtect��DLL����&��װAPI(LSProtectΪ����PE�ļ�����������ʽ����)
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#ifndef LSProtect_PACK_H
#define LSProtect_PACK_H

#include "EngineHeadFile/DLLFunction.h"

char detectLSProtectDLL() {
	toDLLFunction dllLSProtect("LSProtect.dll", "LSProtect");
	return 0;
}

static const char LSProtectDetectLoader = detectLSProtectDLL();//���ñ����ĳ�ʼ��ʵ����������ִ��֮ǰִ�иú���

std::string LSProtect(const std::string TargetPath, const bool EnableSensitiveMode = false) {
	static toDLLFunction dllLSProtect("LSProtect.dll", "LSProtect");
	typedef std::string (*funcLSProtect)(std::string, bool);
	funcLSProtect functionLSProtect = (funcLSProtect)dllLSProtect.getFuntion();
	return functionLSProtect(TargetPath, EnableSensitiveMode);
}

#endif