/*
 * BITProtect/dllmain.cpp
 * CSafeɱ������������BITProtect��API��װ������(BITProtectΪ����PE�ļ���������������ʽ����)
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#include "BITProtect.h"
#define DLLExport __declspec(dllexport)

extern "C" DLLExport std::string BITProtect(const std::string TargetPath, const float BlackWeight = 1.0, const float WhiteWeight = 1.0) {
	return _BITProtect(TargetPath, BlackWeight, WhiteWeight);
}