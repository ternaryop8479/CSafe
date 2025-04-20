/*
 * WhiteProtect.h
 * CSafe杀毒引擎白启发WhiteProtect的API封装
 * Made By Ternary_Operator
 * Copyright (c) 2024 Ternary_Operator
*/

#ifndef WHITEProtect_PACK_H
#define WHITEProtect_PACK_H

#include "EngineHeadFile/DLLFunction.h"

char detectWhiteProtectDLL() {
	toDLLFunction dllWhiteProtect("WhiteProtect.dll", "WhiteProtect");
	return 0;
}

static const char WhiteProtectDetectLoader = detectWhiteProtectDLL();//利用变量的初始化实现在主函数执行之前执行该函数

typedef unsigned char WPCODE;

const WPCODE WPCODE_WHITE = 1;
const WPCODE WPCODE_ELSE  = 2;
const WPCODE WPCODE_ERR   = 0;

WPCODE WhiteProtect(const std::string TargetPath, const double SensitiveValue = 1.0) {
	static toDLLFunction dllWhiteProtect("WhiteProtect.dll", "WhiteProtect");
	typedef WPCODE (*funcWhiteProtect)(std::string, double);
	funcWhiteProtect functionWhiteProtect = (funcWhiteProtect)dllWhiteProtect.getFuntion();
	return functionWhiteProtect(TargetPath, SensitiveValue);
}

#endif