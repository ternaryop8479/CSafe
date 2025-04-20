/*
 * MBR.h
 * 包含MBR拷贝与备份的API封装
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#pragma once

#include <cstdio>
#include <fstream>

bool CopyMBR(void) {//复制MBR函数
	FILE *MBRFile;
	FILE *ToMBR;
	unsigned char MBRCode[512] = {0};//一个扇区512字节
	MBRFile = fopen("\\\\.\\PhysicalDrive0", "rb+");
	if (!MBRFile) {
		return false;
	} else if (!feof(MBRFile)) {
		fseek(MBRFile, 0, SEEK_SET);
		fread(MBRCode, 512, 1, MBRFile);
		ToMBR = fopen("CSafeData\\MBRData.data", "wb+");
		if (!ToMBR) {
			return false;
		} else if (!feof(ToMBR)) {
			fwrite(MBRCode, 512, 1, ToMBR);
			fclose(ToMBR);
		}
		fclose(MBRFile);
	}
	return true;
}

bool ReMBR(void) {//写入MBR
	FILE *MBRFile;
	FILE *ToMBR;
	unsigned char MBRCode[512] = {0};//一个扇区512字节
	MBRFile = fopen("CSafeData\\MBRData.data", "rb+");
	if (!MBRFile) {
		return false;
	} else if (!feof(MBRFile)) {
		fseek(MBRFile, 0, SEEK_SET);
		fread(MBRCode, 512, 1, MBRFile);
		ToMBR = fopen("\\\\.\\PhysicalDrive0", "wb+");
		if (!ToMBR) {
			return false;
		} else if (!feof(ToMBR)) {
			fwrite(MBRCode, 512, 1, ToMBR);
			fclose(ToMBR);
		}
		fclose(MBRFile);
	}
	return true;
}