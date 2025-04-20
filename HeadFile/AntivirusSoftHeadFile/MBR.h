/*
 * MBR.h
 * ����MBR�����뱸�ݵ�API��װ
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#pragma once

#include <cstdio>
#include <fstream>

bool CopyMBR(void) {//����MBR����
	FILE *MBRFile;
	FILE *ToMBR;
	unsigned char MBRCode[512] = {0};//һ������512�ֽ�
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

bool ReMBR(void) {//д��MBR
	FILE *MBRFile;
	FILE *ToMBR;
	unsigned char MBRCode[512] = {0};//һ������512�ֽ�
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