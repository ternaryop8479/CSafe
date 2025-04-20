/*
 * LSProtect.h
 * CSafe杀毒引擎子引擎LSProtect的功能性函数
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <fstream>

//计算Offset的函数
ULONG RvaToOffset(IMAGE_NT_HEADERS *pNtHeader, ULONG Rva) {
	if (IsBadReadPtr(pNtHeader, sizeof(IMAGE_NT_HEADERS))) //指针检查
		return 0;

	//取得节表项数目
	ULONG sNum = pNtHeader->FileHeader.NumberOfSections;
	//此处无指针因此无需检查

	//取得第一个节表项
	IMAGE_SECTION_HEADER *p_section_header = (IMAGE_SECTION_HEADER *)
	        ((BYTE *)pNtHeader + sizeof(IMAGE_NT_HEADERS));
	if (IsBadReadPtr(p_section_header, sizeof(IMAGE_SECTION_HEADER))) //指针检查
		return 0;


	for (ULONG i = 0; i < sNum; i++) {
		if ((p_section_header->VirtualAddress <= Rva) && Rva < (p_section_header->VirtualAddress + p_section_header->SizeOfRawData)) {
			return Rva - p_section_header->VirtualAddress + p_section_header->PointerToRawData;
		}
		p_section_header++;
		if (IsBadReadPtr(p_section_header, sizeof(IMAGE_SECTION_HEADER))) //指针检查
			return 0;
	}
	return 0;
}

std::vector<std::pair<std::string, std::string>> calculatePEImportMap(std::string TargetFile) {
	if (TargetFile.empty()) { //路径检查
		return {std::make_pair("Error_FilePath", "Error_FilePath")};
	}

	HANDLE hFile = CreateFile(TargetFile.data(), GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0);//打开文件
	if (hFile == NULL) {//句柄检查
		return {std::make_pair("Error_OpenFile", "Error_OpenFile")};
	}

	HANDLE hMapObject = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);//创建内存映射
	if (hMapObject == NULL) {//句柄检查
		CloseHandle(hFile);
		return {std::make_pair("Error_FileMapping", "Error_FileMapping")};
	}

	//PE基址
	PUCHAR uFileMap = (PUCHAR)MapViewOfFile(hMapObject, FILE_MAP_READ, 0, 0, 0);//映射文件
	if (uFileMap == NULL) {//检查映射
		CloseHandle(hMapObject);
		CloseHandle(hFile);
		return {std::make_pair("Error_FileMapping", "Error_FileMapping")};
	}

	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)uFileMap;//读取Dos头
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {//检查DOS头
		UnmapViewOfFile(uFileMap);
		CloseHandle(hMapObject);
		CloseHandle(hFile);
		return {std::make_pair("Error_InvalidPEFile", "Error_InvalidPEFile")};
	}

	//定位到NT PE头
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)uFileMap + pImageDosHeader->e_lfanew);
	if (IsBadReadPtr(pImageNtHeaders, sizeof(IMAGE_NT_HEADERS))) { //指针检查
		UnmapViewOfFile(uFileMap);
		CloseHandle(hMapObject);
		CloseHandle(hFile);
		return {std::make_pair("Error_InvalidPEFile", "Error_InvalidPEFile")};
	}

	//导入表的相对虚拟地址(RVA)
	ULONG rva_ofimporttable = pImageNtHeaders->OptionalHeader.DataDirectory[1].VirtualAddress;

	//根据相对虚拟(rva)地址计算偏移地址(offset)
	ULONG offset_importtable = RvaToOffset(pImageNtHeaders, rva_ofimporttable);
	if (!offset_importtable) {
		UnmapViewOfFile(uFileMap);
		CloseHandle(hMapObject);
		CloseHandle(hFile);
		return {std::make_pair("Error_InvalidImportMap", "Error_InvalidImportMap")};
	}

	//取得导入表的地址
	IMAGE_IMPORT_DESCRIPTOR *pImportTable = (IMAGE_IMPORT_DESCRIPTOR *)((char *)uFileMap + offset_importtable);
	if (IsBadReadPtr(pImportTable, sizeof(IMAGE_IMPORT_DESCRIPTOR))) { //第一次指针检查
		UnmapViewOfFile(uFileMap);
		CloseHandle(hMapObject);
		CloseHandle(hFile);
		return {std::make_pair("Error_InvalidImportMap", "Error_InvalidImportMap")};
	}

	std::vector<std::pair<std::string, std::string>> ImportMap(128);//导入表vector
	short BadReadNum_pThunk = 0, BadReadNum_dllName = 0, BadReadNum_wpThunk;
	for (int i = 0; pImportTable[i].Name != 0; i++) {
		if (IsBadReadPtr(pImportTable + i, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {//检查指针
			UnmapViewOfFile(uFileMap);
			CloseHandle(hMapObject);
			CloseHandle(hFile);
			return ImportMap;
		}

		char *dllName = (char *)(uFileMap + RvaToOffset(pImageNtHeaders, pImportTable[i].Name));//DLL名
		if (IsBadReadPtr(dllName, sizeof(char)) || dllName[0] == '\0') {//指针检查
			++BadReadNum_dllName;
			if (BadReadNum_dllName >= 2) { //设置循环上限为2，防止这里一直continue导致崩溃
				break;
			}
			continue;
		}

		PIMAGE_THUNK_DATA32 pThunk = (PIMAGE_THUNK_DATA32)(uFileMap + RvaToOffset(pImageNtHeaders, pImportTable[i].FirstThunk));
		if (IsBadReadPtr(pThunk, sizeof(IMAGE_THUNK_DATA32))) {//指针检查
			++BadReadNum_pThunk;
			if (BadReadNum_pThunk >= 2) { //设置循环上限为2，防止这里一直continue导致崩溃
				break;
			}
			continue;
		}

		while (pThunk->u1.Ordinal != 0) {
			PIMAGE_IMPORT_BY_NAME pname = (PIMAGE_IMPORT_BY_NAME)(uFileMap + RvaToOffset(pImageNtHeaders, pThunk->u1.AddressOfData));
			if (IsBadReadPtr(pname, sizeof(IMAGE_IMPORT_BY_NAME))) {
				break;
			}
			ImportMap.push_back(std::make_pair(std::string(dllName), std::string(pname->Name)));//返回该项导入表条目
			pThunk++;
			if (IsBadReadPtr(pThunk, sizeof(IMAGE_THUNK_DATA32))) {//指针检查
				++BadReadNum_wpThunk;
				if (BadReadNum_wpThunk >= 2) { //设置循环上限为2，防止这里一直continue导致崩溃
					break;
				}
				continue;
			}
		}

		if (IsBadReadPtr(pImportTable + i + 1, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {//提前检查下一个指针位
			UnmapViewOfFile(uFileMap);
			CloseHandle(hMapObject);
			CloseHandle(hFile);
			return ImportMap;
		}
	}
	UnmapViewOfFile(uFileMap);
	CloseHandle(hMapObject);
	CloseHandle(hFile);

	return ImportMap;
}