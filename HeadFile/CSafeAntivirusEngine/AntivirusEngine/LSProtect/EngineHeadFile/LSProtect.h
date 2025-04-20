/*
 * LSProtect.h
 * CSafeɱ������������LSProtect�Ĺ����Ժ���
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <fstream>

//����Offset�ĺ���
ULONG RvaToOffset(IMAGE_NT_HEADERS *pNtHeader, ULONG Rva) {
	if (IsBadReadPtr(pNtHeader, sizeof(IMAGE_NT_HEADERS))) //ָ����
		return 0;

	//ȡ�ýڱ�����Ŀ
	ULONG sNum = pNtHeader->FileHeader.NumberOfSections;
	//�˴���ָ�����������

	//ȡ�õ�һ���ڱ���
	IMAGE_SECTION_HEADER *p_section_header = (IMAGE_SECTION_HEADER *)
	        ((BYTE *)pNtHeader + sizeof(IMAGE_NT_HEADERS));
	if (IsBadReadPtr(p_section_header, sizeof(IMAGE_SECTION_HEADER))) //ָ����
		return 0;


	for (ULONG i = 0; i < sNum; i++) {
		if ((p_section_header->VirtualAddress <= Rva) && Rva < (p_section_header->VirtualAddress + p_section_header->SizeOfRawData)) {
			return Rva - p_section_header->VirtualAddress + p_section_header->PointerToRawData;
		}
		p_section_header++;
		if (IsBadReadPtr(p_section_header, sizeof(IMAGE_SECTION_HEADER))) //ָ����
			return 0;
	}
	return 0;
}

std::vector<std::pair<std::string, std::string>> calculatePEImportMap(std::string TargetFile) {
	if (TargetFile.empty()) { //·�����
		return {std::make_pair("Error_FilePath", "Error_FilePath")};
	}

	HANDLE hFile = CreateFile(TargetFile.data(), GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0);//���ļ�
	if (hFile == NULL) {//������
		return {std::make_pair("Error_OpenFile", "Error_OpenFile")};
	}

	HANDLE hMapObject = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);//�����ڴ�ӳ��
	if (hMapObject == NULL) {//������
		CloseHandle(hFile);
		return {std::make_pair("Error_FileMapping", "Error_FileMapping")};
	}

	//PE��ַ
	PUCHAR uFileMap = (PUCHAR)MapViewOfFile(hMapObject, FILE_MAP_READ, 0, 0, 0);//ӳ���ļ�
	if (uFileMap == NULL) {//���ӳ��
		CloseHandle(hMapObject);
		CloseHandle(hFile);
		return {std::make_pair("Error_FileMapping", "Error_FileMapping")};
	}

	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)uFileMap;//��ȡDosͷ
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {//���DOSͷ
		UnmapViewOfFile(uFileMap);
		CloseHandle(hMapObject);
		CloseHandle(hFile);
		return {std::make_pair("Error_InvalidPEFile", "Error_InvalidPEFile")};
	}

	//��λ��NT PEͷ
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)uFileMap + pImageDosHeader->e_lfanew);
	if (IsBadReadPtr(pImageNtHeaders, sizeof(IMAGE_NT_HEADERS))) { //ָ����
		UnmapViewOfFile(uFileMap);
		CloseHandle(hMapObject);
		CloseHandle(hFile);
		return {std::make_pair("Error_InvalidPEFile", "Error_InvalidPEFile")};
	}

	//��������������ַ(RVA)
	ULONG rva_ofimporttable = pImageNtHeaders->OptionalHeader.DataDirectory[1].VirtualAddress;

	//�����������(rva)��ַ����ƫ�Ƶ�ַ(offset)
	ULONG offset_importtable = RvaToOffset(pImageNtHeaders, rva_ofimporttable);
	if (!offset_importtable) {
		UnmapViewOfFile(uFileMap);
		CloseHandle(hMapObject);
		CloseHandle(hFile);
		return {std::make_pair("Error_InvalidImportMap", "Error_InvalidImportMap")};
	}

	//ȡ�õ����ĵ�ַ
	IMAGE_IMPORT_DESCRIPTOR *pImportTable = (IMAGE_IMPORT_DESCRIPTOR *)((char *)uFileMap + offset_importtable);
	if (IsBadReadPtr(pImportTable, sizeof(IMAGE_IMPORT_DESCRIPTOR))) { //��һ��ָ����
		UnmapViewOfFile(uFileMap);
		CloseHandle(hMapObject);
		CloseHandle(hFile);
		return {std::make_pair("Error_InvalidImportMap", "Error_InvalidImportMap")};
	}

	std::vector<std::pair<std::string, std::string>> ImportMap(128);//�����vector
	short BadReadNum_pThunk = 0, BadReadNum_dllName = 0, BadReadNum_wpThunk;
	for (int i = 0; pImportTable[i].Name != 0; i++) {
		if (IsBadReadPtr(pImportTable + i, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {//���ָ��
			UnmapViewOfFile(uFileMap);
			CloseHandle(hMapObject);
			CloseHandle(hFile);
			return ImportMap;
		}

		char *dllName = (char *)(uFileMap + RvaToOffset(pImageNtHeaders, pImportTable[i].Name));//DLL��
		if (IsBadReadPtr(dllName, sizeof(char)) || dllName[0] == '\0') {//ָ����
			++BadReadNum_dllName;
			if (BadReadNum_dllName >= 2) { //����ѭ������Ϊ2����ֹ����һֱcontinue���±���
				break;
			}
			continue;
		}

		PIMAGE_THUNK_DATA32 pThunk = (PIMAGE_THUNK_DATA32)(uFileMap + RvaToOffset(pImageNtHeaders, pImportTable[i].FirstThunk));
		if (IsBadReadPtr(pThunk, sizeof(IMAGE_THUNK_DATA32))) {//ָ����
			++BadReadNum_pThunk;
			if (BadReadNum_pThunk >= 2) { //����ѭ������Ϊ2����ֹ����һֱcontinue���±���
				break;
			}
			continue;
		}

		while (pThunk->u1.Ordinal != 0) {
			PIMAGE_IMPORT_BY_NAME pname = (PIMAGE_IMPORT_BY_NAME)(uFileMap + RvaToOffset(pImageNtHeaders, pThunk->u1.AddressOfData));
			if (IsBadReadPtr(pname, sizeof(IMAGE_IMPORT_BY_NAME))) {
				break;
			}
			ImportMap.push_back(std::make_pair(std::string(dllName), std::string(pname->Name)));//���ظ�������Ŀ
			pThunk++;
			if (IsBadReadPtr(pThunk, sizeof(IMAGE_THUNK_DATA32))) {//ָ����
				++BadReadNum_wpThunk;
				if (BadReadNum_wpThunk >= 2) { //����ѭ������Ϊ2����ֹ����һֱcontinue���±���
					break;
				}
				continue;
			}
		}

		if (IsBadReadPtr(pImportTable + i + 1, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {//��ǰ�����һ��ָ��λ
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