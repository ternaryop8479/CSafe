/*
 * MainAntivirus.h
 * ������ɱ��ģ��Ĺ��ܷ�װ
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#pragma once

#include <thread>
#include "AntivirusSoftHeadFile/Log.h"
#include "VirusHandle.h"
#include "CSafeAntivirusEngine/CSafeAntivirusEngine.h"//ɱ������ͷ�ļ�

bool EnableDynamicEngine = true;
bool EnableStaticEngine = true;

void saveSetting() {
	log_error("Saved setting: ", EnableStaticEngine, EnableDynamicEngine, CSafeAntivirusEngine::LSProtectEnableSensitiveMode, CSafeAntivirusEngine::EnableLSProtect, CSafeAntivirusEngine::BITProtectBlackWeight, CSafeAntivirusEngine::WhiteProtectSensitiveValue);
	std::ofstream outFile("CSafeData\\CSafeSetting.csdata", std::ios::binary | std::ios::out);

	outFile.write(reinterpret_cast<char *>(&EnableStaticEngine), sizeof(bool));
	outFile.write(reinterpret_cast<char *>(&EnableDynamicEngine), sizeof(bool));

	outFile.write(reinterpret_cast<char *>(&CSafeAntivirusEngine::LSProtectEnableSensitiveMode), sizeof(bool));
	outFile.write(reinterpret_cast<char *>(&CSafeAntivirusEngine::EnableLSProtect), sizeof(bool));
	outFile.write(reinterpret_cast<char *>(&CSafeAntivirusEngine::BITProtectBlackWeight), sizeof(float));
	outFile.write(reinterpret_cast<char *>(&CSafeAntivirusEngine::WhiteProtectSensitiveValue), sizeof(double));

	outFile.close();
}

void loadSetting() {
	std::ifstream inFile("CSafeData\\CSafeSetting.csdata", std::ios::binary | std::ios::out);

	inFile.read(reinterpret_cast<char *>(&EnableStaticEngine), sizeof(bool));
	inFile.read(reinterpret_cast<char *>(&EnableDynamicEngine), sizeof(bool));

	inFile.read(reinterpret_cast<char *>(&CSafeAntivirusEngine::LSProtectEnableSensitiveMode), sizeof(bool));
	inFile.read(reinterpret_cast<char *>(&CSafeAntivirusEngine::EnableLSProtect), sizeof(bool));
	inFile.read(reinterpret_cast<char *>(&CSafeAntivirusEngine::BITProtectBlackWeight), sizeof(float));
	inFile.read(reinterpret_cast<char *>(&CSafeAntivirusEngine::WhiteProtectSensitiveValue), sizeof(double));

	inFile.close();
	log_error("Loaded setting: ", EnableStaticEngine, EnableDynamicEngine, CSafeAntivirusEngine::LSProtectEnableSensitiveMode, CSafeAntivirusEngine::EnableLSProtect, CSafeAntivirusEngine::BITProtectBlackWeight, CSafeAntivirusEngine::WhiteProtectSensitiveValue);
}

//���̷���

void DetectThread(PROCESSENTRY32 pe32) {
	std::string fPath;
	try {
		PauseProcess(pe32.th32ProcessID, true);

		fPath = CSafeAntivirusEngine::getProcessPath(pe32.th32ProcessID);
		std::string hash = calculate_file_sha256(fPath);
		if (!WhiteList(fPath)) {
			//����Ϊ��̬���
			std::string riskType;
			size_t fsize = getFileSize(CSafeAntivirusEngine::getProcessPath(pe32.th32ProcessID));
			log("Start the static detection with process(", pe32.th32ProcessID, "). ", "file size: ", fsize, "byte.");
			if (fsize <= 10485760) { //�ļ���СС�ڵ���10MB�����������ʱ���Լ��0.5s~3.5s����
				riskType = CSafeAntivirusEngine::detectFile(fPath);
			} else { // ��ʾ��Ϣ
				log_warn("The program file is a little fat, please wait patiently.");
				riskType = CSafeAntivirusEngine::detectFile(fPath); // ���ڴ��ļ����ʱ����ܱȽϳ������ǳ����ִ���ļ���������(90%����Ϊʷɽ����)
			}
			log("Generate file risk done.");
			if (riskType.find("Error") == std::string::npos && riskType.find("disVirus") == std::string::npos) {
				if (!ForceTerminateProcess(pe32.th32ProcessID)) {
					log_error("Failed to terminate process!");
				}
				log("\nIntercepted a malware!\nVirus type: ", riskType, "\nSource path: ", fPath, "\nSHA-256: ", hash, "\n");
				Sleep(64);
				IsolateFile(fPath);
				std::string Notice;
				Notice += "���ص��������������(�������ʧ�ܻ�����ʾ)��";
				Notice += pe32.szExeFile;
				Notice += "\n�������ͣ�";
				Notice += riskType;
				Notice += "\nԴλ�ã�";
				Notice += fPath;
				Notice += "\nSHA-256: ";
				Notice += hash;
				Notice += "\n�Ƿ��䱣���ڸ�������\n�������ǣ����Ὣ�����ڸ�������\n������������ͷ��䲢Ϊ����Ӱ�������";
				int MsgRs = MessageBox(NULL, Notice.data(), "CSafe", MB_SETFOREGROUND | MB_ICONWARNING | MB_YESNO);
				if (MsgRs == IDNO) {
					ReleaseFile(hash);
					Sleep(64);
					WriteList(fPath);
					return;
				} else {
					return;
				}
			}
			log("The process(", pe32.th32ProcessID, ")passed the static detection. Start the dynamic detection with it.");

			//�����ǻ���TOProtect�Ķ�̬��Ϊ���
			PauseProcess(pe32.th32ProcessID, false);
			std::stringstream arguments;
			TOProtectInfo riskInfo = CSafeAntivirusEngine::detectProcess(pe32, &arguments);
			HandleTOProtect(pe32, riskInfo, &arguments);
		}
	} catch (const std::runtime_error &e) {
		log_error("Catch a engine error! In process(", pe32.th32ProcessID, "): ", pe32.szExeFile, ", Error details: \n", e.what());
		if (std::string(e.what()).find("ReleaseFile()") != std::string::npos) {
			WriteList(fPath); // �е�ʱ�������Ϊ�ļ�����ʧ�ܵ����ͷ��ļ���ʱ��throw��error�����ʱ��û�Ӱ������������Ҫ����һ��
		}
	}
	PauseProcess(pe32.th32ProcessID, false);
	log("The process(", pe32.th32ProcessID, ")passed all of the detection.");
}

void DynamicAntivirusThread() {
	while (1) {
		try {
			PROCESSENTRY32 ProcessPE32;
			if (CSafeAntivirusEngine::getNewProcess(ProcessPE32)) {
				if (!EnableDynamicEngine) {
					log_warn("Dynamic detection is not enable. Give up the detection with process(", ProcessPE32.th32ProcessID, ").");
					continue;
				}
				std::thread detectThread(DetectThread, ProcessPE32);
				detectThread.detach();
			}
		} catch (const std::runtime_error &e) {
			log_error("Catch a error: ", e.what());
		}

		if (!EnableDynamicEngine) { //���δ���ö�̬����Ļ��ͼӴ�Sleepʱ��������ռ��
			Sleep(100);
		} else {
			Sleep(34);
		}
	}
}

//�ļ�����

//���Ŀ¼�仯�����ڱ仯ִ�д�����
void ObserveHandleDirectory(std::string directoryPath, void (*HandleFunction)(std::string)) {
	class {
		public:
			std::wstring STOW(const std::string &strCmd) {
				int bytes =  MultiByteToWideChar(CP_ACP, 0, strCmd.c_str(), strCmd.size(), NULL, 0);
				std::wstring wstrCmd(bytes, '\0');
				bytes  =  MultiByteToWideChar(CP_ACP, 0, strCmd.c_str(), strCmd.size(), const_cast<wchar_t *>(wstrCmd.c_str()), wstrCmd.size());
				return wstrCmd;
			}



			std::string WTOS(const std::wstring &wstrCmd) {
				int bytes =  WideCharToMultiByte(CP_ACP, 0, wstrCmd.c_str(), wstrCmd.size(), NULL, 0, NULL, NULL);
				std::string strCmd(bytes, '\0');
				bytes  =  WideCharToMultiByte(CP_ACP, 0, wstrCmd.c_str(), wstrCmd.size(), const_cast<char *>(strCmd.data()), strCmd.size(), NULL, NULL);
				return strCmd;
			}
	} inlineTools;
	std::wstring directoryPathw = inlineTools.STOW(directoryPath);

	WCHAR *path = new WCHAR[directoryPathw.size()];
	memcpy(path, directoryPathw.data(), directoryPathw.size() * 2);

	HANDLE dirHandle = CreateFileW(
	                       path,
	                       FILE_LIST_DIRECTORY,
	                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
	                       NULL,
	                       OPEN_EXISTING,
	                       FILE_FLAG_BACKUP_SEMANTICS,
	                       NULL
	                   );

	if (dirHandle == INVALID_HANDLE_VALUE) {
		log_error("Failed to open directory: ", inlineTools.WTOS(path));
		return;
	}

	const int bufferSize = 1024 * 1024;
	std::vector<BYTE> buffer(bufferSize);
	FILE_NOTIFY_INFORMATION *fileInfo;
	DWORD bytesReturned = 0;

	while (TRUE) {
		if (ReadDirectoryChangesW(
		            dirHandle,
		            &buffer[0],
		            buffer.size(),
		            TRUE,
		            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE,
		            &bytesReturned,
		            NULL,
		            NULL
		        )) {
			fileInfo = (FILE_NOTIFY_INFORMATION *)&buffer[0];
			do {
				static std::wstring backOnce = L"0";
				std::wstring fileName(fileInfo->FileName, fileInfo->FileNameLength / sizeof(WCHAR));
				std::wstring fullPathw = path + fileName;

				if (backOnce == fullPathw || backOnce.find(fullPathw) != std::wstring::npos || fullPathw.find(backOnce) != std::wstring::npos) {
					fileInfo = (FILE_NOTIFY_INFORMATION *)((PBYTE)fileInfo + fileInfo->NextEntryOffset);
					continue;
				}

				std::string fullPath = inlineTools.WTOS(fullPathw);

				HandleFunction(fullPath);

				backOnce = fullPathw;
				fileInfo = (FILE_NOTIFY_INFORMATION *)((PBYTE)fileInfo + fileInfo->NextEntryOffset);
			} while (fileInfo->NextEntryOffset != 0);
		} else {
			log_error("ReadDirectoryChangesW failed: ", GetLastError());
			break;
		}
	}

	CloseHandle(dirHandle);
	return;
}

void FileHandler_thread(std::string filePath) {
	if (WhiteList(filePath)) {
		return;
	}
	try {
		log("Found the file changed at {", filePath, "}, start detection.");
		std::string riskType;
		if (getFileSize(filePath) <= 10485760) { //�ļ���СС�ڵ���10MB�����������ʱ���Լ��0.5s~3.5s����
			riskType = CSafeAntivirusEngine::detectFile(filePath);
		} else {
			riskType = CSafeAntivirusEngine::detectFile_fast(filePath);
		}
		if (riskType.find("Error") == std::string::npos && riskType.find("disVirus") == std::string::npos) {
			std::string hash = calculate_file_sha256(filePath);
			log("\nIntercepted a malware!\nVirus type: ", riskType, "\nSource path: ", filePath, "\nSHA-256: ", hash, "\n");
			Sleep(64);
			IsolateFile(filePath);
			std::string Notice;
			Notice += "��ص��������������(�������ʧ�ܻ�����ʾ)��\n";
			Notice += filePath;
			Notice += "\n�������ͣ�";
			Notice += riskType;
			Notice += "\nSHA-256: ";
			Notice += hash;
			Notice += "\n�Ƿ��䱣���ڸ�������\n�������ǣ����Ὣ�����ڸ�������\n������������ͷ��䲢Ϊ����Ӱ�������";
			int MsgRs = MessageBox(NULL, Notice.data(), "CSafe", MB_SETFOREGROUND | MB_ICONWARNING | MB_YESNO);
			if (MsgRs == IDNO) {
				ReleaseFile(hash);
				Sleep(64);
				WriteList(filePath);
			}
		}
	} catch (const std::runtime_error &e) {
		log_error("Catch a error in malware processing! Error details: ", e.what());
		if (std::string(e.what()).find("ReleaseFile()") != std::string::npos) {
			WriteList(filePath); // �е�ʱ�������Ϊ�ļ�����ʧ�ܵ����ͷ��ļ���ʱ��throw��error�����ʱ��û�Ӱ������������Ҫ����һ��
		}
	}
}

void FileHandler(std::string filePath) {
	if (!EnableStaticEngine) {
		log_warn("Static detection is not enable. Give up the detection with file {", filePath, "}.");
		return;
	}
	std::thread handleThread(FileHandler_thread, filePath);
	handleThread.detach();//��Ϊ�ú�����ִ���������ģ�������Ҫ����һ������ȥ���
}

void FileAntivirusThread() {
	while (1) {
		log("Loading the File Antivirus Engine...");
		char systemDisk[4];
		GetSystemDirectory(systemDisk, MAX_PATH);
		systemDisk[3] = '\0';
		log("File Antivirus Engine: Load monitor at system disk: ", systemDisk);
		ObserveHandleDirectory(systemDisk, FileHandler);
		log_error("File Antivirus Engine: The Monitor crash!");
	}
}