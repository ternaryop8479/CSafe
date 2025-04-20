/*
 * MainAntivirus.h
 * 包含主杀毒模块的功能封装
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#pragma once

#include <thread>
#include "AntivirusSoftHeadFile/Log.h"
#include "VirusHandle.h"
#include "CSafeAntivirusEngine/CSafeAntivirusEngine.h"//杀毒引擎头文件

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

//进程防护

void DetectThread(PROCESSENTRY32 pe32) {
	std::string fPath;
	try {
		PauseProcess(pe32.th32ProcessID, true);

		fPath = CSafeAntivirusEngine::getProcessPath(pe32.th32ProcessID);
		std::string hash = calculate_file_sha256(fPath);
		if (!WhiteList(fPath)) {
			//以下为静态检测
			std::string riskType;
			size_t fsize = getFileSize(CSafeAntivirusEngine::getProcessPath(pe32.th32ProcessID));
			log("Start the static detection with process(", pe32.th32ProcessID, "). ", "file size: ", fsize, "byte.");
			if (fsize <= 10485760) { //文件大小小于等于10MB，完整检测检测时间大约在0.5s~3.5s左右
				riskType = CSafeAntivirusEngine::detectFile(fPath);
			} else { // 提示信息
				log_warn("The program file is a little fat, please wait patiently.");
				riskType = CSafeAntivirusEngine::detectFile(fPath); // 对于大文件检测时间可能比较长，但是超大可执行文件还是少数(90%是因为史山代码)
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
				Notice += "拦截到恶意软件并隔离(如果隔离失败会有提示)：";
				Notice += pe32.szExeFile;
				Notice += "\n病毒类型：";
				Notice += riskType;
				Notice += "\n源位置：";
				Notice += fPath;
				Notice += "\nSHA-256: ";
				Notice += hash;
				Notice += "\n是否将其保留在隔离区？\n如果点击是，将会将其留在隔离区；\n如果点击否，则会释放其并为其添加白名单。";
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

			//下面是基于TOProtect的动态行为检测
			PauseProcess(pe32.th32ProcessID, false);
			std::stringstream arguments;
			TOProtectInfo riskInfo = CSafeAntivirusEngine::detectProcess(pe32, &arguments);
			HandleTOProtect(pe32, riskInfo, &arguments);
		}
	} catch (const std::runtime_error &e) {
		log_error("Catch a engine error! In process(", pe32.th32ProcessID, "): ", pe32.szExeFile, ", Error details: \n", e.what());
		if (std::string(e.what()).find("ReleaseFile()") != std::string::npos) {
			WriteList(fPath); // 有的时候可能因为文件隔离失败导致释放文件的时候throw出error，这个时候还没加白名单，因此需要特判一下
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

		if (!EnableDynamicEngine) { //如果未启用动态引擎的话就加大Sleep时长来降低占用
			Sleep(100);
		} else {
			Sleep(34);
		}
	}
}

//文件防护

//监控目录变化并对于变化执行处理函数
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
		if (getFileSize(filePath) <= 10485760) { //文件大小小于等于10MB，完整检测检测时间大约在0.5s~3.5s左右
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
			Notice += "监控到恶意软件并隔离(如果隔离失败会有提示)：\n";
			Notice += filePath;
			Notice += "\n病毒类型：";
			Notice += riskType;
			Notice += "\nSHA-256: ";
			Notice += hash;
			Notice += "\n是否将其保留在隔离区？\n如果点击是，将会将其留在隔离区；\n如果点击否，则会释放其并为其添加白名单。";
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
			WriteList(filePath); // 有的时候可能因为文件隔离失败导致释放文件的时候throw出error，这个时候还没加白名单，因此需要特判一下
		}
	}
}

void FileHandler(std::string filePath) {
	if (!EnableStaticEngine) {
		log_warn("Static detection is not enable. Give up the detection with file {", filePath, "}.");
		return;
	}
	std::thread handleThread(FileHandler_thread, filePath);
	handleThread.detach();//因为该函数的执行是阻塞的，所以需要单开一个进程去检测
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