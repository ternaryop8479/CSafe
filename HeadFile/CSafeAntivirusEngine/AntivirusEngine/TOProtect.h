/*
 * TOProtect.h
 * CSafeɱ������������TOProtect��API��װ�������һЩ������Ϊ�ļ��API��װ
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#ifndef TOProtect_H
#define TOProtect_H

#include <io.h>
#include <chrono>
#include <sstream>
#include <algorithm>
#include <unordered_set>
#include <unordered_map>
#include "EngineHeadFile/TOProtect.h"
#include "EngineHeadFile/toHandlesInfo.h"
#define MAX_MAPSIZE 16384

//--------------�ǽӴ�ʽ��⣬���Ա�֤����Ȩ�޵������Ҳ�м��

// ������API
namespace {
	bool HideFileDetection(PROCESSENTRY32 TargetProcess) {//����ļ��Ƿ�����
		if (IsFileHidden(GetProcessFullPath(TargetProcess.th32ProcessID)))
			return true;
		return false;
	}

	bool HideExeDetection(PROCESSENTRY32 TargetProcess) {//����ļ���Ŀ¼����������exe
		std::string directoryPath = GetProcessFullPath(TargetProcess.th32ProcessID);

		for (int i = 0; i < directoryPath.size(); ++i) {
			if (directoryPath[i] == '/')
				directoryPath[i] = '\\';
		}

		for (int i = directoryPath.size() - 1; i >= 0; --i) {
			if (directoryPath[i] == '\\') {
				directoryPath.erase(i, directoryPath.size() - 1);
				break;
			}
		}

		directoryPath += "\\*.exe";

		WIN32_FIND_DATA findFileData;
		HANDLE hFind = FindFirstFile(directoryPath.c_str(), &findFileData);

		if (hFind == INVALID_HANDLE_VALUE) {
			throw std::runtime_error("TOProtect-TOProtect.h-HideExeDetection(): Failed to FindFirstFile()");
		}

		do {
			if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN)
				return true;

			// ȷ������Ŀ¼��ֻ�г��ļ�
			if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				continue;
			}
		} while (FindNextFile(hFind, &findFileData) != 0);

		FindClose(hFind); // �ر��������
		return false;
	}

	bool HideDllDetection(PROCESSENTRY32 TargetProcess) {//����ļ���Ŀ¼����������dll
		std::string directoryPath = GetProcessFullPath(TargetProcess.th32ProcessID);

		for (int i = 0; i < directoryPath.size(); ++i) {
			if (directoryPath[i] == '/')
				directoryPath[i] = '\\';
		}

		for (int i = directoryPath.size() - 1; i >= 0; --i) {
			if (directoryPath[i] == '\\') {
				directoryPath.erase(i, directoryPath.size() - 1);
				break;
			}
		}

		directoryPath += "\\*.dll";

		WIN32_FIND_DATA findFileData;
		HANDLE hFind = FindFirstFile(directoryPath.c_str(), &findFileData);

		if (hFind == INVALID_HANDLE_VALUE) {
			throw std::runtime_error("TOProtect-TOProtect.h-HideDllDetection(): Failed to FindFirstFile()");
		}

		do {
			if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN)
				return true;

			// ȷ������Ŀ¼��ֻ�г��ļ�
			if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				continue;
			}
		} while (FindNextFile(hFind, &findFileData) != 0);

		FindClose(hFind); // �ر��������
		return false;
	}

	// -- 2025.2.21 Ternary_Operator ADD: �ú��������ã����ڶ��ϴ���ļ������壬�öδ�����Ȼ���������Ǽ����������øú������������ڲ��˽�CSafeAE�ϴ����״̬��
	bool StartItemDetection(PROCESSENTRY32 TargetProcess) {
		std::vector<std::string> StartItems = getStartupItems();

		for (int i = 0; i < StartItems.size(); ++i) {
			for (int j = 0; j < StartItems[i].size(); ++j) {
				if (StartItems[i][j] == '/')
					StartItems[i][j] = '\\';
			}
			FilterProgramName(StartItems[i]);
		}

		const std::string ProcessPath = GetProcessFullPath(TargetProcess.th32ProcessID);

		for (int i = 0; i < StartItems.size(); ++i) {
			if (StartItems[i] == ProcessPath)
				return true;
		}
		return false;
	}

	bool IEFODetection(PROCESSENTRY32 TargetProcess) {
		std::vector<std::string> IEFOItems = ScanIEFO();

		for (int i = 0; i < IEFOItems.size(); ++i) {
			for (int j = 0; j < IEFOItems[i].size(); ++j) {
				if (IEFOItems[i][j] == '/')
					IEFOItems[i][j] = '\\';
			}
			FilterProgramName(IEFOItems[i]);
		}

		const std::string ProcessPath = GetProcessFullPath(TargetProcess.th32ProcessID);

		for (int i = 0; i < IEFOItems.size(); ++i) {
			if (IEFOItems[i] == ProcessPath)
				return true;
		}
		return false;
	}

	inline std::string strGenerateRiskLevel(short RiskLevel) {
		if (RiskLevel <= 0) { //RiskLevel <= 0���޷���
			return "Risk.NoRisk";
		} else if (RiskLevel >= 1 && RiskLevel <= 3) { //1 <= RiskLevel <= 3���ͷ���
			return "Risk.LowRisk";
		} else if (RiskLevel >= 4 && RiskLevel <= 6) { //4 <= RiskLevel <= 6���еȷ���
			return "Risk.MidRisk";
		} else if (RiskLevel >= 7 && RiskLevel <= 8) { //7 <= RiskLevel <= 8��Σ��
			return "Risk.HighRisk";
		}

		//RiskLevel > 8(RiskLevel >= 9)������
		return "Risk.Malware";
	}

	inline bool isInSensitiveFolder(const std::string &file, const std::string &processFolder) {
		return (file.find("\\desktop\\") != std::string::npos ||
		        file.find("\\document") != std::string::npos ||
		        file.substr(0, file.find_last_of("\\/")) == processFolder); // Ҫ��Ŀ���ļ���Ҫ�ڳ���ĸ�Ŀ¼�¶����Ǹ�Ŀ¼����Ŀ¼��
	}
}

class TOProtectInfo {
	public:
		TOProtectInfo(std::string _expectedType, short _riskLevel) : expectedType(_expectedType), riskLevel(_riskLevel) {}

		std::string expectedType;
		short riskLevel;
};

// �ڲ�ʵ�ֵĴ����࣬������������ں˴������ͳһ�洢������Ҫ��ʱ����ȫ��throw���ȱ�֤�˽�׳�ԣ��ֱ�֤��³����
class TOProtectErrorList : public std::runtime_error {
	private:
		std::string errorMsgs;
		bool _isNoError = true;

	public:
		TOProtectErrorList() : std::runtime_error("") {}

		void appendError(const std::runtime_error &error) {
			errorMsgs += error.what();
			errorMsgs += "\n";
			_isNoError = false;
		}

		bool isNoError() {
			return _isNoError;
		}

		const char *what() const noexcept override {
			return errorMsgs.c_str();
		}
};

//----------------�Ӵ�ʽ�������������ɱ������

TOProtectInfo TOProtect(PROCESSENTRY32 targetProcess, std::stringstream *logStreamPtr = nullptr, unsigned short maxDelayMS = 3200) {
#define logStream if (logStreamPtr != nullptr) *logStreamPtr // ��������־���

	TOProtectErrorList finalExceptions; // Ҫ�������throw��ȥ��error

	const std::string TypePrefix = "TOProtect."; // ���صĲ�������ǰ׺
	short finalRisk = 0; // ������ܷ��յȼ�
	std::string expectedVirusType = "Malware.Unknown"; // Ԥ�ƵĲ������ͣ����ݼ����Ŀ����̵Ĳ�ͬ��Ϊ����

	auto startTime = std::chrono::high_resolution_clock::now(); // ��ʼ��ʱ

	std::unordered_map<std::string, std::unordered_set<std::string>> usedDirectories; // ���ڲ�ɱ��������һ�����ͱ�ʾʹ�õ�Ŀ¼���ڶ������ͱ�ʾĿ¼�·��ʹ����ļ�����Ŀ¼�ظ�����ʱʧ��ʱ������ļ����Ƿ���ͬ������ͬ���ظ�++
	std::unordered_map<std::string, unsigned short> sameDirectories; // ����ͬһ�ļ����µĲ�ͬ�ļ��Ĵ���
	unsigned short totalSameCount = 0;                               // ���������ظ��ļ����µĲ��ظ��ļ��Ĵ���
	unsigned short sensitiveFolderCount = 0;                         // ���������ļ��еĴ���
	std::string lastFolder = "", lastFile = "";                      // [��������]�����ʵ��ļ��к��ļ�

	bool detectionsDone[3] = {0}; // ��ֹ�ظ������
	bool isFirstDetection = true; // ������ʶ�Ƿ��ǵ�һ�μ��

	if (IsProcessElevatedForProcessID(targetProcess.th32ProcessID)) { // ����Ա������յȼ��Զ�+2
		finalRisk += 2;
	}

	std::string processFolder = GetProcessFullPath(targetProcess.th32ProcessID); // Ŀ����������ļ���
	processFolder = processFolder.substr(0, processFolder.find_last_of("\\/")); // �ص��ļ���
	std::transform(processFolder.begin(), processFolder.end(), processFolder.begin(),
	[](unsigned char c) {
		return std::tolower(c);
	}); // ת��ΪСд

	while (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - startTime).count() < maxDelayMS) {
		try { // ��Ϊһ��throw�����������������ѭ������˲��õ���Ӱ����밲ȫ��
			std::vector<std::string> usingFiles = GetTargetFilePaths(targetProcess.th32ProcessID, false); // ��ȡ���̵�ǰ�򿪵������ļ������·��
			for (std::string &file : usingFiles) { // �ļ�����ϵ��
				std::transform(file.begin(), file.end(), file.begin(),
				[](unsigned char c) {
					return std::tolower(c);
				}); // ��ת��ΪСд

				if (file.find("physicaldrive0") != std::string::npos) { // MBR����
					return TOProtectInfo(TypePrefix + "Malware.Killer.MBR", finalRisk + 9); // �ƻ��Բ��������µ�MBR����
				}

				if ((file.find(".exe") != std::string::npos || (file.find(".dll") != std::string::npos && IsFileHidden(file))) && (file.find(".exe") + 4 == file.size() || file.find(".dll") + 4 == file.size())) { // ��ֹ���ʿ�ִ���ļ�д��������
					// -- 2025.2.15 Ternary_Operator ADD: ��ʵ�����Է��֣�һ�������ڳ���������һ������ʱ���򿪵��ļ����Ҳ�ǿ��Ա���ɱ���ģ���������������Բ��ķѱ���Ĳ�ɱʱ��ȥ���
					logStream << "[Trojan Detection] PATH: " << file << std::endl;
					return TOProtectInfo(TypePrefix + "Malware.Trojan", finalRisk + 8); // ��������ȷ����ľ��Ҳ�п�������棬��������Ҳ����ľ����
				}

				if (!detectionsDone[0] && (file.find(".inf") != std::string::npos || file.find(".ini") != std::string::npos) && (file.find(".inf") + 4 == file.size() || file.find(".ini") + 4 == file.size())) { // ��ֹд�������ļ�
					finalRisk += 7;
					detectionsDone[0] = 1;
					expectedVirusType = "Malware.Worm"; // ��ʾԤ�ƿ�������没��
					logStream << "[Worm Detection] PATH: " << file << std::endl;
				}

				size_t lastSlashPos = file.find_last_of("\\/"); // ����ר��
				const std::string fFolder = file.substr(0, lastSlashPos), fName = file.substr(lastSlashPos + 1);
				auto result = usedDirectories.insert(std::make_pair(fFolder, std::unordered_set<std::string>()));

				if (!result.second && usedDirectories.find(fFolder)->second.insert(fName).second) { // ���������Ŀ¼���Ҳ��Ƿ�������ͬһ�ļ���˵���п����ǲ����ڱ���ͬһ���ļ���
					++totalSameCount; // �Ȱ��ܵ��ظ���������1
					if (sameDirectories.count(fFolder) == 0) { // ���˵���Ŀ¼��û�з��ֹ��ظ�
						sameDirectories.insert(std::make_pair(fFolder, 1)); // �����Ŀ¼���ڵļ�ֵ�Խ��г�ʼ�����ظ�����Ϊ1
					} else {
						++sameDirectories.find(fFolder)->second; // �ظ���������һ��
					}
					logStream << "[BlackMail Detection] TOTAL: " << totalSameCount << ", FOLD: " << sameDirectories.find(fFolder)->second << ", PATH: " << file << ", FOLDPATH: " << fFolder << std::endl;

					// ����λ������Ŀ¼�µ��ļ�
					if (isInSensitiveFolder(file, processFolder)) {
						++sensitiveFolderCount;
						logStream << "[BlackMail Detection-SensitiveFolder] COUNT: " << sensitiveFolderCount << ", PATH: " << file << std::endl;
						if (sensitiveFolderCount >= 3) {
							return TOProtectInfo(TypePrefix + "Malware.Trojan.BlackMail", finalRisk + 10);
						}
					}
					// �ھ��а�����ϵ������Ŀ¼���ظ������ļ�
					if (lastFolder != "" && lastFolder != fFolder && (lastFolder.find(fFolder) != std::string::npos || fFolder.find(lastFolder) != std::string::npos)) {
						logStream << "[BlackMail Detection-SameFolder] lastFolder: " << lastFolder << ", now-folder: " << fFolder << ", count(LastFolder): " << sameDirectories.find(lastFolder)->second << ", count(NowFolder): " << sameDirectories.find(fFolder)->second << std::endl;
						if ((sameDirectories.find(fFolder)->second >= 3 && sameDirectories.find(lastFolder)->second >= 2) ||
						        (sameDirectories.find(fFolder)->second >= 2 && sameDirectories.find(lastFolder)->second >= 3) || isInSensitiveFolder(file, processFolder) || isInSensitiveFolder(lastFile, processFolder)) { // �������������ٻ���
							return TOProtectInfo(TypePrefix + "Malware.Trojan.BlackMail", finalRisk + 11);
						}
					}
					// �����������������У���һ���Ƿ��ʵ����ظ��ļ����µ��ļ���Ŀ����22�����ж�Ϊ������
					// �ڶ�������һ��Ŀ¼�·����˳���17���ļ����ж�Ϊ������
					// �����������ͬ�ļ��еļ�⣬����ܷ����뵱ǰ���ʵ��ļ����ظ���Ŀ��Ϊ5������ζ��һֱ�ڱ���һ���ļ��У��ж�Ϊ������
					// ͬһ��Ŀ¼�·��ʵĻ���%user%\appdata��windows����Ŀ¼���ػ�
					if (totalSameCount >= 22 ||
					        ((file.find("\\appdata\\") != std::string::npos || file.find("\\windows\\fonts\\") != std::string::npos) ? (sameDirectories.find(fFolder)->second >= 20) : 0) ||
					        (sameDirectories.find(fFolder)->second >= 17) ||
					        (totalSameCount == 5 && sameDirectories.find(fFolder)->second == 5)) {
						return TOProtectInfo(TypePrefix + "Malware.Trojan.BlackMail", finalRisk + 9);
					}

					lastFolder = fFolder, lastFile = file;
				}
			}

			try {
				if (isFirstDetection) { // ��һЩ�ȽϺ�ʱ����ֻ��Ҫsleepһ����֮����һ�εļ����Ŀ�ͷŵ�����ȵ�һ�μ��ִ����(�󲿷ֲ���Ҳ����Ӧ������ʼ�����ֶ���)ʱ�ټ��
					// -- 2025.2.15 Ternary_Operator ADD: 100���밡������������100���룡��̫�ֲ��ˣ�������������һ����������Ӧ�û�úܶ�
					IEFODetection(targetProcess) ? finalRisk += 8 : 0;
					HideFileDetection(targetProcess) ? expectedVirusType = "Malware.Trojan_or_Worm", finalRisk += 7 : 0;
					// StartItemDetection(targetProcess) ? finalRisk += 3 : 0; -- 2025.2.15 Ternary_Operator ADD: ������ɨ���ô����󣬼�������3�������Ҽ��˻�������һ�ѣ����ֶ�̫�ͻ�����Ѵ����ȼ��µ�
					isFirstDetection = false;
				}

				// �ǽӴ�ʽ����������ץ��Ϊ��������û��Ӧ�������µ�©��֮��  --2025.2.15 Ternary_Operator ADD: ����Ҳռ����ʲôʱ�䣬һ���������()
				(!detectionsDone[1] && HideExeDetection(targetProcess)) ? expectedVirusType = "Malware.Trojan_or_Worm", detectionsDone[1] = 1, finalRisk += 7 : 0;
				(!detectionsDone[2] && HideDllDetection(targetProcess)) ? expectedVirusType = "Malware.Trojan_or_Worm", detectionsDone[2] = 1, finalRisk += 7 : 0;
			} catch (const std::runtime_error &e) {
				if (std::string(e.what()).find("TOProtect") == std::string::npos) { // ���ַ�����ִ�й����м���������Ȩ�����⣬�������������������ֱ�Ӻ��Լ���
					throw;
				}
			}
		} catch (std::runtime_error e) {
			finalExceptions.appendError(e);
		}

		if (finalRisk >= 9) {
			return TOProtectInfo(TypePrefix + expectedVirusType, finalRisk);
		}
	}
	if (!finalExceptions.isNoError()) {
		throw finalExceptions; // �����׳������쳣
	}
	return TOProtectInfo(TypePrefix + "Safe", finalRisk);
}

#endif