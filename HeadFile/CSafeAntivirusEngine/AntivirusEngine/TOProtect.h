/*
 * TOProtect.h
 * CSafe杀毒引擎子引擎TOProtect的API封装及定义和一些风险行为的检测API封装
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

//--------------非接触式检测，可以保证在无权限的情况下也有检出

// 不开放API
namespace {
	bool HideFileDetection(PROCESSENTRY32 TargetProcess) {//检查文件是否隐藏
		if (IsFileHidden(GetProcessFullPath(TargetProcess.th32ProcessID)))
			return true;
		return false;
	}

	bool HideExeDetection(PROCESSENTRY32 TargetProcess) {//检查文件根目录下有无隐藏exe
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

			// 确保跳过目录，只列出文件
			if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				continue;
			}
		} while (FindNextFile(hFind, &findFileData) != 0);

		FindClose(hFind); // 关闭搜索句柄
		return false;
	}

	bool HideDllDetection(PROCESSENTRY32 TargetProcess) {//检查文件根目录下有无隐藏dll
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

			// 确保跳过目录，只列出文件
			if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				continue;
			}
		} while (FindNextFile(hFind, &findFileData) != 0);

		FindClose(hFind); // 关闭搜索句柄
		return false;
	}

	// -- 2025.2.21 Ternary_Operator ADD: 该函数已弃用，出于对老代码的纪念意义，该段代码仍然保留，但是极不建议启用该函数，尤其是在不了解CSafeAE老代码的状态下
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
		if (RiskLevel <= 0) { //RiskLevel <= 0，无风险
			return "Risk.NoRisk";
		} else if (RiskLevel >= 1 && RiskLevel <= 3) { //1 <= RiskLevel <= 3，低风险
			return "Risk.LowRisk";
		} else if (RiskLevel >= 4 && RiskLevel <= 6) { //4 <= RiskLevel <= 6，中等风险
			return "Risk.MidRisk";
		} else if (RiskLevel >= 7 && RiskLevel <= 8) { //7 <= RiskLevel <= 8，危险
			return "Risk.HighRisk";
		}

		//RiskLevel > 8(RiskLevel >= 9)，病毒
		return "Risk.Malware";
	}

	inline bool isInSensitiveFolder(const std::string &file, const std::string &processFolder) {
		return (file.find("\\desktop\\") != std::string::npos ||
		        file.find("\\document") != std::string::npos ||
		        file.substr(0, file.find_last_of("\\/")) == processFolder); // 要求目标文件需要在程序的根目录下而不是根目录的子目录下
	}
}

class TOProtectInfo {
	public:
		TOProtectInfo(std::string _expectedType, short _riskLevel) : expectedType(_expectedType), riskLevel(_riskLevel) {}

		std::string expectedType;
		short riskLevel;
};

// 内部实现的错误类，可以针对引擎内核错误进行统一存储，在需要的时候再全部throw，既保证了健壮性，又保证了鲁棒性
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

//----------------接触式检测整合在主查杀函数里

TOProtectInfo TOProtect(PROCESSENTRY32 targetProcess, std::stringstream *logStreamPtr = nullptr, unsigned short maxDelayMS = 3200) {
#define logStream if (logStreamPtr != nullptr) *logStreamPtr // 简化引擎日志输出

	TOProtectErrorList finalExceptions; // 要留到最后throw出去的error

	const std::string TypePrefix = "TOProtect."; // 返回的病毒类型前缀
	short finalRisk = 0; // 计算的总风险等级
	std::string expectedVirusType = "Malware.Unknown"; // 预计的病毒类型，根据检测中目标进程的不同行为决定

	auto startTime = std::chrono::high_resolution_clock::now(); // 开始计时

	std::unordered_map<std::string, std::unordered_set<std::string>> usedDirectories; // 用于查杀勒索，第一个类型表示使用的目录，第二个类型表示目录下访问过的文件，当目录重复插入时失败时，检测文件名是否相同，不相同就重复++
	std::unordered_map<std::string, unsigned short> sameDirectories; // 访问同一文件夹下的不同文件的次数
	unsigned short totalSameCount = 0;                               // 访问所有重复文件夹下的不重复文件的次数
	unsigned short sensitiveFolderCount = 0;                         // 访问敏感文件夹的次数
	std::string lastFolder = "", lastFile = "";                      // [勒索防护]最后访问的文件夹和文件

	bool detectionsDone[3] = {0}; // 防止重复检测用
	bool isFirstDetection = true; // 用来标识是否是第一次检测

	if (IsProcessElevatedForProcessID(targetProcess.th32ProcessID)) { // 管理员程序风险等级自动+2
		finalRisk += 2;
	}

	std::string processFolder = GetProcessFullPath(targetProcess.th32ProcessID); // 目标进程所在文件夹
	processFolder = processFolder.substr(0, processFolder.find_last_of("\\/")); // 截掉文件名
	std::transform(processFolder.begin(), processFolder.end(), processFolder.begin(),
	[](unsigned char c) {
		return std::tolower(c);
	}); // 转换为小写

	while (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - startTime).count() < maxDelayMS) {
		try { // 因为一旦throw出错误立马跳过这次循环，因此不用担心影响代码安全性
			std::vector<std::string> usingFiles = GetTargetFilePaths(targetProcess.th32ProcessID, false); // 获取进程当前打开的所有文件句柄的路径
			for (std::string &file : usingFiles) { // 文件防护系列
				std::transform(file.begin(), file.end(), file.begin(),
				[](unsigned char c) {
					return std::tolower(c);
				}); // 先转换为小写

				if (file.find("physicaldrive0") != std::string::npos) { // MBR防护
					return TOProtectInfo(TypePrefix + "Malware.Killer.MBR", finalRisk + 9); // 破坏性病毒分类下的MBR分类
				}

				if ((file.find(".exe") != std::string::npos || (file.find(".dll") != std::string::npos && IsFileHidden(file))) && (file.find(".exe") + 4 == file.size() || file.find(".dll") + 4 == file.size())) { // 防止访问可执行文件写入恶意代码
					// -- 2025.2.15 Ternary_Operator ADD: 其实经测试发现，一个进程在尝试运行另一个进程时所打开的文件句柄也是可以被查杀到的，但是情况不大，所以不耗费宝贵的查杀时间去检查
					logStream << "[Trojan Detection] PATH: " << file << std::endl;
					return TOProtectInfo(TypePrefix + "Malware.Trojan", finalRisk + 8); // 基本可以确认是木马，也有可能是蠕虫，不过这里也当作木马处理
				}

				if (!detectionsDone[0] && (file.find(".inf") != std::string::npos || file.find(".ini") != std::string::npos) && (file.find(".inf") + 4 == file.size() || file.find(".ini") + 4 == file.size())) { // 防止写入配置文件
					finalRisk += 7;
					detectionsDone[0] = 1;
					expectedVirusType = "Malware.Worm"; // 表示预计可能是蠕虫病毒
					logStream << "[Worm Detection] PATH: " << file << std::endl;
				}

				size_t lastSlashPos = file.find_last_of("\\/"); // 勒索专防
				const std::string fFolder = file.substr(0, lastSlashPos), fName = file.substr(lastSlashPos + 1);
				auto result = usedDirectories.insert(std::make_pair(fFolder, std::unordered_set<std::string>()));

				if (!result.second && usedDirectories.find(fFolder)->second.insert(fName).second) { // 出现了这个目录并且不是反复访问同一文件，说明有可能是病毒在遍历同一个文件夹
					++totalSameCount; // 先把总的重复次数自增1
					if (sameDirectories.count(fFolder) == 0) { // 如果说这个目录还没有发现过重复
						sameDirectories.insert(std::make_pair(fFolder, 1)); // 给这个目录所在的键值对进行初始化，重复次数为1
					} else {
						++sameDirectories.find(fFolder)->second; // 重复次数自增一下
					}
					logStream << "[BlackMail Detection] TOTAL: " << totalSameCount << ", FOLD: " << sameDirectories.find(fFolder)->second << ", PATH: " << file << ", FOLDPATH: " << fFolder << std::endl;

					// 访问位于敏感目录下的文件
					if (isInSensitiveFolder(file, processFolder)) {
						++sensitiveFolderCount;
						logStream << "[BlackMail Detection-SensitiveFolder] COUNT: " << sensitiveFolderCount << ", PATH: " << file << std::endl;
						if (sensitiveFolderCount >= 3) {
							return TOProtectInfo(TypePrefix + "Malware.Trojan.BlackMail", finalRisk + 10);
						}
					}
					// 在具有包含关系的两个目录中重复访问文件
					if (lastFolder != "" && lastFolder != fFolder && (lastFolder.find(fFolder) != std::string::npos || fFolder.find(lastFolder) != std::string::npos)) {
						logStream << "[BlackMail Detection-SameFolder] lastFolder: " << lastFolder << ", now-folder: " << fFolder << ", count(LastFolder): " << sameDirectories.find(lastFolder)->second << ", count(NowFolder): " << sameDirectories.find(fFolder)->second << std::endl;
						if ((sameDirectories.find(fFolder)->second >= 3 && sameDirectories.find(lastFolder)->second >= 2) ||
						        (sameDirectories.find(fFolder)->second >= 2 && sameDirectories.find(lastFolder)->second >= 3) || isInSensitiveFolder(file, processFolder) || isInSensitiveFolder(lastFile, processFolder)) { // 理论上来讲很少会误报
							return TOProtectInfo(TypePrefix + "Malware.Trojan.BlackMail", finalRisk + 11);
						}
					}
					// 这里有三种条件特判，第一种是访问的总重复文件夹下的文件数目超过22个，判定为病毒，
					// 第二种是在一个目录下访问了超过17个文件，判定为病毒，
					// 第三种是针对同文件夹的检测，如果总访问与当前访问的文件夹重复数目均为5个，意味着一直在遍历一个文件夹，判定为病毒，
					// 同一个目录下访问的话给%user%\appdata和windows字体目录做特化
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
				if (isFirstDetection) { // 有一些比较耗时并且只需要sleep一阵子之后检测一次的检测条目就放到这里，等第一次检测执行完(大部分病毒也都反应过来开始改这种东西)时再检测
					// -- 2025.2.15 Ternary_Operator ADD: 100毫秒啊！！整整将近100毫秒！！太恐怖了！！！但是少了一个启动项检测应该会好很多
					IEFODetection(targetProcess) ? finalRisk += 8 : 0;
					HideFileDetection(targetProcess) ? expectedVirusType = "Malware.Trojan_or_Worm", finalRisk += 7 : 0;
					// StartItemDetection(targetProcess) ? finalRisk += 3 : 0; -- 2025.2.15 Ternary_Operator ADD: 启动项扫描用处不大，加起来才3级，而且加了还可能误报一堆，区分度太低还不如把触发等级下调
					isFirstDetection = false;
				}

				// 非接触式防护，用来抓因为主动防御没反应过来导致的漏网之鱼  --2025.2.15 Ternary_Operator ADD: 反正也占不了什么时间，一两毫秒的事()
				(!detectionsDone[1] && HideExeDetection(targetProcess)) ? expectedVirusType = "Malware.Trojan_or_Worm", detectionsDone[1] = 1, finalRisk += 7 : 0;
				(!detectionsDone[2] && HideDllDetection(targetProcess)) ? expectedVirusType = "Malware.Trojan_or_Worm", detectionsDone[2] = 1, finalRisk += 7 : 0;
			} catch (const std::runtime_error &e) {
				if (std::string(e.what()).find("TOProtect") == std::string::npos) { // 这种防护在执行过程中几乎不会有权限问题，所以这里遇到引擎错误直接忽略即可
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
		throw finalExceptions; // 重新抛出所有异常
	}
	return TOProtectInfo(TypePrefix + "Safe", finalRisk);
}

#endif