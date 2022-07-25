#pragma once

#define LEXER_PEEK CURRENT_LOADED[LEXER_CURRENT - 1]
#define LEXER_SEEK CURRENT_LOADED[LEXER_CURRENT + 1]
#define LEXER_CURR CURRENT_LOADED[LEXER_CURRENT]
#define setfile(s) readLoadedFile(s);
#define isInVector(v, e) (std::find(v.begin(), v.end(), e) != v.end())
#define isMalicious(func,arg) (isInVector(MaliciousArguments[func], arg))
#define isMaliciousString(arg) (isInVector(MaliciousArguments["maliciousStrings"], arg))
#define getReasonForMalicious(func,arg) (MaliciousArguments[func].back())
#define maliciousStringReason MaliciousArguments["maliciousStrings"].back()

#include <string>
#include <vector>

extern std::string CURRENT_LOADED;
extern std::vector<std::string> DLLS;
extern std::string loaded_name;
extern int LEXER_CURRENT;

class MaliciousResult {
public:
	std::vector<std::string> args;
	std::string func;
	std::string reason;
	bool isMalicious;
};

class ScanResult {
public:
	bool positive;
	std::string action;
	std::vector<MaliciousResult> results;
};

extern void LEXER_NEXT();

extern void LEXER_BEHIND();

extern void readLoadedFile(const char* file);

extern std::string read_function();

extern void readExports();

extern void exportRead(char* szName);

extern ScanResult scan();

extern MaliciousResult scanExport(std::string e);