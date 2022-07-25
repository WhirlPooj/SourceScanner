#include "Scanner.h"
#include "WindowsDllEnumerate.h"
#include "database.h"
#include <Windows.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <map>
#include <format>
#include <filesystem>
#include <thread>

using namespace std::filesystem;

std::string CURRENT_LOADED;
std::vector<std::string> DLLS = {"C:\\Windows\\System32\\user32.dll", "C:\\Windows\\System32\\kernel32.dll"};
std::vector<std::string> EXPORTS;
std::string loaded_name;
int LEXER_CURRENT;

void LEXER_NEXT()
{
    if (LEXER_CURRENT > CURRENT_LOADED.size())
        return;
    else
        LEXER_CURRENT++;
}

void LEXER_BEHIND()
{
    if (LEXER_CURRENT < 0)
        return;
    else
        LEXER_CURRENT--;
}

bool isalnumpp(char c) {
    if (c != '"' && c != '\'')
        return isalnum(c);
    else {
        return true;
    }
}

std::string read_string()
{
    std::string word;

    /* Starts off at the quote, so skip it so this guy can understand it. */
    if (LEXER_CURR == '"' || LEXER_CURR == '\'')
        LEXER_NEXT();
    while (LEXER_CURR != '"' && LEXER_CURR != '\'') {
        word.append(1, LEXER_CURR);
        if (LEXER_CURR == '"' || LEXER_CURR == '\'')
            break;
        LEXER_NEXT();
    }
    LEXER_NEXT();
    return word;
}

std::string read_function()
{
    std::string word;
    while (isalnumpp(LEXER_CURR) ) {
        word.append(1, LEXER_CURR);
        if (LEXER_CURR == '"' || LEXER_CURR == '\'') {
            word = read_string();
            break;
        }
        LEXER_NEXT();
    }
    LEXER_NEXT();
    return word;
}

void addDefine(std::string e) {
    char c = e.back();
    if (isupper(c)) {
        std::string s = e.erase(e.size() - 1, 1);
        if (!isInVector(EXPORTS, e))
            EXPORTS.push_back(s);
    }
}

void readExports()
{
    for (std::string DLL : DLLS) {
        printf("Reading export from: %s", (char*)DLL.c_str());
        EnumExportedFunctions((char*)DLL.c_str(), exportRead);
        for (auto i = DLL.begin(); i < DLL.end(); i++)
            printf(" ");
        printf("[OK]\n");
    }
}

void exportRead(char* szName)
{
    std::string func(szName);
    EXPORTS.push_back(func);
    addDefine(func);
}

MaliciousResult scanExport(std::string e) {
    MaliciousResult result = MaliciousResult();

    result.isMalicious = false;

    std::string arg;
    do {
        arg = read_function();
        if (arg != "") {
            if (isMalicious(e, arg)) {
                result.func = e;
                result.args.push_back(arg);
                result.isMalicious = isMalicious(e, arg);
                result.reason = getReasonForMalicious(e, arg);
            }
        }
        if (LEXER_CURRENT == CURRENT_LOADED.size())
            break;
    } while (!isMalicious(e, arg));
    return result;
}

ScanResult scan()
{
    ScanResult result = ScanResult();
    std::vector<MaliciousResult> threats;

    do {

        std::string f = read_function();
        if (f != "") {
            if (isInVector(EXPORTS, f)) {
                printf("Found %s\n", f.c_str());
                threats.push_back(scanExport(f));
            }
        }

    } while (LEXER_CURRENT != CURRENT_LOADED.size());

    int amt = 0;
    for (MaliciousResult v : threats) {

        if (v.isMalicious) {
            result.results.push_back(v);
            amt += 1;

            result.action = "Remove references to the aforementioned functions.";
        }
    }

    if (threats.size() - amt != 0 && amt >= threats.size() - amt)
        result.positive = true;

    return result;
}

void readLoadedFile(const char* file)
{
    std::ifstream stream;
    stream.open(file); 

    std::string tmp((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());

    stream.close();

    loaded_name = file;
    CURRENT_LOADED = tmp;
    LEXER_CURRENT = 0;

}