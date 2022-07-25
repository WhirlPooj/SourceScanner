#include "database.h"

std::map<std::string, std::vector<std::string>> MaliciousArguments;

void makeDatabaseObject(std::string f, std::string v[], size_t sz) {
	std::vector<std::string> e(v, v + sz);
	MaliciousArguments[f] = e;
}

void databaseInit()
{
	/* Last malicious argument is the reasoning by the way. */

	std::string CreateFileArgs[] = { R"(\\\\.\\PhysicalDrive0)", "Creates a handle to Master boot record (Possibly malicious intent)"};
	std::string GetProcAddressArgs[] = { "RtlAdjustPrivilege", "NtRaiseHardError", "Possible attempt to trigger Blue screen"};

	makeDatabaseObject("CreateFileW", CreateFileArgs, 2);
	makeDatabaseObject("CreateFile", CreateFileArgs, 2);
	
	makeDatabaseObject("GetProcAddress", GetProcAddressArgs, 3);

}
