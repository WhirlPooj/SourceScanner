#include "Scanner.h"
#include "database.h"
#include <iostream>

int main() {

	databaseInit();
	readExports();

	printf("As of now the scanner only works with C++/C and maybe C# (dll imports)\n");

	setfile("D:\\TestFile.txt");
	ScanResult result = scan();

	if (result.positive) {

		printf("FILENAME: %s ->\n", loaded_name.c_str());

		printf("Scan came back positive!\n");
		printf("Scan found %i results\n", result.results.size());

		for (MaliciousResult r : result.results) {
			printf("[RESULT]: Function name: %s-> \n	 Malicious arguments found: %i\n	 Function malicious?: %s\n	 Reason for detection: %s\n", r.func.c_str(), r.args.size(), r.isMalicious ? "true" : "false", r.reason.c_str());
			for (std::string arg : r.args)
				printf("	 Found argument: %s\n", arg.c_str());
			printf("<-\n");
		}
		printf("<-\n");

		printf("Recommended action: %s\n", result.action.c_str());
	}

	std::cin.get();

	return 0;
}