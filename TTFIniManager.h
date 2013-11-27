#pragma once

#include "TTFRule.h"
#include <vector>

class TTFIniManager
{
public:
	TTFRules rules;
	unsigned int localAddr;
	int blackListThreshold;
	std::vector<unsigned int> blackList;

	TTFIniManager():localAddr(0), blackListThreshold(0) {}
	void parse(void);
};
