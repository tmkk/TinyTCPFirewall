#pragma once

#include "TTFRule.h"
#include <vector>
#include <utility>

class TTFIniManager
{
public:
	TTFRules rules;
	unsigned int localAddr;
	int blackListThreshold;
	int disableCloseButton;
	std::vector<unsigned int> blackList;
	std::vector<std::pair<unsigned int, unsigned int> > rangedBlackList;

	TTFIniManager():localAddr(0), blackListThreshold(0), disableCloseButton(0) {}
	void parse(void);
};
