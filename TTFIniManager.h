#pragma once

#include "TTFRule.h"

class TTFIniManager
{
public:
	TTFRules rules;
	unsigned int localAddr;
	int blackListThreshold;

	TTFIniManager():localAddr(0), blackListThreshold(0) {}
	void parse(void);
};
