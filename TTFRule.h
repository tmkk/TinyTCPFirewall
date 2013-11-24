#pragma once

#include <tr1/memory>
#include <vector>
#include <string>

struct TTFRule
{
	const std::string processName;
	int direction;
	double when;
	double applyAfter;
	double transferRateUpper;
	unsigned long long transferAmountUpper;
	double transferRateLower;
	unsigned long long transferAmountLower;
	
	TTFRule(std::string &name, int d, double w, double a, double tru, unsigned long long tau, double trl, unsigned long long tal) :
		processName(name), direction(d), when(w), applyAfter(a), 
		transferRateUpper(tru*1024), transferAmountUpper(tau*1024), transferRateLower(trl*1024), transferAmountLower(tal*1024)
	{}
	TTFRule(const char *name, int d, double w, double a, double tru, unsigned long long tau, double trl, unsigned long long tal) :
		processName(std::string(name)), direction(d), when(w), applyAfter(a), 
		transferRateUpper(tru*1024), transferAmountUpper(tau*1024), transferRateLower(trl*1024), transferAmountLower(tal*1024)
	{}
};

typedef std::tr1::shared_ptr<TTFRule> PTTFRule;
typedef std::vector<PTTFRule> TTFRules;
