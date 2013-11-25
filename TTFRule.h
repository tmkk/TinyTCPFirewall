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
	double transferRateUpperAlt;
	unsigned long long transferAmountUpperAlt;
	double transferRateLowerAlt;
	unsigned long long transferAmountLowerAlt;
	
	TTFRule(std::string &name, int d, double w, double a, double tru, unsigned long long tau, double trl, unsigned long long tal) :
		processName(name), direction(d), when(w), applyAfter(a), 
		transferRateUpper(tru*1024), transferAmountUpper(tau*1024),
		transferRateLower(trl*1024), transferAmountLower(tal*1024),
		transferRateUpperAlt(0), transferAmountUpperAlt(0),
		transferRateLowerAlt(0), transferAmountLowerAlt(0)
	{}
	TTFRule(std::string &name, int d, double w, double a, double tru, unsigned long long tau, double trl, unsigned long long tal,
		double trua, unsigned long long taua, double trla, unsigned long long tala) :
		processName(name), direction(d), when(w), applyAfter(a), 
		transferRateUpper(tru*1024), transferAmountUpper(tau*1024),
		transferRateLower(trl*1024), transferAmountLower(tal*1024),
		transferRateUpperAlt(trua*1024), transferAmountUpperAlt(taua*1024),
		transferRateLowerAlt(trla*1024), transferAmountLowerAlt(tala*1024)
	{}
	TTFRule(const char *name, int d, double w, double a, double tru, unsigned long long tau, double trl, unsigned long long tal) :
		processName(std::string(name)), direction(d), when(w), applyAfter(a), 
		transferRateUpper(tru*1024), transferAmountUpper(tau*1024),
		transferRateLower(trl*1024), transferAmountLower(tal*1024),
		transferRateUpperAlt(0), transferAmountUpperAlt(0),
		transferRateLowerAlt(0), transferAmountLowerAlt(0)
	{}
	TTFRule(const char *name, int d, double w, double a, double tru, unsigned long long tau, double trl, unsigned long long tal,
		double trua, unsigned long long taua, double trla, unsigned long long tala) :
		processName(std::string(name)), direction(d), when(w), applyAfter(a), 
		transferRateUpper(tru*1024), transferAmountUpper(tau*1024),
		transferRateLower(trl*1024), transferAmountLower(tal*1024),
		transferRateUpperAlt(trua*1024), transferAmountUpperAlt(taua*1024),
		transferRateLowerAlt(trla*1024), transferAmountLowerAlt(tala*1024)
	{}
};

typedef std::tr1::shared_ptr<TTFRule> PTTFRule;
typedef std::vector<PTTFRule> TTFRules;
