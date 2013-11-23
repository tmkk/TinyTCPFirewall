#pragma once

#include <tr1/memory>
#include <vector>
#include <map>
#include <set>
#ifdef _WIN32
#include <iphlpapi.h>
#endif
#include "TTFSession.h"
#include "TTFRule.h"
typedef std::map<unsigned long long, PTTFSession> TTFSessionList;

class TTFSessionManager
{
protected:
	const unsigned int localAddr;
	TTFSessionList *sessionList;
	std::set<std::string> targetProcessList;
	std::map<unsigned int,std::string> targetPids;
	std::map<unsigned int,int> blockedAddrs;
	std::set<unsigned int> blackList;
	int blackListThreshold;
	TTFRules rules;
	
public:
	TTFSessionManager(unsigned int lAddr, int threshold);
	~TTFSessionManager();
	
	void commitPacket(unsigned char *data);
	void addRule(PTTFRule rule);
	void updateTargetSessions(void);
	void updateTargetProcessPid(void);
	void applyFilters(void);
	void printTargetSessionsState(void);
private:
	void registerToBlackList(PTTFSession session);
#ifdef _WIN32
	bool applyBlackListFilter(MIB_TCPROW_OWNER_PID *table);
#endif
};