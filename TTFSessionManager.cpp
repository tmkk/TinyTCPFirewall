#include <stdio.h>
#include <string>
#include <map>
#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#else
#include <arpa/inet.h>
#endif
#include "TTFSessionManager.h"
#include "log.h"

typedef struct
{
	unsigned char  verhead;
	unsigned char  tos;
	unsigned short len;
	unsigned short id;
	unsigned short frag;
	unsigned char  ttl;
	unsigned char  prot;
	unsigned short chksum;
	unsigned int srcip;
	unsigned int dstip;
	unsigned char  data[0];
} IPHeader;

typedef struct
{
	unsigned short sport;
	unsigned short dport;
	unsigned long seq;
	unsigned long ack;
	unsigned char hlr;
	unsigned char rfl;
	unsigned short win;
	unsigned short sum;
	unsigned short urp;
} TCPHeader;

TTFSessionManager::TTFSessionManager(unsigned int lAddr, int threshold) :
	localAddr(lAddr), blackListThreshold(threshold)
{
	sessionList = new TTFSessionList();
}

TTFSessionManager::~TTFSessionManager()
{
	delete sessionList;
}

void TTFSessionManager::addRule(PTTFRule rule)
{
	rules.push_back(rule);
	targetProcessList.insert(rule->processName);
}

void TTFSessionManager::addBlacklistedAddress(unsigned int address)
{
	blackList.insert(address);
}

void TTFSessionManager::addRangedBlacklistedAddress(unsigned int start, unsigned int end)
{
	rangedBlackList.push_back(std::make_pair(start,end));
}

void TTFSessionManager::commitPacket(unsigned char *data)
{
	if(sessionList->empty()) return;
	IPHeader *header = (IPHeader *)data;
	if(header->prot == 6 && header->dstip != 0 && header->srcip != 0) {
		TCPHeader *tcpHeader = (TCPHeader *)(data + 4*(header->verhead & 0xf));
		unsigned short sport = ntohs(tcpHeader->sport);
		unsigned short dport = ntohs(tcpHeader->dport);
		if(header->srcip == localAddr) {
			if(sport && dport) {
				unsigned long long key = ((unsigned long long)sport << 48) | ((unsigned long long)(header->dstip) << 16) | dport;
				TTFSessionList::iterator it = sessionList->find(key);
				if(it != sessionList->end()) {
					//fprintf(stderr,"committing outgoing packet\n");
					it->second->commitPacket(data);
				}
			}
		}
		else if(header->dstip == localAddr) {
			if(sport && dport) {
				unsigned long long key = ((unsigned long long)dport << 48) | ((unsigned long long)(header->srcip) << 16) | sport;
				TTFSessionList::iterator it = sessionList->find(key);
				if(it != sessionList->end()) {
					//fprintf(stderr,"committing incoming packet\n");
					it->second->commitPacket(data);
				}
			}
		}
		
	}
}

#ifdef _WIN32
bool TTFSessionManager::applyBlackListFilter(MIB_TCPROW_OWNER_PID *table)
{
	if(blackList.empty() || blackList.find(table->dwRemoteAddr) == blackList.end()) {
		if(rangedBlackList.empty()) return false;
		std::vector<std::pair<unsigned int, unsigned int> >::iterator it = rangedBlackList.begin();
		unsigned int addr = ntohl(table->dwRemoteAddr);
		while(it != rangedBlackList.end()) {
			if(addr >= it->first && addr <= it->second) goto found;
			it++;
		}
		return false;
	}
found:
	MIB_TCPROW session;
	session.dwLocalAddr = table->dwLocalAddr;
	session.dwLocalPort = table->dwLocalPort;
	session.dwRemoteAddr = table->dwRemoteAddr;
	session.dwRemotePort = table->dwRemotePort;
	session.dwState = MIB_TCP_STATE_DELETE_TCB;
	SetTcpEntry(&session);
	
	log_dated_printf("\n    Blocked connection from blacklisted address %ld.%ld.%ld.%ld\n",table->dwRemoteAddr&0xff,(table->dwRemoteAddr >> 8)&0xff,(table->dwRemoteAddr >> 16)&0xff,(table->dwRemoteAddr >> 24)&0xff);
	return true;
}
#endif

void TTFSessionManager::updateTargetSessions(void)
{
	if(targetProcessList.empty()) return;
	if(targetPids.empty()) {
		//fprintf(stderr,"No process to monitor\n");
		sessionList->clear();
		return;
	}
#ifdef _WIN32
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(hProcessSnap == INVALID_HANDLE_VALUE) {
		fprintf(stderr,"Failed to take process snapshot.");
		return;
	}
	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof(processEntry);
	if(!Process32First(hProcessSnap, &processEntry)) {
		fprintf(stderr,"Process32First returned error\n");
		return;
	}
	do {
		std::set<std::string>::iterator it = targetProcessList.begin();
		while(it != targetProcessList.end()) {
			if(it->compare(processEntry.szExeFile) == 0) {
				targetPids.insert(std::make_pair(processEntry.th32ProcessID,*it));
			}
			it++;
		}
	} while(Process32Next(hProcessSnap, &processEntry));
	CloseHandle(hProcessSnap);
	
	if(targetPids.empty()) {
		//fprintf(stderr,"No process to monitor\n");
		return;
	}
	
	DWORD Size=0;
	if(ERROR_INSUFFICIENT_BUFFER == GetExtendedTcpTable(NULL,&Size,TRUE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0)){
		MIB_TCPTABLE_OWNER_PID *tcp = (PMIB_TCPTABLE_OWNER_PID) new char[Size];
		if(NO_ERROR == GetExtendedTcpTable(tcp,&Size,TRUE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0)){
			TTFSessionList *newSessionList = new TTFSessionList();
			for(unsigned int i=0; i<tcp->dwNumEntries; i++) {
				std::map<unsigned int,std::string>::iterator it = targetPids.find(tcp->table[i].dwOwningPid);
				if(it != targetPids.end()) {
					unsigned int laddr = tcp->table[i].dwLocalAddr;
					unsigned short lport = ntohs(tcp->table[i].dwLocalPort);
					unsigned int raddr = tcp->table[i].dwRemoteAddr;
					unsigned short rport = ntohs(tcp->table[i].dwRemotePort);
					if(laddr != localAddr || !lport || !raddr || !rport) continue;
					if(this->applyBlackListFilter(&tcp->table[i])) continue;
					unsigned long long key = ((unsigned long long)lport << 48) | ((unsigned long long)raddr << 16) | rport;
					TTFSessionList::iterator it2 = sessionList->find(key);
					if(it2 == sessionList->end()) {
						PTTFSession session(new TTFSession(localAddr,lport,raddr,rport,it->second));
						newSessionList->insert(std::make_pair(key,session));
					}
					else {
						newSessionList->insert(std::make_pair(key,it2->second));
					}
				}
			}
			TTFSessionList *oldSessionList = sessionList;
			sessionList = newSessionList;
			delete oldSessionList;
		}
		else {
			fprintf(stderr,"GetExtendedTcpTable returned error\n");
		}
		delete [] tcp;
	}
	else {
		fprintf(stderr,"GetExtendedTcpTable returned error\n");
	}
#endif
}

void TTFSessionManager::updateTargetProcessPid(void)
{
	if(targetProcessList.empty()) return;
	targetPids.clear();
	
#ifdef _WIN32
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(hProcessSnap == INVALID_HANDLE_VALUE) {
		fprintf(stderr,"Failed to take process snapshot.");
		return;
	}
	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof(processEntry);
	if(!Process32First(hProcessSnap, &processEntry)) {
		fprintf(stderr,"Process32First returned error\n");
		return;
	}
	do {
		std::set<std::string>::iterator it = targetProcessList.begin();
		while(it != targetProcessList.end()) {
			if(it->compare(processEntry.szExeFile) == 0) {
				targetPids.insert(std::make_pair(processEntry.th32ProcessID,*it));
			}
			it++;
		}
	} while(Process32Next(hProcessSnap, &processEntry));
	CloseHandle(hProcessSnap);
#endif
}

void TTFSessionManager::registerToBlackList(PTTFSession session, PTTFRule rule)
{
	if(!blackListThreshold) return;
	std::map<unsigned int,int>::iterator it = blockedAddrs.find(session->remoteAddr);
	bool added = false;
	if(it != blockedAddrs.end()) {
		if(++it->second >= blackListThreshold) {
			blackList.insert(it->first);
			blockedAddrs.erase(it);
			added = true;
		}
	}
	else {
		if(blackListThreshold == 1) {
			blackList.insert(session->remoteAddr);
			added = true;
		}
		else blockedAddrs.insert(std::make_pair(session->remoteAddr,1));
	}
	if(added) {
		char ruleStr[256];
		char addrStr[32];
		snprintf(addrStr,32,"%d.%d.%d.%d",session->remoteAddr&0xff,(session->remoteAddr >> 8)&0xff,(session->remoteAddr >> 16)&0xff,(session->remoteAddr >> 24)&0xff);
		log_dated_printf(" Added %s to blacklist\n",addrStr);
		snprintf(ruleStr,256,"When=%d",(int)rule->when);
		if(rule->direction == 2) {
			if(rule->transferRateUpperAlt) snprintf(ruleStr,256,"%s DownRate>%d",ruleStr,(int)(rule->transferRateUpperAlt/1024));
			if(rule->transferAmountUpperAlt) snprintf(ruleStr,256,"%s DownAmount>%d",ruleStr,(int)(rule->transferAmountUpperAlt/1024));
			if(rule->transferRateLowerAlt) snprintf(ruleStr,256,"%s DownRate<%d",ruleStr,(int)(rule->transferRateLowerAlt/1024));
			if(rule->transferAmountLowerAlt) snprintf(ruleStr,256,"%s DownAmount<%d",ruleStr,(int)(rule->transferAmountLowerAlt/1024));
			if(rule->transferRateUpper) snprintf(ruleStr,256,"%s UpRate>%d",ruleStr,(int)(rule->transferRateUpper/1024));
			if(rule->transferAmountUpper) snprintf(ruleStr,256,"%s UpAmount>%d",ruleStr,(int)(rule->transferAmountUpper/1024));
			if(rule->transferRateLower) snprintf(ruleStr,256,"%s UpRate<%d",ruleStr,(int)(rule->transferRateLower/1024));
			if(rule->transferAmountLower) snprintf(ruleStr,256,"%s UpAmount<%d",ruleStr,(int)(rule->transferAmountLower/1024));
		}
		else if(rule->direction == 1) {
			if(rule->transferRateUpper) snprintf(ruleStr,256,"%s UpRate>%d",ruleStr,(int)(rule->transferRateUpper/1024));
			if(rule->transferAmountUpper) snprintf(ruleStr,256,"%s UpAmount>%d",ruleStr,(int)(rule->transferAmountUpper/1024));
			if(rule->transferRateLower) snprintf(ruleStr,256,"%s UpRate<%d",ruleStr,(int)(rule->transferRateLower/1024));
			if(rule->transferAmountLower) snprintf(ruleStr,256,"%s UpAmount<%d",ruleStr,(int)(rule->transferAmountLower/1024));
		}
		else {
			if(rule->transferRateUpper) snprintf(ruleStr,256,"%s DownRate>%d",ruleStr,(int)(rule->transferRateUpper/1024));
			if(rule->transferAmountUpper) snprintf(ruleStr,256,"%s DownAmount>%d",ruleStr,(int)(rule->transferAmountUpper/1024));
			if(rule->transferRateLower) snprintf(ruleStr,256,"%s DownRate<%d",ruleStr,(int)(rule->transferRateLower/1024));
			if(rule->transferAmountLower) snprintf(ruleStr,256,"%s DownAmount<%d",ruleStr,(int)(rule->transferAmountLower/1024));
		}
		log_blacklist("[%s] %s:%s-%s\n",session->processName.c_str(),ruleStr,addrStr,addrStr);
	}
}

void TTFSessionManager::applyFilters(void)
{
	if(sessionList->empty()) return;
	if(rules.empty()) return;
	
	TTFSessionList::iterator it = sessionList->begin();
	while(it != sessionList->end()) {
		PTTFSession session = it->second;
		TTFRules::iterator it2 = rules.begin();
		double elapsed = session->timeElapsed();
		while(it2 != rules.end()) {
			PTTFRule rule = *it2;
			if((rule->when == 0 && elapsed >= rule->applyAfter) || (rule->when > session->lastChecked && elapsed >= rule->when)) {
				if(rule->processName.compare(session->processName) == 0) {
					int disconnect = 0;
					double transferRate;
					unsigned long long transferAmount;
					double transferRateAlt = 0;
					unsigned long long transferAmountAlt = 0;
					if(rule->direction == 2) {
						transferRate = session->averageUpSpeed();
						transferAmount = session->bytesSent;
						transferRateAlt = session->averageDownSpeed();
						transferAmountAlt = session->bytesReceived;
						if(rule->transferRateUpper) {
							if(transferRate >= rule->transferRateUpper) disconnect = 1;
							else disconnect = -1;
						}
						if(rule->transferAmountUpper && disconnect >= 0) {
							if(transferAmount >= rule->transferAmountUpper) disconnect = 1;
							else disconnect = -1;
						}
						if(rule->transferRateLower && disconnect >= 0) {
							if(transferRate < rule->transferRateLower) disconnect = 1;
							else disconnect = -1;
						}
						if(rule->transferAmountLower && disconnect >= 0) {
							if(transferAmount < rule->transferAmountLower) disconnect = 1;
							else disconnect = -1;
						}
						if(rule->transferRateUpperAlt && disconnect >= 0) {
							if(transferRateAlt >= rule->transferRateUpperAlt) disconnect = 1;
							else disconnect = -1;
						}
						if(rule->transferAmountUpperAlt && disconnect >= 0) {
							if(transferAmountAlt >= rule->transferAmountUpperAlt) disconnect = 1;
							else disconnect = -1;
						}
						if(rule->transferRateLowerAlt && disconnect >= 0) {
							if(transferRateAlt < rule->transferRateLowerAlt) disconnect = 1;
							else disconnect = -1;
						}
						if(rule->transferAmountLowerAlt && disconnect >= 0) {
							if(transferAmountAlt < rule->transferAmountLowerAlt) disconnect = 1;
							else disconnect = -1;
						}
					}
					else {
						if(rule->direction == 0) { // down
							transferRate = session->averageDownSpeed();
							transferAmount = session->bytesReceived;
						}
						else { // up
							transferRate = session->averageUpSpeed();
							transferAmount = session->bytesSent;
						}
						if(rule->transferRateUpper) {
							if(transferRate >= rule->transferRateUpper) disconnect = 1;
							else disconnect = -1;
						}
						if(rule->transferAmountUpper && disconnect >= 0) {
							if(transferAmount >= rule->transferAmountUpper) disconnect = 1;
							else disconnect = -1;
						}
						if(rule->transferRateLower && disconnect >= 0) {
							if(transferRate < rule->transferRateLower) disconnect = 1;
							else disconnect = -1;
						}
						if(rule->transferAmountLower && disconnect >= 0) {
							if(transferAmount < rule->transferAmountLower) disconnect = 1;
							else disconnect = -1;
						}
					}
					if(disconnect > 0) {
						session->disconnect();
						if(transferAmount >= 1024*1024) {
							log_printf("    Reason: %.2f MB %s in %.1f seconds ",transferAmount/1024.0/1024.0,rule->direction?"sent":"received",elapsed);
						}
						else {
							log_printf("    Reason: %.1f KB %s in %.1f seconds ",transferAmount/1024.0,rule->direction?"sent":"received",elapsed);
						}
						if(transferRate >= 1024.0 * 1024.0) {
							log_printf("(%.2f MB/s)\n",transferRate/1024.0/1024.0);
						}
						else {
							log_printf("(%.1f KB/s)\n",transferRate/1024.0);
						}
						if(rule->direction == 2) {
							if(transferAmountAlt >= 1024*1024) {
								log_printf("            %.2f MB received in %.1f seconds ",transferAmountAlt/1024.0/1024.0,elapsed);
							}
							else {
								log_printf("            %.1f KB received in %.1f seconds ",transferAmountAlt/1024.0,elapsed);
							}
							if(transferRateAlt >= 1024.0 * 1024.0) {
								log_printf("(%.2f MB/s)\n",transferRateAlt/1024.0/1024.0);
							}
							else {
								log_printf("(%.1f KB/s)\n",transferRateAlt/1024.0);
							}
						}
						this->registerToBlackList(session,rule);
					}
				}
			}
			it2++;
		}
		session->lastChecked = elapsed;
		it++;
	}
}

void TTFSessionManager::printTargetSessionsState(void)
{
	if(sessionList->empty()) {
		fprintf(stderr,"No sessions to monitor.\n");
		return;
	}
	TTFSessionList::iterator it = sessionList->begin();
	while(it != sessionList->end()) {
		it->second->status();
		it++;
	}
}
