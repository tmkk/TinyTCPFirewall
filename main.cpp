#include "TTFPacketCapture.h"
#include "TTFSessionManager.h"
#include "TTFRule.h"
#include "TTFIniManager.h"
#include "log.h"
#include <stdio.h>
#include <sys/time.h>
#include <windows.h>

int main(int argc, char *argv[])
{
	unsigned char buffer[65536];
	TTFPacketCapture capture;
	TTFIniManager ini;
	ini.parse();

	if(!capture.open(ini.localAddr)) {
		fprintf(stderr,"Socket initialization error\n");
		MessageBox(NULL,"Invalid IP Address, or run with administrator privilege.","Socket initialization error",MB_OK|MB_ICONSTOP);
		return -1;
	}
	
	log_dated_printf(" Started program\n");
	
	struct timeval tv1,tv2;
	TTFSessionManager manager(capture.localAddr, ini.blackListThreshold);
	TTFRules::iterator it = ini.rules.begin();
	while(it != ini.rules.end()) {
		manager.addRule(*it++);
	}
	
	log_dated_printf(" Read %d rule%s\n",ini.rules.size(),ini.rules.size() > 1 ? "s" : "");
	
	if(!ini.blackList.empty()) {
		std::vector<unsigned int>::iterator it2 = ini.blackList.begin();
		while(it2 != ini.blackList.end()) {
			manager.addBlacklistedAddress(*it2++);
		}
		log_dated_printf(" Added %d address%s to blacklist\n",ini.blackList.size(),ini.blackList.size() > 1 ? "es" : "");
	}
	
	manager.updateTargetProcessPid();
	manager.updateTargetSessions();
	
	log_dated_printf(" Started monitoring %d.%d.%d.%d\n",capture.localAddr&0xff,(capture.localAddr >> 8)&0xff,(capture.localAddr >> 16)&0xff,(capture.localAddr >> 24)&0xff);
	
	gettimeofday(&tv1,NULL);
	while(1) {
		unsigned int length = 1024;
		if(capture.read(buffer,length) == false)
		{
			fprintf(stderr,"Error while reading socket\n");
			break;
		}
		manager.commitPacket(buffer);
		gettimeofday(&tv2,NULL);
		double elapsed = tv2.tv_sec-tv1.tv_sec+(tv2.tv_usec-tv1.tv_usec)*1e-6;
		if(elapsed > 1.0) {
			manager.applyFilters();
			manager.updateTargetProcessPid();
			manager.updateTargetSessions();
			//manager.printTargetSessionsState();
			gettimeofday(&tv1,NULL);
		}
		
	}
	
	capture.close();

    return 0;
}
