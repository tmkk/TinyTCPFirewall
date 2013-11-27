#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "TTFIniManager.h"

void TTFIniManager::parse(void)
{
	char iniPath[MAX_PATH], sections[32768];
	sprintf(iniPath,".\\Rules.ini");
	
	rules.clear();
	
	blackListThreshold = GetPrivateProfileInt("Global","BlackListThreshold",0,iniPath);
	int applyAfterGlobal = GetPrivateProfileInt("Global","ApplyAfter",0,iniPath);
	char addrStr[32];
	GetPrivateProfileString("Global","MyIPAddress","",addrStr,32,iniPath);
	if(addrStr[0] != 0 && strcasecmp(addrStr,"auto")) {
		bool fail = true;
		unsigned int num;
		char *ptr;
		num = strtoul(addrStr,&ptr,10);
		if(*ptr++ != '.') goto end;
		localAddr = num & 0xff;
		num = strtoul(ptr,&ptr,10);
		if(*ptr++ != '.') goto end;
		localAddr |= (num & 0xff) << 8;
		num = strtoul(ptr,&ptr,10);
		if(*ptr++ != '.') goto end;
		localAddr |= (num & 0xff) << 16;
		num = strtoul(ptr,&ptr,10);
		localAddr |= (num & 0xff) << 24;
		fail = false;
end:
		if(fail) localAddr = 0;
		//fprintf(stderr,"%d.%d.%d.%d\n",localAddr&0xff,(localAddr >> 8)&0xff,(localAddr >> 16)&0xff,(localAddr >> 24)&0xff);
	}
	else localAddr = 0;
	
	blackList.clear();
	int loadBlacklist = GetPrivateProfileInt("Global","LoadBlackList",0,iniPath);
	if(loadBlacklist) {
		FILE *fp = fopen("blacklist.txt","r");
		if(fp) {
			while(fgets(sections,32768,fp)) {
				unsigned int num;
				char *ptr = strchr(sections,':');
				if(!ptr) continue;
				num = strtoul(++ptr,&ptr,10) & 0xff;
				if(*ptr++ != '.') continue;
				num |= (strtoul(ptr,&ptr,10) & 0xff) << 8;
				if(*ptr++ != '.') continue;
				num |= (strtoul(ptr,&ptr,10) & 0xff) << 16;
				if(*ptr++ != '.') continue;
				num |= (strtoul(ptr,&ptr,10) & 0xff) << 24;
				if(num) blackList.push_back(num);
			}
			fclose(fp);
		}
	}
	
	sections[0] = sections[1] = sections[2] = 0;
	GetPrivateProfileString(NULL,NULL,NULL,sections,32768,iniPath);
	char section[256];
	int pos=0,len=0;
	while(1) {
		section[len++] = sections[pos++];
		if(sections[pos] == 0) {
			section[len] = 0;
			if(!strncasecmp(section,"rule",4)) {
				char exeName[MAX_PATH];
				GetPrivateProfileString(section,"ExeName","",exeName,MAX_PATH,iniPath);
				if(exeName[0] != 0) {
					int direction = 0;
					int when = GetPrivateProfileInt(section,"When",0,iniPath);
					int applyAfter = GetPrivateProfileInt(section,"ApplyAfter",applyAfterGlobal,iniPath);
					int transferRateUpper = GetPrivateProfileInt(section,"TransferRateUpper",0,iniPath);
					int transferAmountUpper = GetPrivateProfileInt(section,"TransferAmountUpper",0,iniPath);
					int transferRateLower = GetPrivateProfileInt(section,"TransferRateLower",0,iniPath);
					int transferAmountLower = GetPrivateProfileInt(section,"TransferAmountLower",0,iniPath);
					if(transferRateUpper || transferAmountUpper || transferRateLower || transferAmountLower) {
						direction = GetPrivateProfileInt(section,"Direction",0,iniPath);
						rules.push_back(PTTFRule(new TTFRule(exeName,direction,when,applyAfter,transferRateUpper,transferAmountUpper,transferRateLower,transferAmountLower)));
					}
					else {
						int uploadRateUpper = GetPrivateProfileInt(section,"UploadRateUpper",0,iniPath);
						int uploadAmountUpper = GetPrivateProfileInt(section,"UploadAmountUpper",0,iniPath);
						int uploadRateLower = GetPrivateProfileInt(section,"UploadRateLower",0,iniPath);
						int uploadAmountLower = GetPrivateProfileInt(section,"UploadAmountLower",0,iniPath);
						if(uploadRateUpper || uploadAmountUpper || uploadRateLower || uploadAmountLower)
							direction = 1;
						int downloadRateUpper = GetPrivateProfileInt(section,"DownloadRateUpper",0,iniPath);
						int downloadAmountUpper = GetPrivateProfileInt(section,"DownloadAmountUpper",0,iniPath);
						int downloadRateLower = GetPrivateProfileInt(section,"DownloadRateLower",0,iniPath);
						int downloadAmountLower = GetPrivateProfileInt(section,"DownloadAmountLower",0,iniPath);
						if(downloadRateUpper || downloadAmountUpper || downloadRateLower || downloadAmountLower) {
							if(direction) direction = 2;
						}
						if(direction == 2)
							rules.push_back(PTTFRule(new TTFRule(exeName,direction,when,applyAfter,uploadRateUpper,uploadAmountUpper,uploadRateLower,uploadAmountLower,downloadRateUpper,downloadAmountUpper,downloadRateLower,downloadAmountLower)));
						else if(direction == 1)
							rules.push_back(PTTFRule(new TTFRule(exeName,direction,when,applyAfter,uploadRateUpper,uploadAmountUpper,uploadRateLower,uploadAmountLower)));
						else
							rules.push_back(PTTFRule(new TTFRule(exeName,direction,when,applyAfter,downloadRateUpper,downloadAmountUpper,downloadRateLower,downloadAmountLower)));
					}
				}
			}
			if(sections[pos+1] == 0) break;
			pos++;
			len = 0;
		}
	}
}

