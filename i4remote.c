#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
 #include <sys/sysinfo.h>
#include <time.h>
#include <pthread.h>
#include <sys/wait.h>
#include <signal.h>
#include "P2PTunnelAPIs.h"
#include "IOTCAPIs.h"
#include "log.h"
#include <errno.h>
#include "chkinet.h"

typedef unsigned long long off64;

//#define URLIOT   "http://www.simicloud.com/media/iotcs/net/info"
//#define URL_UUIDEU   "https://eu1.simicloud.com/media/iotcs/get?sn="
//#define URLIOTEU   "https://eu1.simicloud.com/media/iotcs/net/info"
// Enable auto launch PasswordServer.
#define LAUNCH_PASSWORD_PROC 0
#define PID_FILE	"/var/run/tutkp2p.pid"
#define PID_FILE2	"/var/run/tutkp2p.run"
#define LOCKMODE (S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)

#define DFTHOST	"www.simicloud.com"
char *get_uuid = 
"GET /media/iotcs/get?sn=%s HTTP/1.1\r\n"
"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*/;q=0.8\r\n"
"Accept-Language: zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3\r\n"	
"Connection: keep-alive\r\n"
"Host: %s\r\n\r\n";

char *report_info = 
"POST /media/iotcs/net/info HTTP/1.1\r\n"
"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*/;q=0.8\r\n"
"Content-Type:application/x-www-form-urlencoded\r\n"
"Connection: keep-alive\r\n"
"Content-Length: %d\r\n"
"Host: %s\r\n\r\n%s";

/*tutk relative var*/
int gSID_Used[20];
int gSID_StartTime[20];
// default password if no "passwd.txt" exist
char gPassword[24]="P2P Platform";
typedef struct st_AuthData{
	char szUsername[64];
	char szPassword[64];
} sAuthData;


/*remote Context*/
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

typedef struct {
	int days;
	char expire_time[512];	
	char current_time[512];
	char sn[64];
	char uuid[22];
}i4remote;

i4remote context; 

void thread_cond_sleep(int second)
{
	struct timespec tm;
	int ret;
	
	tm.tv_sec = time(NULL) + second;
	tm.tv_nsec = 0;
	pthread_mutex_lock(&mutex);
	ret = pthread_cond_timedwait(&cond, &mutex, &tm);
	printf("Condition->%d\n", ret);
	pthread_mutex_unlock(&mutex);
}

int decode_http_contentlen(const char *recvbuf, off64 *contentlen)
{
	char *tmp = NULL;
	int hcode = 0;

	if(recvbuf == NULL){
		return -1;
	}
	tmp = strstr(recvbuf, "HTTP/1.1");
	if(tmp == NULL || ((hcode=atoi(tmp+strlen("HTTP/1.1"))) < 200 &&
				hcode >= 300)){
		DPRINTF("Http head format is wrong error code [%d][%s]!!!\n", hcode, recvbuf);
		return -1;
	}
	tmp = strstr(recvbuf, "Content-Length:");
	if(tmp == NULL){
		DPRINTF("Http head format is wrong!!!\n");
		return -1;
	}
	*contentlen = strtoull(tmp+strlen("Content-Length:"), NULL, 10);
	DPRINTF("contentlen=%lld\n", *contentlen);	
	return 0;
}

int http_request_get(char *content, char *host, int port, 
					char **header, char **response)
{
	int sockfd, already, headsize, cur;
	char *recvbuf = NULL, *headbuf = NULL;
	off64 size;

	if(!content || !host){
		return -1;
	}
	sockfd = open_sockfd_gethostbyname(host,port);
	if(sockfd < 0 && 
		(sockfd = open_sockfd_getaddrinfo(host,port)) < 0){
		DPRINTF("Connect Error\n");
		return -1;
	}

	/*timeout=30s*/
	if(socket_write(sockfd, content, strlen(content), 30) < 0){
		DPRINTF("Write Error\n");
		close(sockfd);
		return -1;
	}
	
	printf("send successful...%s\n", content);
	recvbuf = malloc(4096);
	if(recvbuf == NULL){
		DPRINTF("Calloc Error\n");
		close(sockfd);
		return -1;
	}
	/*timeout=30s*/
	if((already = socket_read(sockfd, recvbuf, 4096, "\r\n\r\n", 30)) < 0){
		DPRINTF("Read Error\n");
		free(recvbuf);
		close(sockfd);
		return -1;
	}
	DPRINTF("Recv buff is:%s\n",recvbuf);
	if(decode_http_contentlen(recvbuf, &size) < 0){
		DPRINTF("Decode Error\n");
		free(recvbuf);
		close(sockfd);
		return -1;
	}
	if(size > 2*1024*1024){
		DPRINTF("Content To Big-->%lld\n", size);
		free(recvbuf);
		close(sockfd);
		return -1;
	}

	headsize = strstr(recvbuf, "\r\n\r\n") + strlen("\r\n\r\n") - recvbuf;
	if(header != NULL){
		headbuf = calloc(1, headsize+1);
		memcpy(headbuf, recvbuf, headsize);
	}
	
	cur = already- headsize;
	DPRINTF("cur=%d already=%u size=%lld \n", cur, already, size);
	while(1){
		int tmp;
		if(cur == size){
			DPRINTF("Receive finish...\n");
			break;
		}else if((4096 - already) < (size - cur)){
			printf("recvbuf is too small...realloc\n");
			recvbuf = realloc(recvbuf, size+headsize+1);
			if(recvbuf == NULL){
				goto HAND_ERR;
			}
		}
		if(size-cur > 4096){
			tmp = socket_read(sockfd, recvbuf+already, 4096, NULL, -1);
		}else{
			printf("We receive other %d bytes\n", (int)size-cur);
			tmp = socket_read(sockfd, recvbuf+already, (int)size-cur, NULL, 30);
		}
		if(tmp < 0){
			DPRINTF("Read M Error\n");
			goto HAND_ERR;
		}
		already += tmp;
		cur += tmp;
	}

	close(sockfd);
	if(header != NULL){
		*header = headbuf;
	}
	*response = recvbuf;

	return 0;
HAND_ERR:
	
	free(recvbuf);
	if(header != NULL){
		free(headbuf);
	}	
	close(sockfd);
	return -1;
}

void* thread_report(void *arg)
{
	char *payload = (char *)arg;
	char request[4096] = {0};
	int sockfd, reslen;

	if(arg == NULL){
		return  NULL;
	}
	sockfd = open_sockfd_gethostbyname(DFTHOST,80);
	if(sockfd < 0 && 
		(sockfd = open_sockfd_getaddrinfo(DFTHOST,80)) < 0){
		DPRINTF("Connect Error\n");
		free(payload);
		return NULL;
	}

	/*timeout=30s*/
	snprintf(request, 4095, report_info, strlen(payload), DFTHOST, payload);
	if(socket_write(sockfd, request, strlen(request), 30) < 0){
		DPRINTF("Write Error\n");		
		free(payload);	
		close(sockfd);
		return NULL;
	}
	
	DPRINTF("Report OK:%s\n", payload);
	free(payload);	
	/*timeout=30s*/
	memset(request, 0, sizeof(request));
	reslen = socket_read(sockfd, request, 4096, "\r\n\r\n", 30);
	printf("Response:%d\n%s\n", reslen, request);

	close(sockfd);
	return NULL;	
}

static void report_p2psrv_info(unsigned char mode,unsigned char natType, char *sn)
{
	char *post_content = NULL;
	pthread_t rtid;

	post_content = calloc(1, 512);

	snprintf(post_content, 511, "sn=%s&nattype=%u&mode=%u", sn, natType, mode);

	if (pthread_create(&rtid , NULL, thread_report, (void *)post_content) != 0){
		DPRINTF("Create Report Thread ERROR: %s\n", strerror(errno));
		return ;
	}
	pthread_detach(rtid);
}

void TunnelStatusCB(int nErrorCode, int nSID, void *pArg)
{
	if(nErrorCode == TUNNEL_ER_DISCONNECTED){
		DPRINTF("SID[%d] TUNNEL_ER_DISCONNECTED!\n", nSID);
		P2PTunnelServer_Disconnect(nSID);
		gSID_Used[nSID] = 0;
		if(pArg != NULL){
			printf("MyArg = %s\n", (char *)pArg);
		}
	}
}

int TunnelSessionInfoCB(sP2PTunnelSessionInfo *sSessionInfo, void *pArg)
{
	DPRINTF("TunnelSessionInfoCB trigger\n");
	if(pArg != NULL) printf("pArg = %s\n", (char *)pArg);
	DPRINTF("[Client Session Info]\n");
	DPRINTF("Connection Mode=%d, NAT type = %d\n", sSessionInfo->nMode, sSessionInfo->nNatType);
	DPRINTF("P2PTunnel Version=%X, SID=%d\n", (unsigned int)sSessionInfo->nVersion, sSessionInfo->nSID);
	DPRINTF("IP Address=%s:%d\n", sSessionInfo->szRemoteIP, sSessionInfo->nRemotePort);

	/*end: report info to server*/
	if(sSessionInfo->nAuthDataLen == 0 || sSessionInfo->pAuthData == NULL){
		return -777;
	}else if(sSessionInfo->nAuthDataLen > 0){
		sAuthData *pAuthData = (sAuthData *)sSessionInfo->pAuthData;
		printf("Auth data length = %d, username = %s, passwd = %s\n", sSessionInfo->nAuthDataLen, pAuthData->szUsername, pAuthData->szPassword);
		if(strcmp(pAuthData->szUsername, "Tutk.com") != 0 || strcmp(pAuthData->szPassword, gPassword) != 0){
			return -888;
		}
	}
	gSID_Used[sSessionInfo->nSID] = 1;
	gSID_StartTime[sSessionInfo->nSID] = time(NULL);
	
	DPRINTF("Set Tutk Buffer to --->512000[SID:%d]\n", sSessionInfo->nSID);
	if(P2PTunnel_SetBufSize(sSessionInfo->nSID, 512000) < 0){
		DPRINTF("P2PTunnel_SetBufSize error SID[%d]\n", sSessionInfo->nSID);
	}
	
	/*start: report info to server*/
	report_p2psrv_info(sSessionInfo->nMode, sSessionInfo->nNatType, context.sn);
	
	return 0;
}

static int getSnfromDev(char *getsn)
{	
	char str_sn[33]= {0};

	/*get wifi interface last 4 bit mac from flash,*/
	if(flash_read("/dev/mtd5", 0x43c, str_sn, 32)== FAILURE){
		return FAILURE;
	}
	
	memcpy(getsn,str_sn,32);
	DPRINTF("SN:%s!\n",getsn);
	return SUCCESS;	
}

/*input argument example :
	Fri, 23 Dec 2016 08:20:21 GMT
	return value 0 error,other is time of seconds
*/
time_t time_str2tm(char *timestr)
{
	time_t timeval;
	struct tm *tm_ptr ,timestruct;
	char buf[1024]={0};
	char *result;

	if(timestr == NULL){
		return 0;
	}
	strncpy(buf,timestr, strlen(timestr));
	tm_ptr = &timestruct;
	result = strptime(buf, "%a, %d %b %Y %H:%M:%S",tm_ptr);

	timeval = mktime(tm_ptr);
	if(timeval != -1){
		return timeval;//success
	}
	return 0;// error
}

/* Purpose   : Write process pid file
 * Prameters : *fname: the pid file path and name
 * Return    : FAILURE: 0
 *             SUCCESS: 1
 */
static int dm_write_pidfile(const char *fname)
{	
	char str[32];
	int len;
	pid_t pid;
	int fd = -1, ret = FAILURE;

	if(!fname || (strlen(fname) == 0))
		return FAILURE;
	remove(fname);
	pid = getpid();

	fd = open(fname, O_WRONLY|O_CREAT|O_EXCL, 0666);
	if (fd <= 0) {
		return FAILURE;
	}
	len = snprintf(str, sizeof(str), "%d\n", pid);
	if (len <= 0) {
		goto DM_ERR;
	} 
	if(write(fd, str, len) < 0) {
		goto DM_ERR;
	}
	ret = SUCCESS;

DM_ERR:
	if (fd != -1) {
		close(fd);

	}
	return ret;
}

long sys_uptime(void)
{
	struct sysinfo info;

	if (sysinfo(&info))
		return 0;

	return info.uptime;
}

void signal_handler(int signo)
{
	switch(signo){
		case SIGINT:
			DPRINTF("Recevie SIGINT and quit!!!\n");			
			pthread_cond_signal(&cond);
			exit(1);
		case SIGHUP:
			DPRINTF("Receive SIGHUP, Interupt Sleep\n");
			pthread_cond_signal(&cond);
			break;
		default:
			DPRINTF("Receive Unknow signal, ignore...\n");
	}
}

void* check_expire_time(void *arg)
{
	time_t cur_time, expiretime;
	int sleeptime;
	time_t validtime;

	cur_time = time_str2tm(context.current_time);
	expiretime = time_str2tm(context.expire_time);	
	if(cur_time <= 0 || expiretime <= 0){
		DPRINTF("Current Time Failed:%s=%s\n", context.current_time, context.expire_time);
		remove(PID_FILE);
		return NULL;
	}
	
	while(1){	
		validtime = expiretime-cur_time;
		if(validtime >= 86400){//more than 24 hour
			sleeptime=43200;//12 hours
		}else if((validtime< 86400)&& (validtime >= 43200)){
			sleeptime = 7200;
		}else if ((validtime< 43200)&& (validtime >= 3600)){
			sleeptime = 3600;
		}else if((validtime< 3600)&& (validtime >= 1800)){
			sleeptime = 1800;
		}else if((validtime< 1800)&& (validtime >= 900)){
			sleeptime = 900;
		}else if((validtime< 900)&& (validtime >= 300)){
			sleeptime = 300;
		}else if((validtime< 300)&& (validtime > 0)){
			sleeptime = 30;
		}else{
			remove(PID_FILE);
			exit(-1);
		}
		sleep(sleeptime);
		cur_time += sleeptime;
	}
	
	return NULL;
}

int main(int argc, char *argv[])
{
	char logfile[1024]={0};
	char urlbuf[4096]={0};	
	int i;
	char *phead = NULL, *presponse = NULL, *ptr = NULL;
	pthread_t tid_expire_time = 0;
	struct sigaction act;
	
	if(argc < 2){		
		strcpy(logfile,"/tmp/remote.log");
		dm_daemon();
	}
	
	/*Check run*/
    if (already_running(PID_FILE2)){
		printf("Another %s is running! Exit!\n", argv[0]);
		exit(1);
    }
	memset(&act, 0, sizeof(struct sigaction));
	act.sa_handler = signal_handler;
	sigfillset(&act.sa_mask);
	if(sigaction(SIGHUP, &act, NULL) == -1) {
		printf("Fail to sigaction");
		exit(1);
	}
	act.sa_handler = SIG_IGN;
	sigfillset(&act.sa_mask);
    if (sigaction(SIGPIPE, &act, NULL) == -1 ||
			sigaction(SIGCHLD, &act, NULL) == -1) {
            printf("Fail to signal(SIGPIPE)");
    }
	
	if(dm_write_pidfile(PID_FILE)== FAILURE){
		return -1;
	}
	printf("Log:%s!\n", logfile);	
	if(log_init(logfile)==0){
		printf("log init ok\n");
	}
	
	DPRINTF("Tunnel Version[%X]\n", P2PTunnel_Version());
	memset(&context, 0, sizeof(context));
	for(;;){
		if(network_is_ok() == SUCCESS){
			DPRINTF("Network is OK \n");
			/**get sn**/
			if(getSnfromDev(context.sn) != SUCCESS){
				thread_cond_sleep(15);
				continue;
			}
			/*get uuid*/
			sprintf(urlbuf, get_uuid, context.sn, DFTHOST);
			if(http_request_get(urlbuf, DFTHOST, 80, &phead, &presponse) < 0){
				thread_cond_sleep(15);
				continue;
			}
			ptr = strstr(phead, "Date:");
			if(ptr == NULL){
				DPRINTF("No Found Date Field\n");
				free(phead);
				free(presponse);				
				thread_cond_sleep(35);
				continue;
			}
			ptr += strlen("Date:");
			i = 0;
			while(*ptr == ' '){
				ptr++;
			}
			while(*ptr != '\r'){
				context.current_time[i++] = *ptr;
				ptr++;
			}
			DPRINTF("Current Time is:%s\n", context.current_time);
			ptr = strstr(presponse, "\"error\":");
			if(ptr == NULL){
				DPRINTF("No Found error Field\n");
				free(phead);
				free(presponse);				
				thread_cond_sleep(60);
				continue;
			}
			ptr+= strlen("\"error\":");
			if(atoi(ptr) != 0){
				DPRINTF("Json error:%d\n", atoi(ptr));
				free(phead);
				free(presponse);
				thread_cond_sleep(60);
				continue;
			}
			/*days*/
			ptr = strstr(presponse, "\"days\":");
			if(ptr == NULL){
				DPRINTF("No Found days Field\n");
				free(phead);
				free(presponse);				
				thread_cond_sleep(60);
				continue;
			}
			ptr+= strlen("\"days\":");
			context.days = atoi(ptr);			
			DPRINTF("Days is:%d\n", context.days);
			/*sn*/
			ptr = strstr(presponse, "\"sn\":");
			if(ptr == NULL){
				DPRINTF("No Found sn Field\n");
				free(phead);
				free(presponse);				
				thread_cond_sleep(60);
				continue;
			}
			ptr+= strlen("\"sn\":");			
			i = 0;
			while(*ptr == ' ' || *ptr == '"'){
				ptr++;
			}
			if(strncmp(context.sn, ptr, strlen(context.sn))){
				DPRINTF("SN Not Mitch:%s->%s\n", context.sn, ptr);
				free(phead);
				free(presponse);				
				thread_cond_sleep(60);
				continue;
			}

			/*expires*/
			ptr = strstr(presponse, "\"expires\":");
			if(ptr == NULL){
				DPRINTF("No Found expires Field\n");
				free(phead);
				free(presponse);				
				thread_cond_sleep(60);
				continue;
			}
			ptr+= strlen("\"expires\":");			
			i = 0;
			while(*ptr == ' ' || *ptr == '"'){
				ptr++;
			}
			while(*ptr != '"'){
				context.expire_time[i++] = *ptr;
				ptr++;
			}
			DPRINTF("Expires Time is:%s\n", context.expire_time);
			/*uuid*/
			ptr = strstr(presponse, "\"uuid\":");
			if(ptr == NULL){
				DPRINTF("No Found uuid Field\n");
				free(phead);
				free(presponse);				
				thread_cond_sleep(60);
				continue;
			}
			ptr+= strlen("\"uuid\":");			
			i = 0;
			while(*ptr == ' ' || *ptr == '"'){
				ptr++;
			}
			while(*ptr != '"'){
				context.uuid[i++] = *ptr;				
				ptr++;
			}
			DPRINTF("UUID is:%s\n", context.uuid);
			free(phead);
			free(presponse);				

			if(time_str2tm(context.current_time) >= time_str2tm(context.expire_time)){
				DPRINTF("TimeOut-->%s->%s\n", context.current_time, context.expire_time);
				thread_cond_sleep(60);
				continue;
			}
			break;
		}else{
			thread_cond_sleep(15);
			continue;
		}	
	}

	if (pthread_create(&tid_expire_time , NULL, check_expire_time, NULL) != 0){
		DPRINTF("Create Thread ERROR: %s\n", strerror(errno));	
		remove(PID_FILE);
		exit(1);
	}
	/*TUTK Relative*/
	for(i=0;i<20;i++){
		gSID_Used[i]=0;
	}
	
	P2PTunnelServer_GetStatus(TunnelStatusCB, NULL);
	int ret = P2PTunnelServerInitialize(20);//defautl is 20
	if(ret < 0){
		DPRINTF("P2PTunnelServerInitialize error[%d]!\n",ret);
		remove(PID_FILE);
		return -1;
	}

	ret = P2PTunnelServer_Start(context.uuid);
	if(ret < 0){
		// No Internet
		if(ret == IOTC_ER_SERVER_NOT_RESPONSE || ret == IOTC_ER_NETWORK_UNREACHABLE ){
			DPRINTF("No Internet [%d]!\n",ret);
		}else{
			DPRINTF("P2PTunnelServer_Start error[%d]!\n", ret);
		}
	}else{
		DPRINTF("P2PTunnelServer_Start Success\n");		
		ret = P2PTunnelServer_GetSessionInfo(TunnelSessionInfoCB, NULL);		
		DPRINTF("Call P2PTunnelServer_GetSessionInfo ret[%d]\n", ret);
	}
	int retry = 0, lognum = 0;
	while(1){
		int end =0;
		if( ret < 0 && ++retry%15==0){
			ret = P2PTunnelServer_Start(context.uuid);
			if(ret < 0){
				// No Internet
				if(ret == IOTC_ER_SERVER_NOT_RESPONSE || ret == IOTC_ER_NETWORK_UNREACHABLE){
					DPRINTF("No Internet [%d]!! Reconnect after 15sec...\n", ret);
				}else{
					DPRINTF("P2PTunnelServer_Start Error[%d]!\n", ret);
				}
			}else{		
				ret = P2PTunnelServer_GetSessionInfo(TunnelSessionInfoCB, NULL);
				DPRINTF("P2PTunnelServer_Start Success again.\n");	
			}
			retry=0;
		}
		for(i=0; i<20; i++){
			if(gSID_Used[i]){
				int access_time = P2PTunnel_LastIOTime(i);
				if(access_time < 0){
					DPRINTF("P2PTunnel_LastIOTime Error Code %d\n", access_time);	
					gSID_Used[i] = 0;
				}else{
					printf("SID %d:%u, ", i, access_time);
				}
				end =1;
			}
		}
		if(end)
			printf("\n");
		if(++lognum % 300 == 0){
			struct stat st;		
			if(strlen(logfile) &&  stat(logfile, &st) == 0 &&
					st.st_size > 100*1024){
				log_reset_size(logfile);
				DPRINTF("Reset Log File\n");				
			}
			lognum = 0;
		}		
		sleep(1);
	}

	
	return 0;
}



