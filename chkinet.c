#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <netdb.h>
#include <getopt.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "log.h"
#include "chkinet.h"

#define LOCKMODE    (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)
#define I4SEASON_NETCHK_HOST		"www.simicloud.com"
#define I4SEASON_NETCHK_QUERY		"/media/httpbin/status/204"
char *ntwork_Q= 
	"GET %s HTTP/1.1\r\n"
          "HOST: %s\r\n"
          "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*/;q=0.8\r\n"
          "Accept-Language: zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3\r\n"
          "Connection: keep-alive\r\n\r\n";


int dm_daemon(void)
{
	int pid, i;
	
	switch(fork())
	{
		/* fork error */
	case -1:
		exit(1);
	
		/* child process */
	case 0:
		/* obtain a new process group */
		if((pid = setsid()) < 0) {
			exit(1);
		}

		/* close all descriptors */
		for (i = getdtablesize(); i >= 0; --i) 
			close(i);

		i = open("/dev/null", O_RDWR); /* open stdin */
		dup(i); /* stdout */
		dup(i); /* stderr */

		umask(000);

		//umask(027);

		return SUCCESS;

		/* parent process */
	default:
		exit(0);
	}

	return FAILURE;
}

char *str_ltrim(char *str)
{
	if(str != NULL)
		while ((*str == ' ') || (*str == '\t')) str++;
	
	return str;
}
char *str_rtrim(char *str)
{
	int len;

	if(str == NULL){
		return NULL;
	}

	if (strlen(str) == 0)
		return str;
	
	/* Kill ' ' and '\t' */
	len = strlen(str) - 1;
	while ((str[len] == ' ') || (str[len] == '\t')) {
		if (len)
			len--;
		else {
			str[0] = '\0';
			return str;
		}
	}
	str[len+1] = '\0';
	
	return str;
}

char *str_kill_lf(char *str)
{
	int len;

	if(str == NULL){
		return NULL;
	}

	if (strlen(str) == 0)
		return str;

	len = strlen(str) - 1;
	/* Kill '\n'   */
	while (str[len] == '\n') {
		if (len > 0)
			len--;
		else {
			str[0] = '\0';
			return str;
		}
	}
	str[len+1] = '\0';
	
	return str;
}

char *str_rtrim_lf(char *str)
{
	int len;

	if(str == NULL){
		return NULL;
	}

	if (strlen(str) == 0)
		return str;
	
	len = strlen(str) - 1;
	/* Kill ' ','\t','\n' */
	while ((str[len] == ' ') || (str[len] == '\t') || (str[len] == '\n')) {
		if (len > 0)
			len--;
		else {
			str[0] = '\0';
			return str;
		}
	}
	str[len+1] = '\0';

	return str;
}

char *str_lrtrim(char *str)
{
	char *tmp;
	if(str == NULL){
		return NULL;
	}
	
	tmp = str_ltrim(str);
	tmp = str_rtrim(tmp);

	return tmp;
}

char *str_parse_field_val(char *src, char **field, char **val)
{
	char *start, *end;
	
	start = src;
	if ((end = strchr(src, '=')) == NULL){
//		DPRINTF("%s\n", "arg err");
		return NULL;
	}

	*end++ = '\0';

        /* Get field     */
	*field = str_lrtrim(start);
	
	/* Get the value */
	end = str_ltrim(end);
	*val = str_rtrim_lf(end);
	
	return *val;
}

int config_exist_field(char *path, char *field, char *val)
{
	FILE *fp;
	char buf[256];
	char *tfield;
	char *tval;
	int line=1;

	if(path == NULL ||(fp = fopen(path, "r"))  == NULL){
		DPRINTF("path is null or fopen failed\n");
		return FAILURE;
	}
	memset(buf, 0, 256);
	while(fgets(buf, 256, fp) != NULL){
		if(line++ == 50){
			DPRINTF("Cannot Find !!!!\n");
			break;
		}
		if(str_parse_field_val(buf, &tfield, &tval) == NULL)
			continue;
		if(strcasecmp(field, tfield) == 0){
			strcpy(val, tval);
			fclose(fp);
			return SUCCESS;
		}
		memset(buf, 0, 256);
	}
	
	fclose(fp);
	return FAILURE;
}


int socket_write(int fd, const char *buf, int len, int timeout)
{
	int n = len;
        if (buf == NULL) {
		return -1;
        }

	while (n > 0) {
		int tret;
		fd_set writefd, exceptfd;
		struct timeval tv;

		FD_ZERO(&writefd);
		FD_ZERO(&exceptfd);
		FD_SET(fd, &writefd);
		FD_SET(fd, &exceptfd);

		if (timeout == -1) {
			tret = select(fd+1, 0, &writefd, &exceptfd, NULL);
		} else {
			tv.tv_sec = timeout; /* second */
			tv.tv_usec = 0;      /* us     */
			tret = select(fd+1, 0, &writefd, &exceptfd, &tv);
		}
		if (tret == 0) { /* Timeout */
			return -3;
		} else if (tret == -1) { /* Error */
			if (errno == EINTR)
				continue;
			else {
				return -1;
			}
		} /* else: send data or exception handler */
		if (FD_ISSET(fd, &exceptfd)) {
			return -1;
		}		

		tret = n < 0x2000 ? n : 0x2000;
		tret = send(fd, buf, tret, 0);
		if (tret == -1) {
			if (errno == EINTR){
				continue;
			}else if (errno == ECONNRESET) {
				return -2;
			} else {
				return -1;
			}
		}
		n -= tret;
		buf += tret;
	}

	return len;
}


char *str_memstr(void *s, int slen, void *mstr, int mlen)
{
	unsigned char *start = (unsigned char *)s;
	unsigned char *dst = (unsigned char *)mstr;
	
	if ((s == NULL) || (mstr == NULL) || (slen < 0) || (mlen < 0)){
		return NULL;
	}
	while (start < ((unsigned char *)s + slen)) {
		if (*start == *((unsigned char *)dst)) {
			if (memcmp(start, mstr, mlen) == 0) {
				return (char *)start;
			}
		}
		start++;
	}

	return NULL;
}

int socket_read(int fd, char *base, int len, const char *stop, int timeout)
{
	int n = len;
	char *buf = base;
	if (base == NULL) {
		return -1;
        }
	while (n > 0) {
		int tret;
		fd_set readfd, exceptfd;
		struct timeval tv;

		FD_ZERO(&readfd);
		FD_ZERO(&exceptfd);
		FD_SET(fd, &readfd);
		FD_SET(fd, &exceptfd);

		if (timeout == -1) {
			DPRINTF("select blocked...\n");
			tret = select(fd+1, &readfd, 0, &exceptfd, NULL);
		} else {
			tv.tv_sec = timeout; /* second */
			tv.tv_usec = 0;      /* us     */
			tret = select(fd+1, &readfd, 0, &exceptfd, &tv);
		}
		if (tret == 0) { /* Timeout */
			DPRINTF("Timeout!!!!!!!!!!!...\n");
			return -3;
		} else if (tret == -1) { /* Error */
			if (errno == EINTR){
				continue;
			}else {
				DPRINTF("select failed\n");
				return -1;
			}
		} /* else: receive data or except handle */
		if (FD_ISSET(fd, &exceptfd)) {
			DPRINTF("select exceptfd failed\n");
			return -1;
		}
		
		if (FD_ISSET(fd, &readfd)){
			tret = recv(fd, buf, n, 0);
			if (tret < 0) {
				if ((errno == EINTR) || (errno == EWOULDBLOCK) 
				    || (errno == EAGAIN)) {
					continue;
				} else {
					DPRINTF("recv failed\n");
					return -1;
				}
			} else if (tret == 0) {  /* the peer haved shutdown, terminate */
				DPRINTF("Shutdown connect...\n");
				return -2;
			} else { /* Prepare to the next reading */
				n -= tret;
				buf += tret;
			}

			/* Check stop flag         */
			if (stop != NULL) {
				*buf = '\0';
				/* Got a stop flag */
				if (str_memstr(base, buf - base, (void *)stop,
					       strlen(stop)) != NULL) 
					break;
			}
		}
	}
	return len - n;
}

int connect_nonblock(int sockfd, struct sockaddr *addr, int slen, int nsec)
{
	int error=0,  flag, res;
	fd_set rset, wset;
	struct timeval tv;
	int len;

	flag = fcntl(sockfd, F_GETFL, 0);
	if(flag < 0){
		DPRINTF("fcntl get failed\n");
		return -1;
	}
	if(fcntl(sockfd, F_SETFL, flag | O_NONBLOCK) < 0){
		DPRINTF("fcntl set failed\n");
		return -1;
	}
	res = connect(sockfd, addr, slen);
	if(res < 0){
		if(errno != EINPROGRESS){
			return -1;
		}
	}else if(res == 0){
		goto ok;
	}

	FD_ZERO(&rset);
	FD_SET(sockfd, &rset);
	wset = rset;
	tv.tv_sec = nsec;
	tv.tv_usec = 0;

	res = select(sockfd+1, &rset, &wset, NULL, nsec ? &tv:NULL);
	if(res < 0){
		DPRINTF("select failed\n");
		return -1;
	}else if(res == 0){
		DPRINTF("Nonblock connect timeout!!\n");
		return -1;
	}
	
	if(FD_ISSET(sockfd, &rset) || FD_ISSET(sockfd, &wset)){
		len = sizeof(error);
		if(getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, (socklen_t *)&len) < 0){
			DPRINTF("getsockopt failed\n");
			return -1;
		}
		if(error){
			return -1;
		}else{
			goto ok;
		}
	}else{
		DPRINTF("connect read and write, connect failed!!!\n");
		return -1;
	}

	ok:
		if(fcntl(sockfd, F_SETFL, flag) < 0){
			DPRINTF("fcntl set failed\n");
			return -1;
		}
		
		return 0;
}

int lockfile(int fd)
{
    struct flock f1;
    
    f1.l_type = F_WRLCK;
    f1.l_start = 0;
    f1.l_whence = SEEK_SET;
    f1.l_len = 0;

    return (fcntl(fd, F_SETLK, &f1));
}

int already_running(char *pidfile)
{
    int fd;
    char buf[16];

    fd = open(pidfile, O_RDWR|O_CREAT, LOCKMODE);
    if(fd < 0){
        printf("Can not open %s:%s\n", pidfile, strerror(errno));
        return -1;
    }

    if(lockfile(fd) < 0){
        if(errno == EACCES || errno == EAGAIN){
            close(fd);
            return 1;
        }
        printf("Can not lock %s:%s\n", pidfile, strerror(errno));
        return -1;
    }
    ftruncate(fd, 0);
    sprintf(buf, "%ld", (long)getpid());
    write(fd, buf, strlen(buf)+1);
    return 0;
}

int do_cmd(char *cmd)
{
    //printf("do_cmd_r:%s\n",cmd);
    int pid;
    int statbuf;
    int wpid = 0,  waittime = 0, timeout =3000;
    pid = vfork();
    if(pid < 0)
    {
        return 0;
    }
    if(pid == 0)
    {
        execl("/bin/sh", "sh", "-c", cmd, (char *) 0); 
    }
	while(1){
       		wpid = waitpid(pid, &statbuf, WNOHANG);
     		if (wpid == 0) {
            		if (waittime < timeout) {
               			usleep(100000);
               			waittime ++;
            		}else {
                		kill(pid, SIGKILL);
               			usleep(100000);
       				wpid = waitpid(pid, &statbuf, WNOHANG);
				printf("Warning: do cmd is too long and kill it \n");
                                return -1;
								//break;
            		}
		}else{
			break;
		}
	}
    return 0;
}

int copyFile(const char *sourceFileNameWithPath,  
        const char *targetFileNameWithPath)  
{  
    FILE *fpR, *fpW;  
    char buffer[4096];  
    int lenR, lenW;  
    if ((fpR = fopen(sourceFileNameWithPath, "r")) == NULL)  
    {  
        printf("The file '%s' can not be opened! \n", sourceFileNameWithPath);  
        return FAILURE;  
    }  
    if ((fpW = fopen(targetFileNameWithPath, "w")) == NULL)  
    {  
        printf("The file '%s' can not be opened! \n", targetFileNameWithPath);  
        fclose(fpR);  
        return FAILURE;  
    }  
  
    memset(buffer, 0, 4096);  
    while ((lenR = fread(buffer, 1, 4096, fpR)) > 0)  
    {  
        if ((lenW = fwrite(buffer, 1, lenR, fpW)) != lenR)  
        {  
            printf("Write to file '%s' failed!\n", targetFileNameWithPath);  
            fclose(fpR);  
            fclose(fpW);  
            return FAILURE;  
        }  
        memset(buffer, 0, 4096);  
    }  
  
    fclose(fpR);  
    fclose(fpW);  
    return SUCCESS;  
}  

/* Purpose   : Read data from 'start' address in '*mtddev' MTD device to '*buf'
 * Parameters: 
 *             *mtddev: the MTD device name
 *             start  : the starting address
 *             *buf   : the data buffer to store reading data
 *            buflen  : the buffer length which is multiple of FLASH_MTD_BLK_SIZE.
 *                      shall call FLASH_GET_MULTI_LEN(len) to generate.
 * Return    : FAILURE (0)
 *             SUCCESS (1)
 */
int flash_read(const char *mtddev, int start, char *buf, int buflen)
{
	int fd = -1;
	if ((fd = open(mtddev, O_RDONLY)) == -1) {
		DPRINTF("Open %s:%s\n", mtddev, strerror(errno));
		return FAILURE;
	}
	/* Write the mtdblock device  */
	if (lseek(fd, start, SEEK_SET) == -1) {
		DPRINTF("lseek %s:%s\n", mtddev, strerror(errno));
		close(fd);
		return FAILURE;
	}
	/* Read data from mtdblock    */
	if (read(fd, buf, buflen - 1) != (buflen - 1)) {
		DPRINTF("read_n %s:%s\n", mtddev, strerror(errno));
		close(fd);
		return FAILURE;
	} else {
		buf[buflen - 1] = '\0'; /* prevent over-read */
	}

	close(fd);
	return SUCCESS;
}

int open_sockfd_gethostbyname(char *host,int port)
{
	int sockfd;
	struct sockaddr_in addr;
	struct hostent hent, *result;
	char buff[8192];
	int err;
	char **pptr;
	char ip[32];

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd < 0){
		DPRINTF("socket failed\n");
		return -1;
	}
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	
	DPRINTF("gethostbyname_r DNS host\n");
	if(gethostbyname_r(host, &hent, buff, 8192, &result, &err) != 0){
		DPRINTF("gethostbyname_r failed\n");
		return -1;
	}
	for(pptr = result->h_addr_list; *pptr != NULL; pptr++){
		memcpy(&addr.sin_addr, *pptr, sizeof(addr.sin_addr));
		DPRINTF("Connect to %s...\n", inet_ntop(AF_INET, &addr.sin_addr, ip, 32));
		//if(connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == 0){
		if(connect_nonblock(sockfd, (struct sockaddr *)&addr, sizeof(addr), 5) == 0){
			return sockfd;
		}
	}
	close(sockfd);
	
	return -1;
}

int open_sockfd_getaddrinfo(char *host,int port)
{
	int sockfd;
	struct addrinfo hints, *result, *curr;
	char ip[32];
	char addr_port[5] = {0};

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd < 0){
		DPRINTF("socket failed\n");
		return -1;
	}
	sprintf(addr_port, "%d", port);	

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
		
	DPRINTF("getaddrinfo DNS host\n");
	if(getaddrinfo(host, addr_port, &hints, &result) != 0){
		DPRINTF("getaddrinfo failed\n");
		return -1;
	}
    for(curr = result; curr !=NULL; curr = curr->ai_next){
            inet_ntop(AF_INET,  &(((struct sockaddr_in *)(curr->ai_addr))->sin_addr),
            ip, 16);
		DPRINTF("Connect to %s...\n", ip);
		if(connect_nonblock(sockfd, curr->ai_addr, curr->ai_addrlen, 5) == 0){
			freeaddrinfo(result);
			return sockfd;
		}        
    }
	
	freeaddrinfo(result);
	close(sockfd);
	
	return -1;
}

int network_is_ok(void)
{
	int sockfd;
	char sndbuf[4096] = {0}, rcvbuf[4096] = {0}, *ptmp = NULL;	

	res_init(); 	
	sockfd = open_sockfd_getaddrinfo(I4SEASON_NETCHK_HOST,80);
	if(sockfd < 0){
		sockfd = open_sockfd_gethostbyname(I4SEASON_NETCHK_HOST,80);
		if(sockfd < 0){
			return FAILURE;
		}
	}
	
	snprintf(sndbuf, 4095, ntwork_Q, I4SEASON_NETCHK_QUERY, I4SEASON_NETCHK_HOST);
	if(socket_write(sockfd, sndbuf, strlen(sndbuf),  8) < 0){
		close(sockfd);		
		return FAILURE;
	}
	
	if(socket_read(sockfd,rcvbuf,4095,"\r\n\r\n", 8) < 0){
		close(sockfd);		
		return FAILURE;
	}
	/*Decode HTTP Response*/
	ptmp = strstr(rcvbuf, "HTTP/1.1");
	if(ptmp == NULL || atoi(ptmp+strlen("HTTP/1.1")) != 204){
		close(sockfd);		
		return FAILURE;
	}
	
	close(sockfd);
	return SUCCESS;
}

