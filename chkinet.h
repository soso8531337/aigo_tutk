#ifndef __CHKINET_H
#define __CHKINET_H

#define FAILURE	0
#define SUCCESS	1

int network_is_ok(void);
int flash_read(const char *mtddev, int start, char *buf, int buflen);
int open_sockfd_gethostbyname(char *host,int port);
int open_sockfd_getaddrinfo(char *host,int port);
int socket_write(int fd, const char *buf, int len, int timeout);
int socket_read(int fd, char *base, int len, const char *stop, int timeout);
int dm_daemon(void);
int already_running(char *pidfile);

#endif
