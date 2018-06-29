#include <stdio.h>
#include <mntent.h>
#include <time.h>
#include <stdarg.h>
#include <string.h>
#include<errno.h>
#include <unistd.h>
#include <sys/types.h>

FILE *log_fp = NULL;

void log_close(void)
{
	if (log_fp)
		fclose(log_fp);
	
}

int log_init(const char *fname)
{
	/*int i;*/
	FILE *fp;

	if (!fname || strlen(fname) == 0)		// use default i.e. stdout
		return 0;
	if(log_fp){
		fclose(log_fp);
		log_fp = NULL;
	}
	if (!(fp = fopen(fname, "a")))
	{
		printf(">>>>>>>>>>>>fopen %s:%s\n", fname, strerror(errno));
		return 1;
	}
	log_fp = fp;
	return 0;
}

void log_err(char *fname, const char *func, int lineno, char *fmt, ...)
{
	va_list ap;
	pid_t pid;
	
	if (!log_fp)
		log_fp = stdout;

	pid = getpid();
	
	// timestamp
	
	time_t t;
	struct tm *tm, tmptm={0};
	t = time(NULL);
	//tm = localtime(&t); Modify by zhangwei 20151022, locatime is not thread safe
	localtime_r(&t, &tmptm);
	tm=&tmptm;
	fprintf(log_fp, "[%04d/%02d/%02d %02d:%02d:%02d] ",
			tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
			tm->tm_hour, tm->tm_min, tm->tm_sec);

	/*fprintf(stdout, "[%04d/%02d/%02d %02d:%02d:%02d] ",*/
			/*tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,*/
			/*tm->tm_hour, tm->tm_min, tm->tm_sec);*/
	
	fprintf(log_fp, "[pid:%d] ", pid);
	/*fprintf(stdout, "[pid: %d] ", pid);*/
	
	fprintf(log_fp, "(%s:%s():%d) ", fname, func, lineno);
	/*fprintf(stdout, "(%s:%s():%d) ", fname, func, lineno);*/

	// user log
	va_start(ap, fmt);
	if (vfprintf(log_fp, fmt, ap) == -1)
	{
		va_end(ap);
		return;
	}
	/*if (vfprintf(stdout, fmt, ap) == -1)*/
	/*{*/
		/*va_end(ap);*/
		/*return;*/
	/*}*/
	va_end(ap);

	fflush(log_fp);

	return;
}

void log_reset_size(const char *fname)
{
	truncate(fname, 0);
	if (log_fp){
		rewind(log_fp);
	}
}

void log_debug(FILE *fp, char *fname, const char *func, int lineno, char *fmt, ...)
{
	va_list ap;
	pid_t pid;
	
	if (fp == NULL)
		fp=stderr;

	pid = getpid();
	
	// timestamp
	
	time_t t;
	struct tm *tm, tmptm={0};
	t = time(NULL);
	//tm = localtime(&t); Modify by zhangwei 20151022, locatime is not thread safe
	localtime_r(&t, &tmptm);
	tm=&tmptm;
	fprintf(fp, "[%04d/%02d/%02d %02d:%02d:%02d] ",
			tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
			tm->tm_hour, tm->tm_min, tm->tm_sec);

	/*fprintf(stdout, "[%04d/%02d/%02d %02d:%02d:%02d] ",*/
			/*tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,*/
			/*tm->tm_hour, tm->tm_min, tm->tm_sec);*/
	
	fprintf(fp, "[pid:%d] ", pid);
	/*fprintf(stdout, "[pid: %d] ", pid);*/
	
	fprintf(fp, "(%s:%s():%d) ", fname, func, lineno);
	/*fprintf(stdout, "(%s:%s():%d) ", fname, func, lineno);*/

	// user log
	va_start(ap, fmt);
	if (vfprintf(fp, fmt, ap) == -1)
	{
		va_end(ap);
		return;
	}
	/*if (vfprintf(stdout, fmt, ap) == -1)*/
	/*{*/
		/*va_end(ap);*/
		/*return;*/
	/*}*/
	va_end(ap);

	fflush(fp);

	return;
}
int get_dev_mountpoint(const char *dev, char *mntpoint)
{
	FILE *file = NULL;
	struct mntent *mount_entry = NULL, mntdata;
	char mbuf[1024];
	
	if((dev==NULL))
		return 0;

	/* Open mount file  */
	if ((file = setmntent("/proc/mounts", "r")) == NULL) {
		return 0;
	}

	memset(mbuf, 0, sizeof(mbuf));
	/* Read mount file  */
	while((mount_entry = getmntent_r(file, &mntdata, mbuf, sizeof(mbuf))) != NULL) {
		if(strncmp(dev,mount_entry->mnt_dir, strlen(dev)) != 0){
			printf("dev=%s!   mountPoint=%s\n", dev, mount_entry->mnt_fsname);
			continue;
		}
		/* Found, Get the file system informaton  */
		printf("Found MountPoint  :%s\n", mount_entry->mnt_dir);
		strcpy(mntpoint, mount_entry->mnt_dir);
		//strcpy(fsname, mount_entry->mnt_type);
		endmntent(file);
		return 1;

	}

	endmntent(file);
	
	return 0;
}

