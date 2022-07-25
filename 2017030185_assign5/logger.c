#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>

FILE *
fopen(const char *path, const char *mode) 
{

	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	

	int access_type;
	struct stat checker;
    int fex = stat(path,&checker);
    if(fex != 0){
        access_type=0;
    }
    else {
        access_type=1;
    }


	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);
	FILE *logfile = original_fopen("./access_control_logfile.txt","a");
	
	if (logfile ==NULL){perror("No Path found,Error opening file.");}


	//UID
	int UID = getuid();

	//TIME & DATE

	time_t rawtime;
	struct tm * timeinfo;

	time(&rawtime);
	timeinfo=localtime(&rawtime);

	/*ACTION DENIED */
	int action = 0;
	FILE *buff = original_fopen(path,mode);
	if (!buff){action = 1; printf("ACTION DENIED\n");}
	
	/*HASH VALUE*/
	long lSize; char *buffer;
	if(buff){
	fseek(buff, 0L,SEEK_END);
	lSize = ftell(buff);
	rewind(buff);
}

	
	buffer = calloc(1,lSize+1);
	if (!buffer) fclose(buff),fputs("memory allocation failed\n",stderr),exit(1);

	int xxx;
	if(buff)
	xxx =fread(buffer, lSize,1,buff);
else
	buffer[0]='\0';
	

	unsigned char hash[MD5_DIGEST_LENGTH];	

	MD5((const unsigned char*)buffer, sizeof(buffer) - 1, hash);

	print_log(logfile,UID,realpath(path,NULL), timeinfo,access_type,action,hash);
	


	return original_fopen_ret;
}


size_t 
fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{

	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);

	
	FILE *(*original_fopen)(const char*, const char*);
	original_fopen = dlsym(RTLD_NEXT,"fopen");

	FILE *logfile = original_fopen("./access_control_logfile.txt","a");
	if (logfile == NULL){perror("error opening file.");}

	//UID
	int UID = getuid();

	//TIME & DATE

	time_t rawtime;
	struct tm * timeinfo;

	time(&rawtime);
	timeinfo=localtime(&rawtime);

	/*ACTION DENIED */
	fflush(stream);
	int fd = fileno(stream);


	char proclnk[0xFFF];
	char filename[0xFFF];
	int MAXSIZE =0xFFF;
	
	sprintf(proclnk, "/proc/self/fd/%d", fd);
	ssize_t r = readlink(proclnk,filename,MAXSIZE);
	 if (r < 0)
     {
		printf("failed to readlink\n");
		exit(1);
    }
    filename[r] = '\0';

	FILE *fwrite_text = original_fopen(filename,"r+");
	if (!fwrite_text){printf("den anoikse to file gia na dw to content gia hash\n");}

	long lSize; char *buffer;
	fseek(fwrite_text,0L,SEEK_END);
	lSize = ftell(fwrite_text);
	rewind(fwrite_text);


	buffer = calloc(1,lSize+1);
	if (!buffer) fclose(fwrite_text),fputs("memory allocation failed\n",stderr),exit(1);

	
	fread(buffer, lSize,1,fwrite_text);
	unsigned char hash[MD5_DIGEST_LENGTH];	

	MD5((const unsigned char*)buffer, sizeof(buffer) - 1, hash);
	

	ssize_t(*original_write)(int, const void*, size_t);
	original_write = dlsym(RTLD_NEXT,"write");
	int action = 0;
	char TEST[] = "";
	if(original_write(fd,TEST,0) != 0){action = 1;}

	print_log(logfile,UID,filename, timeinfo,2,action,hash);




	return original_fwrite_ret;
}

FILE *
fopen64(const char *path, const char *mode) 
{

	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	

	int access_type;
	struct stat checker;
    int fex = stat(path,&checker);
    if(fex != 0){
        access_type=0;
    }
    else {
        access_type=1;
    }


	original_fopen = dlsym(RTLD_NEXT, "fopen64");
	original_fopen_ret = (*original_fopen)(path, mode);
	FILE *logfile = original_fopen("./access_control_logfile.txt","a");
	
	if (logfile ==NULL){perror("No Path found,Error opening file.");}


	//UID
	int UID = getuid();

	//TIME & DATE

	time_t rawtime;
	struct tm * timeinfo;

	time(&rawtime);
	timeinfo=localtime(&rawtime);

	/*ACTION DENIED */
	int action = 0;
	FILE *buff = original_fopen(path,mode);
	if (!buff){action = 1; printf("ACTION DENIED\n");}
	
	/*HASH VALUE*/
	long lSize; char *buffer;
	if(buff){
	fseek(buff, 0L,SEEK_END);
	lSize = ftell(buff);
	rewind(buff);
}

	
	buffer = calloc(1,lSize+1);
	if (!buffer) fclose(buff),fputs("memory allocation failed\n",stderr),exit(1);

	int xxx;
	if(buff)
	xxx =fread(buffer, lSize,1,buff);
else
	buffer[0]='\0';
	

	unsigned char hash[MD5_DIGEST_LENGTH];	

	MD5((const unsigned char*)buffer, sizeof(buffer) - 1, hash);

	print_log(logfile,UID,realpath(path,NULL), timeinfo,access_type,action,hash);
	


	return original_fopen_ret;
}


void print_log(FILE *logfile,int uid, const char* path,struct tm* timeinfo, int open, int action_denied, unsigned char* hash ){
	fprintf(logfile,"%d\t%s\t%d-%d-%d\t%d:%d:%d\t%d\t%d\t",uid,path,1900+timeinfo->tm_year,timeinfo->tm_mon,timeinfo->tm_mday,timeinfo->tm_hour,
		   timeinfo->tm_min,timeinfo->tm_sec,open,action_denied);
	
	size_t i;
	for (i = 0; i < 16; i++) {
		fprintf(logfile,"%02x", hash[i]);
	}
	fprintf(logfile,"\n");
}
