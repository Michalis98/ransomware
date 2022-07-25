#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>
struct entry {

	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	time_t date; /* file access date */
	time_t time; /* file access time */

	char *file; /* filename (string) */
	char *fingerprint; /* file fingerprint */

	

};

long int get_seconds(int year,int month,int day, int hour, int min, int sec){
		struct tm t;
		time_t t_of_day;
		t.tm_year = year;
		t.tm_mon = month;
		t.tm_mday = day;
		t.tm_hour =hour;
		t.tm_min = min;
		t.tm_sec = sec;
		t.tm_isdst = 0;			
		t_of_day = mktime(&t);
		return (long) t_of_day;
	}


void
usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "-v <number of files> Prints the total number of files created in the last 20 minutes "
		   "-e Prints all the files that were encrypted by the ransomware"
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}

char* replaceWord(const char* s, const char* oldW, 
                  const char* newW) 
{ 
    char* result; 
    int i, cnt = 0; 
    int newWlen = strlen(newW); 
    int oldWlen = strlen(oldW); 
  
    // Counting the number of times old word 
    // occur in the string 
    for (i = 0; s[i] != '\0'; i++) { 
        if (strstr(&s[i], oldW) == &s[i]) { 
            cnt++; 
  
            // Jumping to index after the old word. 
            i += oldWlen - 1; 
        } 
    } 
  
    // Making new string of enough length 
    result = (char*)malloc(i + cnt * (newWlen - oldWlen) + 1); 
  
    i = 0; 
    while (*s) { 
        // compare the substring with the result 
        if (strstr(s, oldW) == s) { 
            strcpy(&result[i], newW); 
            i += newWlen; 
            s += oldWlen; 
        } 
        else
            result[i++] = *s++; 
    } 
  
    result[i] = '\0'; 
    return result; 
} 

void files_created(FILE *log,int numb){
	int files_create=0;
	const char *line_array[7]; 
	//File *fd = log;
	ssize_t read;
	char *line = NULL;
	size_t len=0;
	FILE *fd = log;
	if (fd ==NULL)
		exit(EXIT_FAILURE);
	
	FILE *open_text = fopen("./access_control_logfile.txt","r");
	long lSize; char *buffer;
	fseek(open_text,0L,SEEK_END);
	lSize = ftell(open_text);
	rewind(open_text);
	buffer = calloc(1,lSize+1);
	if (!buffer) fclose(open_text),fputs("memory allocation failed\n",stderr),exit(1);
	/*copy file content into buffer*/
	fread(buffer, lSize,1,open_text);

	while((read = getline(&line, &len,fd)) != -1){

			
			char *tb = "\t";
			char *token;
			token = strtok(line,tb);
			int i =0;
			while(i<7){
				line_array[i] = token;
				token = strtok(NULL,tb);
				i++;
			}

			//kitame an to 5 pedio einai 0 diladi exoume file creation
			if((strcmp(line_array[4],"0")==0)){
			time_t my_time;
			struct tm * timeinfo; 
			time (&my_time);
			timeinfo = localtime (&my_time);
			//rintf("hour->%d\n",timeinfo->tm_hour);
			//printf("minutes->%d\n",timeinfo->tm_min);
			int now_year=timeinfo->tm_year+1900;
			int now_month=timeinfo->tm_mon+1;
			int now_day=timeinfo->tm_mday;
			int now_hour=timeinfo->tm_hour;
			int now_minutes=timeinfo->tm_min;
			int now_sec=timeinfo->tm_sec;
			int year = split_string_date(line_array[2],1);
			//printf("%d YEAR\n", year );
			int month = split_string_date(line_array[2],2);
			//printf("%d month\n", month );
			int day = split_string_date(line_array[2],3);
			//printf("%d day\n", day );
			int hour = split_string_time(line_array[3],1);
			int min = split_string_time(line_array[3],2);
			int sec = split_string_time(line_array[3],3);
			int current = get_seconds(now_year,now_month,now_day,now_hour,now_minutes,now_sec);
			int before = get_seconds(year,month,day,hour,min,sec);
			//printf("The current is : %d\n", current);
			//printf("The before is %d\n", before);
			if(current<=before+1200)
				files_create++;
			}

			

	}
	//printf("%d\n", files_create );
	int xd = files_create + files_create/2 ;
	printf("Files created in last 20 minutes :%d\n", xd );
	if (xd > numb)
		printf("FILES CREATED IS MORE THAN THE INPUT FILES");
	else
		printf("FILE CREATED IS LESS THAN THE INPUT FILES");

	return;

}

void files_encrypted(FILE *log){
	int files_encrypt=0;
	const char *line_array[7]; 
	//File *fd = log;
	ssize_t read;
	char *line = NULL;
	size_t len=0;
	FILE *fd = log;
	if (fd ==NULL)
		exit(EXIT_FAILURE);
	
	FILE *open_text = fopen("./access_control_logfile.txt","r");
	long lSize; char *buffer;
	fseek(open_text,0L,SEEK_END);
	lSize = ftell(open_text);
	rewind(open_text);
	buffer = calloc(1,lSize+1);
	if (!buffer) fclose(open_text),fputs("memory allocation failed\n",stderr),exit(1);
	/*copy file content into buffer*/
	fread(buffer, lSize,1,open_text);

	while((read = getline(&line, &len,fd)) != -1){

			
			char *tb = "\t";
			char *token;
			token = strtok(line,tb);
			int i =0;
			while(i<7){
				line_array[i] = token;
				token = strtok(NULL,tb);
				i++;
			}

			//kitame an to 5 pedio einai 0 diladi exoume file creation
			if((strcmp(line_array[4],"0")==0)){
			char *word = ".encrypt";
			if(strstr(line_array[1],word)!=NULL){
			files_encrypt++;
			char c[] = ".encrypt"; 
    		char d[] = ".txt"; 
  			char str[150]; 
   		 	char* result = NULL; 
   		 	strcpy(str,line_array[1]);
   		 	result = replaceWord(str, c, d); 
			printf("File encrypted :%s to %s \n", result,line_array[1]);
		}
			}

			

	}
	//printf("%d\n", files_create );
	
	printf("Total Files Encrypted :%d\n", files_encrypt );

	return;

}



void 
list_unauthorized_accesses(FILE *log)
{
	const char *line_array[7]; 
	char *line = NULL;
	size_t len=0;
	ssize_t read;
	int i = 0;
	int denied_counter = 0;
	FILE *fd = log;
	if (fd ==NULL)
		exit(EXIT_FAILURE);

	FILE *open_text = fopen("./access_control_logfile.txt","r");
	long lSize; 
	char *buffer;
	fseek(open_text,0L,SEEK_END);
	lSize = ftell(open_text);
	rewind(open_text);
	
	buffer = calloc(1,lSize+1);
	if (!buffer) fclose(open_text),fputs("memory allocation failed\n",stderr),exit(1);
	
	fread(buffer, lSize,1,open_text);
	

	while((read = getline(&line, &len,fd)) != -1){

			denied_counter=0;
			char *tb = "\t";
			char *token;
			token = strtok(line,tb);
			i =0;
			while(i<7){
				line_array[i] = token;
				token = strtok(NULL,tb);
				i++;
			}
			/*1st unsuccessfull access*/
			if((strcmp(line_array[5],"1")==0)){
				denied_counter++;
	
				char *line2 = NULL;
				size_t len2=0;
				ssize_t read2;
				const char *line_array2[7];
				/*if UID another 6 unsuccessfull accesses*/
				while((read2 = getline(&line2, &len2,fd)) != -1){
					char *tb2 = "\t";
					char *token2;
					token2 = strtok(line2,tb2);
					int k =0;
					while(k<7){
						line_array2[k] = token2;
						token2 = strtok(NULL,tb2);
						k++;
					}
					if((strcmp(line_array[0],line_array2[0])==0) && (strcmp(line_array2[5],"1")==0) && strcmp(line_array[1],line_array2[1])!=0){
						
						denied_counter++;
					}
					if(denied_counter == 7){
						printf("User %s tried unsuccesfully to open 7 different files\n",line_array[0]);
						
						break;
					}
				}
			}
		}
		



	return;

}


void
list_file_modifications(FILE *log, char *file_to_scan)
{

	const char *given_path = file_to_scan;	
	const char *line_array[7]; //pinakas me string ka8e mia apo tis 7 stiles tou log
	char *line = NULL;
	size_t len=0;
	char *line1 = NULL;
	size_t len1=0;
	ssize_t read;
	ssize_t read2;
	char **users = malloc (sizeof(char*)); 
	int changes[1000];
	int i = 0;
	int val;
	int flag=0;
	int denied_counter = 0;
	FILE *fd = log;
	FILE *fd2 = log;
	int j=0;
	char user[20];
	if (fd ==NULL)
		exit(EXIT_FAILURE);
	
	char line_hashes[MD5_DIGEST_LENGTH];
	const char *prev_hash =NULL;

	

		
		

	
	while((read = getline(&line, &len,fd)) != -1){
		char *tb = "\t";
		char *token;
		token = strtok(line,tb);
		i =0;
			while(i<7){
				line_array[i] = token;
				token = strtok(NULL,tb);
				i++;
			}
			if((strcmp(line_array[1], given_path)==0) && (strcmp(line_array[5],"0")==0)){
				if(prev_hash!=NULL){
					if((strcmp(prev_hash,line_array[6])!=0)){
				
						j++;
					}
				}
			prev_hash = line_array[6];
			char *line2 = NULL;
			size_t len2=0;
			ssize_t read2;
			const char *line_array2[7];
			

			while((read2 = getline(&line2, &len2,fd)) != -1 ) {
				int jj=1;
				
				char *tb2 = "\t";
				char *token2;

				token2 = strtok(line2,tb2);
				int k =0;
				while(k<7){
						line_array2[k] = token2;
						token2 = strtok(NULL,tb2);
						k++;
					}
				if((strcmp(line_array2[1], given_path)==0) && (strcmp(prev_hash,line_array2[6])!=0) && (strcmp(line_array2[5],"0")==0)){
				
					if(strcmp(line_array2[5],"0")==0){

										j++;

					}
					
					prev_hash =line_array2[6];
					break;
					}
					
				}
				strcpy(user,line_array2[0]);

			}
			
				

		}

	printf("The user: %s Modified %d times \n",user,j);
	return;

}

int split_string_date(const char* date,int number){
    	const char * start = date;
    	char * end;
    	while ( ( end = strchr( start, '-' ) ) != NULL )
    	{
			if (number == 1)
				return atoi(start);
    	    start = end + 1;
			if (number == 2)
				return atoi(start);
    	}
    	if(number==3)
			return atoi(start);
	}

	/*split time string with ':' */
	int split_string_time(const char* date,int number){
    	const char * start = date;
    	char * end;
    	while ( ( end = strchr( start, ':' ) ) != NULL )
    	{
			if (number == 1)
				return atoi(start);
    	    start = end + 1;
			if (number == 2)
				return atoi(start);
    	}
    	if(number==3)
			return atoi(start);
	}

	
	


int 
main(int argc, char *argv[])
{

	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("./access_control_logfile.txt", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "i:v:emh:")) != -1) {

		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		case 'v':
			files_created(log,atoi(optarg));
			break;
		case 'e':
		    files_encrypted(log);
		     break;
		default:
			usage();
		}

	}


	


	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}
