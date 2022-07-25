#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>


int main(int argc, char *argv[]) 
{
	//time_t current_time;
	 //current_time = time(NULL);
	
	int i;
	size_t bytes;
	FILE *file;
	int t =atoi(argv[2]);
	
	char directory[150];
	strcpy(directory,argv[1]);
	
	//int t = 5;
	//printf("%d",t);
	char filenames[t][150];
	char str[12];
	char file1[] = "file";
	char snum[150];
   

	for (i = 0; i < t ; i++){
		//char file1[] = "/file";
		sprintf(snum, "/file%d.txt", i);
		strcat(directory,snum);
		strcpy(snum,directory);
		//strcat(file1,snum);
		//strcat(snum,".txt");
		strcpy(filenames[i],snum);	
		printf("%s\n",filenames[i]);
		strcpy(directory,argv[1]);								
	}

	/* example source code */
 
	for (i = 0; i < t; i++) {

		file = fopen(filenames[i], "w+");	
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}

	}
	
	/*file = fopen("file_0","a");
fwrite(filenames[0], strlen(filenames[0]), 1, file);
	
	
	
	for (i = 0; i < 10; i++) {
	 char mode[] = "0000";
	 int x;
   	 x = strtol(mode, 0, 8);
    	chmod (filenames[i],x);
	 
	file = fopen(filenames[i], "a");
	}
	
	

***********/

}
