#include <mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/md5.h>
#include<unistd.h>
#define STRING_SIZE 50
# define sql1 "select * from login2 where username=? and password=?"
#define KCYN  "\x1B[36m"
#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
 // Sensitive data exposure (start)
struct userinfo_struct {
    char user[128];
    char salt[128];
    char crypt_passwd[128];
};
int parse_shadowline(char *shadow_line, struct userinfo_struct *parse_result) {
    char *p, *q;

    if (shadow_line == NULL) {
        printf("Error shadow_line input!\n");
        return -1;
    }
    // Extract each line in the shadow file with the proper
    // userinfo_struct format
    p = shadow_line;
    q = strchr(p, ':');

    if (!q) {
        printf("0x001, Not userinfo format\n");
        return -1;
    }
    // Extract the username from the line of shadow file
    strncpy(parse_result -> user, p, q - p);
    parse_result -> user[q - p] = '\0';
    p = q + 1;

    if (strncmp(p, "$1$", 3) == 0) {
        printf("Password encrypted by md5 algorithm!\n");
    }
    else if (strncmp(p, "$5$", 3) == 0) {
        printf("Password encrypted by SHA-256 algorithm!\n");
    }
    else if (strncmp(p, "$6$", 3) == 0) {
        printf("Password encrypted by SHA-512 algorithm!\n");
    }
    else {
        printf("0x002, Not userinfo format!\n");
        return -1;
    }

    q = strchr(p + 3, '$');
    if (!q) {
        printf("0x003, Not userinfo format!\n");
        return -1;
    }
    strncpy(parse_result -> salt, p, q - p + 1);
    
    parse_result -> salt[q - p + 1] = '\0';
    p = q + 1;
    q = strchr(p, ':');
    if (!q) {
        printf("0x004, Not userinfo format!\n");
        return -1;
    }
    
    strncpy(parse_result -> crypt_passwd, p, q - p);
    parse_result -> crypt_passwd[q - p] = '\0';
    return 0;
}
// Shadow Part (End)

//hashing Part Start
void MD5_HashString(char *src, char *dest){
  MD5_CTX ctx;
  unsigned char digest[16];
  int i;
  MD5_Init(&ctx);
  MD5_Update(&ctx, src, strlen(src));
  MD5_Final(digest,&ctx);
  for (i = 0; i < 16; i++)  {
    sprintf(&dest[i*2],"%02x", digest[i]);
  }
}
void trim(char *str){
  int len=strlen(str);
  if(str[len-1] == '\n'){
    str[len-1] = '\0';
  }
}
int file_nlines(FILE *f){
  size_t nread = 0;
  char *buffer;
  int nlines = 0;

  while (getline(&buffer, &nread, f) != -1) {
    nlines++;
  }
  return nlines;
}  

// Sensitive data exposure (end)

void design(int a)
{

if (a==0)
{
		printf("	+---------------------------------------------------+\n");
		printf("	|                                                   |\n"); 
		printf("	|                                                   |\n");
		printf("	|          Welcome to the attack simulator          |\n");
		printf("	|                                                   |\n");
		printf("	|                                                   |\n");
		printf("	|     INDEX                         INPUT           |\n");
		printf("	|                                                   |\n");
		printf("	| 1) Buffer Overflow                  1             |\n");
		printf("	|                                                   |\n");
		printf("	| 2) Sensitive data exposure          2             |\n");
		printf("	|                                                   |\n");
		printf("	| 3) SQL Injections                   3             |\n");
		printf("	|                                                   |\n");
		printf("	| 4) exit                             4             |\n");
		printf("	|                                                   |\n");
		printf("	|                                                   |\n");
		printf("	| #above mentioned attacks are just replica of      |\n");
		printf("	|  actual attack and prevention                     |\n");
		printf("	|                                                   |\n");
		printf("	+---------------------------------------------------+\n");

}

else if (a==1)
{
		printf("	+---------------------------------------------------+\n");
		printf("	|                                                   |\n"); 
		printf("	|                                                   |\n");
		printf("	|                 Buffer Overflow                   |\n");
		printf("	|                                                   |\n");
		printf("	| Where when program writing data to buffer         |\n");
		printf("	| overruns and fill the adjacent memory.            |\n");
		printf("	|                                                   |\n");
		printf("	| Modules                           Input           |\n");
		printf("	|                                                   |\n");
		printf("	| a) Attack                           1             |\n");
		printf("	|                                                   |\n");
		printf("	| b) Prevention                       2             |\n");
		printf("	|                                                   |\n");
		printf("	| c) exit                             3             |\n");
		printf("	|                                                   |\n");
		printf("	|                                                   |\n");
		printf("	| #above mentioned attacks are just replica of      |\n");
		printf("	|  actual attack and prevention                     |\n");
		printf("	|                                                   |\n");
		printf("	+---------------------------------------------------+\n");

}
 
else if (a==2)
{
		printf("	+---------------------------------------------------+\n");
		printf("	|                                                   |\n"); 
		printf("	|                                                   |\n");
		printf("	|            Sensitive data exposure                |\n");
		printf("	|                                                   |\n");
		printf("	| Exposure of unauthorized information in the form  |\n");
		printf("	| plain text to all users.                          |\n");
		printf("	|                                                   |\n");
		printf("	| Modules                           Input           |\n");
		printf("	|                                                   |\n");
		printf("	| a) Simulation                       a             |\n");
		printf("	|                                                   |\n");
		printf("	| b) Exit                             b             |\n");
		printf("	|                                                   |\n");
		printf("	|                                                   |\n");
		printf("	| #above mentioned attacks are just replica of      |\n");
		printf("	|  actual attack and prevention                     |\n");
		printf("	|                                                   |\n");
		printf("	+---------------------------------------------------+\n");
}

else if (a==3)
{
		printf("	+---------------------------------------------------+\n");
		printf("	|                                                   |\n"); 
		printf("	|                                                   |\n");
		printf("	|                 SQL injection                     |\n");
		printf("	|                                                   |\n");
		printf("	| Where a mallicious SQL query is inserted instead  |\n");
		printf("	| of valid input to get into the database.          |\n");
		printf("	|                                                   |\n");
		printf("	| Modules                           Input           |\n");
		printf("	|                                                   |\n");
		printf("	| 1) Attack                           1             |\n");
		printf("	|                                                   |\n");
		printf("	| 2) Prevention                       2             |\n");
		printf("	|                                                   |\n");
		printf("	| 3) exit                             3             |\n");
		printf("	|                                                   |\n");
		printf("	|                                                   |\n");
		printf("	| #above mentioned attacks are just replica of      |\n");
		printf("	|  actual attack and prevention                     |\n");
		printf("	|                                                   |\n");
		printf("	+---------------------------------------------------+\n");

}

else
{
printf("\n");
}
}
main()
{
	
//mysql part
MYSQL *conn;
MYSQL_RES *res;
MYSQL_ROW row;
char *server = "localhost";
char *user = "root";
char *password = "123456";
char *database = "student";
conn = mysql_init(NULL);
if (!mysql_real_connect(conn, server, user, password, database, 0, NULL, 0)) 
{
	fprintf(stderr, "%s\n", mysql_error(conn));
	exit(1);
} // mysql part end

//sde start
  int i;
  int verbose;
  char *dictionary, *shadow,*hash;
  char shadow_line[256];
  int BUF_SIZE = 255;
  char hash_md5[32];
  char *dict_name[15];
  char *shadow_name[15];
  char *hash_name[25];  
  char hash_concat[256];
  verbose=0;  //-v to see process ongoing

  struct userinfo_struct userinfo;
  	
  dictionary = malloc(1*sizeof(char));
  hash = malloc(1*sizeof(char));
  shadow = malloc(1*sizeof(char));
  

//sde end
int a=0,b,input_check;
char input;
while(a!=4)
{
	design(0);
	scanf("%d",&a);
	switch(a)
	{
	case 1 : //buffer overflow part
	{		
	while(input_check!=3)
	{
	design(1);				
	scanf("%d",&input_check);
	if (input_check==1)				
	{
		char sql[1000];
		sprintf(sql,"select * from login2");
		char buff[10];
		int pass = 0;
		printf("\n Enter the password : ");
		scanf("%s",buff);
		fflush(stdin);
		if(strcmp(buff, "csfbatch"))
		{
			printf ("\n Wrong Password \n");
		}
		else
		{
			printf ("\n Correct Password \n");
			pass = 1;
		}
		if(pass)
		{
			printf ("\n Root privileges given to the user \n");
			if (mysql_query(conn, sql)) {
			fprintf(stderr, "%s\n", mysql_error(conn));
			exit(1);
			res = mysql_use_result(conn);
			while ((row = mysql_fetch_row(res)) != NULL)
		{ 
			printf("%s \n", row[0]);
			

		}
		}
		continue;	    				
		}
				
				else if(input_check==2)
	                                {
					char sql[100];
    					sprintf(sql,"select * from login2");
    					char buff[10];
    					int pass = 0;
					printf("\n Enter the password : ");
    					scanf("%s",buff);
					fflush(stdin);
					if(strncmp(buff, "csfbatch",8))
    					{
						printf ("\n Wrong Password \n");
    					}
    					else
    					{
						printf ("\n Correct Password \n");
						pass = 1;
    					}
					if(pass)
    					{
						printf ("\n Root privileges given to the user \n");
						if (mysql_query(conn, sql)) {
      						fprintf(stderr, "%s\n", mysql_error(conn));
      						exit(1);
						res = mysql_use_result(conn);
   						while ((row = mysql_fetch_row(res)) != NULL)
     					{ 
						printf("%s \n", row[0]);
						

   					}}
					mysql_close(conn);
				continue;
				}
				else
				{ printf("\n");
				continue;
				}
			}
			
			}
}

		break;

		case 2 : //sensitive data exposure
			{
			        input="";
				while(input!='b')
				{
				design(2);
				scanf(" %c",&input);
				if(input=='a')
				{	
				  printf("\nEnter dictionary file to use for Dictionary Attack : ");
				  scanf("%s",dict_name);
				  printf("\n");
				  dictionary = realloc(dictionary, strlen(dict_name));
				  strcpy(dictionary, dict_name);
				  
				  
				  printf("\nEnter Shadow file name to crack it using dictionary attack : ");
				  scanf("%s",shadow_name); 
				  shadow = realloc(shadow, strlen(shadow_name));
				  strcpy(shadow, shadow_name);
				  printf("\n");
				  
				  printf("\n Enter (0/1) to see ongoing process : ");
				  scanf("%d",&verbose);

				  printf("Dictionary: %s\n", dictionary);
				  printf("Shadow: %s\n", shadow);
				  printf("\n");
				  
				  FILE *dictionary_file;
				  FILE *shadow_file;
				  
				  dictionary_file = fopen(dictionary,"r");
				  if(dictionary_file==NULL){
				    fprintf(stderr, "Can't open file \"%s\"!\n", dictionary);
				      exit(1);
							   }
				  
				  shadow_file = fopen(shadow,"r");
				  if(shadow_file==NULL){
				    fprintf(stderr, "Can't open file \"%s\"!\n", shadow);
				      exit(1);
						       }
				   
				  while ((fscanf(shadow_file, "%s", shadow_line)) != EOF) {
					if (parse_shadowline(shadow_line, &userinfo) != 0) {
					    continue;
					}
					
					printf("\nAnalizing file...\n");
				   	int number_of_words = file_nlines(dictionary_file);

				  	char word[BUF_SIZE], word_cpy[BUF_SIZE], word_md5[32];

				  	if(fseek(dictionary_file, 0, SEEK_SET)==-1){
				    	break;
				  	}

				  	int j, found=0;
				  	double begin = clock();
				  	// Assign one word for each thread
				  	printf("\nSearching...\n");
				  	for(j=0;j<number_of_words;j++){
				    	if(fgets(word,BUF_SIZE,dictionary_file)!= NULL){
				      	if(found){
						fclose(dictionary_file);
				       		 break;
				      		}
					strcpy(word_cpy,word);
					trim(word_cpy);

				    if(verbose){
					printf("Thread: %d - Trying: %s\n", omp_get_thread_num(), word_cpy);
				      }

				      MD5_HashString(word_cpy,word_md5);
				      sprintf(hash_concat,"%s%s",userinfo.salt, userinfo.crypt_passwd); 
				      
				      hash = realloc(hash, strlen(hash_concat));
				      
				      strcpy(hash,hash_concat);
				 	//hash="06a943c59f33a34bb5924aaf72cd2995";      
					hash[32]='\0';      
					if(strcmp("8621ffdbc5698829397d97767ac13db3", word_md5)==0){
					if(verbose){
					  printf("Thread: %d - Found: %s\n", omp_get_thread_num(), word_cpy);
					}
					
					else{
					  printf("Password Found: %s\n\n", word_cpy);
				   	  double time_spent = (double)(clock() - begin) / CLOCKS_PER_SEC;
					  printf("Search Execution time: %f seconds\n\n", time_spent);
					}
					found=1;
				      }

				    }
				  }
				  fclose(dictionary_file);
				  fclose(shadow_file);
				  if(!found){
				    printf("Password not found.\n\n");
				    double time_spent = (double)(clock() - begin) / CLOCKS_PER_SEC;
				    printf("Search Execution time: %f seconds\n\n", time_spent);
				  	   }
					
										
					}
					continue;					
					}
					else
					{ 
						printf("\n");
					continue;
					}
		}
		}			
		break;
		case 3 :   //sql injection
				b=0;
				while(b!=3)
				{
				design(3);
				scanf("%d",&b);
				switch(b)
				{
					case 1 :
                                        { //Sql injection (attack) start
					  MYSQL *conn;
			   MYSQL_RES *res;
			   MYSQL_ROW row;

			   char *server = "localhost";
			   char *user = "root";
			   char *password = "123456"; /* set me first */
			   char *database = "student";

			   conn = mysql_init(NULL);

			   /* Connect to database */
			   if (!mysql_real_connect(conn, server,
				 user, password, database, 0, NULL, 0)) {
			      fprintf(stderr, "%s\n", mysql_error(conn));
			      break;
			   }

			char username[20];
			char *password1[20];
			printf("Enter username : ");
			scanf("%s",username);
			fflush(stdin);
			printf("Enter password : ");
			gets(password1);



			char sql[1000];

			sprintf(sql, "select * from login2 where username='%s' and password='%s'", username,password1);
			 
			printf("Following Query will be executed: \n%s%s\n",KYEL,sql);

			 int trigger = 500; // ms
			     int numDots = 7;
			     char prompt[] = "Submitting query";
			int j=0;
			 
			    while (j<4) {
				// Return and clear with spaces, then return and print prompt.
				printf("\r%*s\r%s%s", strlen(prompt) - 1 + numDots, "", KGRN,prompt);
				fflush(stdout);

				// Print numDots number of dots, one every trigger milliseconds.
				for (int i = 0; i < numDots; i++) {
				    usleep(trigger * 1000);
				    fputc('.', stdout);
				    fflush(stdout);
			j++;
				}
			    }
			   printf("\n");

			j=0;
			char prompt1[] = "Fetching info";
			 while (j<4) {
				// Return and clear with spaces, then return and print prompt.
				printf("\r%*s\r%s%s", strlen(prompt1) - 1 + numDots, "", KCYN,prompt1);
				fflush(stdout);

				// Print numDots number of dots, one every trigger milliseconds.
				for (int i = 0; i < numDots; i++) {
				    usleep(trigger * 500);
				    fputc('.', stdout);
				    fflush(stdout);
			j++;
				}
			    }

			   /* send SQL query */
			   if (mysql_query(conn, sql)) {
			      fprintf(stderr, "%s\n", mysql_error(conn));
			      exit(1);
			   }

			   res = mysql_use_result(conn);
			  
			   printf("\n");
			   /* output table name */
			   

			printf("%s",KRED);
			   
			   while ((row = mysql_fetch_row(res)) != NULL)

			     {

			printf(" Username:%s\n Password:%s\n Name:%s\n Gender:%s\n Email:%s\n \n", row[0], row[1], row[2], row[3],row[4]);

			}

			if(strcmp(username,password1)!=0)
			printf("\nInvalid Credentials! Please try again.\n");

			   /* close connection */
			   mysql_free_result(res);
			   mysql_close(conn);
			} //sql injection (attack) finish


					break;
					case 2 : 
					{   //sql injection (prevent) start

					MYSQL *conn;
					   MYSQL_RES *res;
					   MYSQL_ROW row;
					   MYSQL_STMT *stmt;
					int a=3;
					int param_count;
					char str_data[STRING_SIZE],str_data1[STRING_SIZE];
					unsigned long str_length,str_length1;


					   char *server = "localhost";
					   char *user = "root";
					   char *password = "123456"; /* set me first */
					   char *database ="student";
					conn = mysql_init(NULL);
					  
					char username[20];
					char *password1;
					printf("Enter username : ");
					scanf("%s",username);
					fflush(stdin);
					password1=getpass("Enter password : ");

					   /* Connect to database */
					   if (!mysql_real_connect(conn, server,
						 user, password, database,0, NULL, 0)) {
					      fprintf(stderr, "%s\n", mysql_error(conn));
					      exit(1);
					   }
					stmt=mysql_stmt_init(conn);
					mysql_stmt_prepare(stmt, sql1, strlen(sql1));


					str_length = strlen(username);


					str_length1 = strlen(password1);

					MYSQL_BIND bind[1];

					memset(bind, 0, sizeof(bind));

					/* STRING PARAM */
					bind[0].buffer_type= MYSQL_TYPE_STRING;
					bind[0].buffer= (char *) username;
					bind[0].buffer_length= str_length;
					bind[0].is_null= 0;
					bind[0].length= 0;// XXXXXXXXX as length is not used for mysql_stmt_bind_param I set it to NULL

					bind[1].buffer_type= MYSQL_TYPE_STRING;
					bind[1].buffer= (char *) password1;
					bind[1].buffer_length= str_length1;
					bind[1].is_null= 0;
					bind[1].length= 0;

					mysql_stmt_bind_param(stmt, bind);

					bind[0].length= &str_length; // XXXXXXXXXXX now set the length
					bind[1].length= &str_length1;

					if (mysql_stmt_execute(stmt))
					{
					  fprintf(stderr, " mysql_stmt_execute(), failed\n");
					  fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
					  exit(0);
					}

					MYSQL_BIND result[5]; 
					char username1[15];
					char passw[15];
					char name[15];
					char gender[15];
					char email[15];

					memset (result, 0, sizeof (result)); /* zero the structures */

					result[0].buffer= (void *) &username1;       
					result[0].buffer_type    = MYSQL_TYPE_STRING;  // Return data as string
					result[0].buffer_length  = 100;

					result[1].buffer= (void *) &passw;       
					result[1].buffer_type    = MYSQL_TYPE_STRING;  // Return data as string
					result[1].buffer_length  = 100;

					result[2].buffer= (void *) &name;       
					result[2].buffer_type    = MYSQL_TYPE_STRING;  // Return data as string
					result[2].buffer_length  = 100;

					result[3].buffer= (void *) &gender;       
					result[3].buffer_type    = MYSQL_TYPE_STRING;  // Return data as string
					result[3].buffer_length  = 100;

					result[4].buffer= (void *) &email;       
					result[4].buffer_type    = MYSQL_TYPE_STRING;  // Return data as string
					result[4].buffer_length  = 100;

					mysql_stmt_bind_result(stmt,result);

					int trigger = 500; // ms
					     int numDots = 7;
					     char prompt[] = "Submitting query";
					int j=0;
					 
					    while (j<4) {
						// Return and clear with spaces, then return and print prompt.
						printf("\r%*s\r%s%s", strlen(prompt) - 1 + numDots, "", KBLU,prompt);
						fflush(stdout);

						// Print numDots number of dots, one every trigger milliseconds.
						for (int i = 0; i < numDots; i++) {
						    usleep(trigger * 1000);
						    fputc('.', stdout);
						    fflush(stdout);
					j++;
						}
					    }
					   printf("\n");

					j=0;
					char prompt1[] = "Fetching info";
					 while (j<4) {
						// Return and clear with spaces, then return and print prompt.
						printf("\r%*s\r%s%s", strlen(prompt1) - 1 + numDots, "", KCYN,prompt1);
						fflush(stdout);

						// Print numDots number of dots, one every trigger milliseconds.
						for (int i = 0; i < numDots; i++) {
						    usleep(trigger * 500);
						    fputc('.', stdout);
						    fflush(stdout);
					j++;
						}
					    }



					while(!mysql_stmt_fetch(stmt))
					{
					 printf("\n%sName:%s\n", KGRN,username1);
					printf("Password:%s\n", passw);
					printf("Name:%s\n", name);
					printf("Gender:%s\n", gender);
					printf("Email:%s\n", email);
					   
					}

					if(strcmp(username,password1)!=0)
					printf("\n\nInvalid Credentials! Please try again.\n");

					printf("\n");

					 mysql_stmt_close(stmt);
					}  //sql injection (prevent) finish
					break;
					case 3 : printf("\n");
					break;
					default : 
			                    printf("\n");
				}
				}
		break;
		case 4:
					
			printf("");
					
		break;
		
	}}
	
}	


	
}
