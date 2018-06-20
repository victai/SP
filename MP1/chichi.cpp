#include <bits/stdc++.h>
using namespace std;
char mystring[128] = {};
void stringclear(char mystring[128])
{
	for(int i = 0; i < 128; i++)
		mystring[i] = '\0';
	return;
}
unsigned int max(unsigned int a, unsigned int b){
	if(a > b)
		return a;
	else 
		return b;
}
int lcs(unsigned int clientarr[], int clientl, unsigned int serverarr[], int serverl){
	unsigned int array[clientl+1][serverl+1];
	for(int i = 0; i <= clientl+1; i++)	printf("%u ", clientarr[i]);
		puts("");
	for(int i = 0; i <= serverl+1; i++)	printf("%u ", serverarr[i]);
		puts("");
	for(int i = 0; i <= clientl; i++)
		array[i][0] = 0;
	for(int i = 0; i <= serverl; i++)
		array[0][i] = 0;
	for(int i = 1; i <= clientl; i++)
		for(int j = 1; j <= serverl; j++){
			if(clientarr[i] == serverarr[j])
				array[i][j] = array[i-1][j-1] + 1;
			else
				array[i][j] = max(array[i-1][j], array[i][j-1]);
		}
	return array[clientl][serverl];
}
int main()
{
	unsigned int ret;
	unsigned int clientarr[1024], serverarr[1024]; 
	int cnt=0, addcnt=0, delcnt=0, i=1, j=1, k=0;
	int clientl=0, serverl=0, same, flag = 0;
	FILE *fp1, *fp2;
	char cmd[10000];
	char upd[8] = "update", ex[8] = "exit";
	char c;
	string space = " ";
	string p;
	string del = "rm -rf";
	string client = "./client/";
	string server = "./server/";
	string copy = "cp ";
	while(scanf("%s", cmd) != EOF){
		if(strcmp(upd, cmd) == 0){
			cin >> p;
			//cout << client+p << endl;
			//printf("|%s|\n", (client+p).data());
			fp1 = fopen((client+p).data(), "r");
			fp2 = fopen((server+p).data(), "r");
			//if(fp1 == NULL) putchar('x');
			if(fp1 == NULL && fp2 == NULL)
			 	continue;
			if(fp2 == NULL){                                      //1build server
				//if(fp1 != NULL) cout << client+p << endl;	
				while(fgets(mystring, 128, fp1) != NULL){
					if(mystring[strlen(mystring)-1] == '\n')
					 	cnt++;
					stringclear(mystring);
				}
				addcnt = cnt;
 				system((copy+client+p+space+server).data());
				fclose(fp1);
			}
			else if(fp1 == NULL){                                  //2kill server
				while(fgets(mystring, 128, fp2) != NULL){
					if(mystring[strlen(mystring)-1] == '\n')
							cnt++;
					stringclear(mystring);
				}
				delcnt = cnt;
				system((del+space+server+p).data());
				fclose(fp2);
			}
			else{
				while(fgets(mystring, 128, fp1)!= NULL){
					while(mystring[k] != '\n' && k < 128){
						ret = ret*131 + mystring[k];
						k++;
					}
					if(mystring[strlen(mystring)-1] == '\n'){
						clientl++;
						clientarr[i++] = ret;
						ret = 0;
					}
					k = 0;
					stringclear(mystring);
				}
				while(fgets(mystring, 128, fp2)!= NULL){
					while(mystring[k] != '\n' && k < 128){
						ret = ret*131 + mystring[k];
						k++;
					}
					if(mystring[strlen(mystring)-1] == '\n'){
						serverl++;
						serverarr[j++] = ret;
						ret = 0;
					}
					k = 0;
					stringclear(mystring);
				}
				same = lcs(clientarr, clientl, serverarr, serverl);
				// system((copy+client+p+space+server).data());
				// printf("%d\n", same);
				addcnt = clientl - same;
				delcnt = serverl - same;
			}
		}
		else if(strcmp(ex, cmd) == 0)
			break;
		else
		 	continue;
		printf("%d %d\n", addcnt, delcnt);
		fflush(stdout);
		for(int k = 1; k < 1024; k++){
			clientarr[k] = '\0';
			serverarr[k] = '\0';
		}
		clientl = 0;
		serverl = 0;
		i = 1;
		j = 1;
		cnt = 0;
		addcnt = 0;
		delcnt = 0;
	}
	return 0;
}