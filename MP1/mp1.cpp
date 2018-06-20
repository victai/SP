#include <iostream>
#include <cstring>
#include <cstdlib>
#include <stdio.h>
#include <inttypes.h>
#include <algorithm>
using namespace std;

string Client = "client/";
string Server = "server/";
FILE *fp_C;
FILE *fp_S;
uint64_t arr_c[1001] = {0}, arr_s[1001] = {0};
int flag;

int LCS(int cnt_c, int cnt_s)
{
	int matrix[cnt_c][cnt_s];
	for(int i = 0; i < cnt_c; i++)
		for(int j = 0; j < cnt_s; j++)
			matrix[i][j] = 0;
	for(int i = 1; i < cnt_c; i++)
	{
		for(int j = 1; j < cnt_s; j++)
		{
			if(arr_c[i] == arr_s[j])
				matrix[i][j] = matrix[i-1][j-1] + 1;
			else	matrix[i][j] = max(matrix[i-1][j], matrix[i][j-1]);
		}
	}
	return matrix[cnt_c-1][cnt_s-1];
}

void Update(void)
{
	string Client = "client/";
	string Server = "server/";
	string filename;
	cin >> filename;
	Client += filename;
	Server += filename;
	string str;
	fp_C = fopen(Client.c_str(), "r");
	fp_S = fopen(Server.c_str(), "r");
	int line_C = 0, line_S = 0;
	if(fp_C == NULL && fp_S == NULL)
	{
		printf("0 0\n");
		return;
	}
	else if(fp_C == NULL)
	{	
		char c;
		c = fgetc(fp_S);
		while(!feof(fp_S))
		{
			if(c == '\n')	line_S++;
			c = fgetc(fp_S);
		}
		printf("0 %d\n", line_S);
		fflush(stdout);
		str = "rm -f " + Server;
		system(str.c_str());
	}
	else if(fp_S == NULL)
	{
		char c;
		c = fgetc(fp_C);
		while(!feof(fp_C))
		{
			if(c == '\n')	line_C++;
			c = fgetc(fp_C);
		}
		printf("%d 0\n", line_C);
		fflush(stdout);
		str = "cp " + Client + " server/";
		system(str.c_str());
	}
	else
	{
		char *buffer_c = new char[1000];
		char *buffer_s = new char[1000];
		int cnt_c = 1, cnt_s = 1;
		uint64_t ret = 0;
		int x;
		while(x = fread(buffer_c, 1, 1000, fp_C))
		{
			int cnt = 0;
			while (*buffer_c)
			{
				if(cnt < x-1)
				{
					if(*buffer_c == '\n')
					{
						arr_c[cnt_c++] = ret;
						ret = 0;
						*buffer_c++;
					}
					else	ret = ret * 131 + *buffer_c++;
				}
				else if(cnt == x-1)
				{
					if(*buffer_c == '\n')
					{
						arr_c[cnt_c++] = ret;
						ret = 0;
					}
					else	ret = ret * 131 + *buffer_c;
				}
				cnt++;
				if(cnt == x)	{buffer_c -= x-1; memset(buffer_c, '\0', x); break;}
			}
		}
		ret = 0;
		while(x = fread(buffer_s, 1, 1000, fp_S))
		{
			int cnt = 0;
			while (*buffer_s)
			{
				if(cnt < x-1)
				{
					if(*buffer_s == '\n')
					{
						arr_s[cnt_s++] = ret;
						ret = 0;
						*buffer_s++;
					}
					else	ret = ret * 131 + *buffer_s++;
				}
				else if(cnt == x-1)
				{
					if(*buffer_s == '\n')
					{
						arr_s[cnt_s++] = ret;
						ret = 0;
					}
					else	ret = ret * 131 + *buffer_s;
				}
				cnt++;
				if(cnt == x)	{buffer_s -= x-1; memset(buffer_s, '\0', x); break;}
			}
		}
		int lcs = LCS(cnt_c, cnt_s);
		printf("%d %d\n", cnt_c-1-lcs, cnt_s-1-lcs);
		fflush(stdout);
		str = "cp  "+ Client + " server/"; 
		system(str.c_str());
	}
	return;
}

int main(void)
{
	char cmd[10];
	while(scanf("%s", cmd) != EOF)
	{
		if(cmd[0] == 'e')	exit(0);
		else if(cmd[0] == 'u')
			Update();
	}
	return 0;
}