#include <bits/stdc++.h>
#include <sys/types.h>
#include <dirent.h>
using namespace std;

void tree_walk(DIR *dir, string str){
	if(dir == NULL)	return;
	struct dirent *ptr;
	while(ptr = readdir(dir)){
		string d_name = ptr->d_name;
		string tmp = str;
		if(d_name[0] == '.')	continue;
		if(!tmp.length())	tmp += ptr->d_name;
		else	tmp += "/" + d_name;
		printf("%s\n", tmp.c_str());
		if(ptr->d_type == DT_REG)	system(("cp  client/" + tmp + " server/" + tmp).c_str());
		else if(ptr->d_type == DT_DIR)	system(("mkdir server/" + tmp).c_str());
		else{
			system(("cp -P client/" + tmp + " server/" + tmp).c_str());
			continue;
		}
		tree_walk(opendir(("client/" + tmp).c_str()), tmp);
	}
	return;
}

int main(void){
	DIR *Client = opendir("client");
	DIR *Server = opendir("server");
	tree_walk(Client, "");
	struct dirent *ptr2;
	// closedir(Client);
	// Client = opendir("client");
	// while(ptr2 = readdir(Client)){
	// 	string s = ptr2->d_name;
	// 	if(ptr2->d_type != DT_DIR && ptr2->d_type != DT_REG)	system(("cp -P client/" + s + " server/" + s).c_str());
	// 	else	system(("cp -r client/" + s + " server/" + s).c_str());
	// }
	closedir(Client);
	closedir(Server);
	return 0;
}