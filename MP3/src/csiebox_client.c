#include "csiebox_client.h"

#include "csiebox_common.h"
#include "connect.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <utime.h>

#define EVENT_SIZE (sizeof(struct inotify_event))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))

static int parse_arg(csiebox_client* client, int argc, char** argv);
static int login(csiebox_client* client);

char WD[EVENT_SIZE][PATH_MAX];
char buffer[EVENT_BUF_LEN];
int fd, length;
struct Inode{
	int inode;
	char i_path[PATH_MAX];
};
struct Inode I_node[100000];
int inode_cnt = 0;
//read config file, and connect to server
void csiebox_client_init(
  csiebox_client** client, int argc, char** argv) {
  csiebox_client* tmp = (csiebox_client*)malloc(sizeof(csiebox_client));
  if (!tmp) {
    fprintf(stderr, "client malloc fail\n");
    return;
  }
  memset(tmp, 0, sizeof(csiebox_client));
  if (!parse_arg(tmp, argc, argv)) {
    fprintf(stderr, "Usage: %s [config file]\n", argv[0]);
    free(tmp);
    return;
  }
  int fd = client_start(tmp->arg.name, tmp->arg.server);
  if (fd < 0) {
    fprintf(stderr, "connect fail\n");
    free(tmp);
    return;
  }
  tmp->conn_fd = fd;
  *client = tmp;
}

int sync_meta_client(char path[PATH_MAX], char rel_path[PATH_MAX], csiebox_client *client){
	csiebox_protocol_meta req;
	memset(&req, 0, sizeof(csiebox_protocol_meta));
	req.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
	req.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_META;
	req.message.header.req.datalen = sizeof(req) - sizeof(req.message.header);
	req.message.body.pathlen = strlen(path);
	lstat(path, &(req.message.body.stat));

	for(int i = 0; i <= inode_cnt; i++){
		if(req.message.body.stat.st_ino == I_node[i].inode){
			if(req.message.body.stat.st_nlink > 1){
				csiebox_protocol_hardlink hardlink;
				hardlink.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
				hardlink.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_HARDLINK;
				hardlink.message.header.req.datalen = sizeof(hardlink) - sizeof(hardlink.message.header);
				hardlink.message.body.srclen = strlen(rel_path);
				hardlink.message.body.targetlen = strlen(I_node[i].i_path);
				fprintf(stderr, "UPLOADING HARDLINK...\n%s -> %s\n", rel_path, I_node[i].i_path);
				if(!send_message(client->conn_fd, &hardlink, sizeof(hardlink))){
					fprintf(stderr, "send hardlink req fail\n");
					return -1;
				}
				if(!send_message(client->conn_fd, rel_path, strlen(rel_path))){
					fprintf(stderr, "send source path fail\n");
					return -1;
				}
				if(!send_message(client->conn_fd, I_node[i].i_path, strlen(I_node[i].i_path))){
					fprintf(stderr, "send target path fail\n");
					return -1;
				}
				fprintf(stderr, "-------SUCCESS-------\n");
				return 0;
			}
		}
	}
	inode_cnt++;
	I_node[inode_cnt].inode = req.message.body.stat.st_ino;
	strcpy(I_node[inode_cnt].i_path, rel_path);
	// fprintf(stderr, "sync meta---path: %s\nrel_path: %s\n", path, rel_path);
	if(S_ISREG(req.message.body.stat.st_mode)){
		md5_file(path, req.message.body.hash);
	}
	if(S_ISLNK(req.message.body.stat.st_mode)){
		char buf[PATH_MAX];
		int len;
		memset(buf, 0, PATH_MAX);
		len = readlink(path, buf, PATH_MAX);
		// fprintf(stderr, "len: %d buf: %s\n", len, buf);
		md5(buf, len, req.message.body.hash);
		// fprintf(stderr, "hash:%d\n", req.message.body.hash);
	}
	// if(req.message.header.req.magic == CSIEBOX_PROTOCOL_MAGIC_REQ){
	// 	fprintf(stderr, "req.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ\n");
	// }
	fprintf(stderr, "OP = %d\n", req.message.header.req.op);
	if(!send_message(client->conn_fd, &req, sizeof(req))){
		fprintf(stderr, "send meta req fail\n");
		return -1;
	}
	int pathlen = strlen(rel_path);
	if(!send_message(client->conn_fd, &pathlen, sizeof(int))){
		fprintf(stderr, "send pathlen fail\n");
		return -1;
	}
	if(!send_message(client->conn_fd, rel_path, strlen(rel_path))){
		fprintf(stderr, "send path fail\n");
		return -1;
	}
	if(!S_ISDIR(req.message.body.stat.st_mode)){
		csiebox_protocol_header header;
		memset(&header, 0, sizeof(header));
		if(recv_message(client->conn_fd, &header, sizeof(header))){
			if(header.res.magic == CSIEBOX_PROTOCOL_MAGIC_RES &&
				header.res.op == CSIEBOX_PROTOCOL_OP_SYNC_META){
				// fprintf(stderr, "receive from server: %04x\n", header.res.status);
				if(header.res.status == CSIEBOX_PROTOCOL_STATUS_MORE){
					if(S_ISREG(req.message.body.stat.st_mode)){
						fprintf(stderr, "UPLOADING REG...\n%s\n", path);
						int numbytes;
						int blksize = req.message.body.stat.st_blksize;
						char buffer[blksize];
						FILE *fp = fopen(path, "r");
						if(req.message.body.stat.st_size){
							while(!feof(fp)){
								memset(buffer, 0, blksize);
								numbytes = fread(buffer, sizeof(char), blksize, fp);
								fprintf(stderr, "numbytes = %d\n", numbytes);
								if(numbytes <= 0)	break;
								// fprintf(stderr, "numbytes: %d buffer: %s\n", numbytes, buffer);
								send_message(client->conn_fd, &numbytes, sizeof(int));
								send_message(client->conn_fd, buffer, numbytes);
							}
						}
						int x = 0;
						send_message(client->conn_fd, &x, sizeof(int));
						fclose(fp);
						fprintf(stderr, "-------SUCCESS-------\n");
						// fprintf(stderr, "SEND REG: %s\n", rel_path);
					}
					if(S_ISLNK(req.message.body.stat.st_mode)){
						fprintf(stderr, "UPLOADING LINK...\n%s\n", path);
						char buf[PATH_MAX];
						int len;
						memset(buf, 0, PATH_MAX);
						len = readlink(path, buf, PATH_MAX);
						send_message(client->conn_fd, &len, sizeof(int));
						send_message(client->conn_fd, buf, len);
						fprintf(stderr, "-------SUCCESS-------\n");
						// fprintf(stderr, "SEND LINK: %s -> %s\n", rel_path, buf);
						return 1;
					}
				}
			}
			else{
				fprintf(stderr, "\n");
				return -1;
			}
		}
	}
	else{
		int wd = inotify_add_watch(fd, path, IN_CREATE | IN_DELETE | IN_ATTRIB | IN_MODIFY);
		if(strlen(WD[wd]))	memset(WD[wd], 0, PATH_MAX);
		strcpy(WD[wd], path);
	}
	return 0;
}

void rm(char rel_path[], csiebox_client *client){
	csiebox_protocol_rm rm;
	rm.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
	rm.message.header.req.op = CSIEBOX_PROTOCOL_OP_RM;
	rm.message.header.req.datalen = sizeof(rm) - sizeof(rm.message.header);

	send_message(client->conn_fd, &rm, sizeof(rm));
	int len = strlen(rel_path);
	send_message(client->conn_fd, &len, sizeof(int));
	send_message(client->conn_fd, rel_path, len);
}

void monitor(csiebox_client *client){
	int i;
	while ((length = read(fd, buffer, EVENT_BUF_LEN)) > 0) {
		i = 0;
		while (i < length) {
			struct inotify_event* event = (struct inotify_event*)&buffer[i];
			if(event->name[0] == '.')	continue;
			fprintf(stderr, "event: (%d, %d, %s)\n", event->wd, strlen(event->name), event->name);
			char path[PATH_MAX], rel_path[PATH_MAX];
			memset(path, 0, PATH_MAX);
			memset(rel_path, 0, PATH_MAX);
			strcpy(path, WD[event->wd]);
			strcat(path, "/");
			strcat(path, event->name);
			int len = strlen(path);
			int start = strlen(client->arg.path);
			for(int i = start; i < len; i++)
				rel_path[i-start] = path[i];
			// fprintf(stderr, "monitor---path: %s\nrel_path: %s\n", path, rel_path);
			if(event->mask & IN_ISDIR){
				if (event->mask & IN_CREATE) {
					fprintf(stderr, "create dir %s %s\n", path, rel_path);
					sync_meta_client(path, rel_path, client);
				}
				if (event->mask & IN_DELETE) {
					fprintf(stderr, "delete dir %s %s\n", path, rel_path);
					rm(rel_path, client);
				}
			}
			else if(!(event->mask &IN_ISDIR)){
				if (event->mask & IN_DELETE) {
					fprintf(stderr, "delete file %s %s\n", path, rel_path);
					rm(rel_path, client);
				}
				if ((event->mask & IN_ATTRIB) || (event->mask & IN_CREATE) || (event->mask & IN_MODIFY)) {
					fprintf(stderr, "sync file %s %s\n", path, rel_path);
					sync_meta_client(path, rel_path, client);
				}
				// if (event->mask & IN_MODIFY) {
				// 	printf("modify file %s %s\n", path, rel_path);
				// 	sync_meta(path, rel_path, client);
				// }
			}
			i += EVENT_SIZE + event->len;
		}
		memset(buffer, 0, EVENT_BUF_LEN);
	}

	  //inotify_rm_watch(fd, wd);
	close(fd);
}


int tree_walk_client(DIR *dir, char rel_path[], csiebox_client* client){
	if(dir == NULL)	return 0;
	struct dirent *ptr;
	fprintf(stderr, "tree_walking\n");
	while(ptr = readdir(dir)){
		char d_name[PATH_MAX];
		strcpy(d_name, ptr->d_name);
		if(d_name[0] == '.')	continue;
		if(d_name[strlen(d_name)-1] == '~')	continue;
		// fprintf(stderr, "READING FILE:  %s\n", d_name);
		char tmp[PATH_MAX];
		strcpy(tmp, client->arg.path);
		char tmp_rel[PATH_MAX];
		strcpy(tmp_rel, rel_path);
		strcat(tmp_rel, "/");
		strcat(tmp_rel, d_name);
		strcat(tmp, tmp_rel);

		int a = sync_meta_client(tmp, tmp_rel, client);
		if(a == -1)	return -1;
		else if(a == 1)	continue;
		
		tree_walk_client(opendir(tmp), tmp_rel, client);
	}
	return 0;
}

int walk(DIR *dir, char rel_path[], csiebox_client* client){
	if(dir == NULL)	return 0;
	struct dirent *ptr;
	// fprintf(stderr, "tree_walking\n");
	while(ptr = readdir(dir)){
		char d_name[PATH_MAX];
		strcpy(d_name, ptr->d_name);
		if(d_name[0] == '.')	continue;
		if(d_name[strlen(d_name)-1] == '~')	continue;
		// fprintf(stderr, "READING FILE:  %s\n", d_name);
		char tmp[PATH_MAX];
		strcpy(tmp, client->arg.path);
		char tmp_rel[PATH_MAX];
		strcpy(tmp_rel, rel_path);
		strcat(tmp_rel, "/");
		strcat(tmp_rel, d_name);
		strcat(tmp, tmp_rel);
		if(ptr->d_type == DT_DIR){
			int wd = inotify_add_watch(fd, tmp, IN_CREATE | IN_DELETE | IN_ATTRIB | IN_MODIFY);
			if(strlen(WD[wd]))	memset(WD[wd], 0, PATH_MAX);
			strcpy(WD[wd], tmp);
		}

		walk(opendir(tmp), tmp_rel, client);
	}
	return 0;
}

int Download(csiebox_client *client){
	csiebox_protocol_header header;
	header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
	header.req.op = CSIEBOX_PROTOCOL_OP_DOWNLOAD;
	// send_message(client->conn_fd, &header, sizeof(header));
	fprintf(stderr, "=============download sent============\n");
	// csiebox_protocol_header header;
	// while (recv_message(client->conn_fd, &header, sizeof(header))) {
	// fprintf(stderr, "conn_fd = %d\n", client->conn_fd);
	while(1){
		if(!recv_message(client->conn_fd, &header, sizeof(header))){
			fprintf(stderr, "DOWNLOAD receive header fail!!!!!!\n");
			return 1;
		}
		fprintf(stderr, "============header received============\n");
		fprintf(stderr, "size of header %d\n", sizeof(header));
		fprintf(stderr, "download received OP = %d\n", header.req.op);
		// fprintf(stderr, "RECEIVING\n");
		switch (header.req.op){
			case CSIEBOX_PROTOCOL_OP_SYNC_META:
				fprintf(stderr, "sync_meta\n");
				csiebox_protocol_meta meta;
				if (complete_message_with_header(client->conn_fd, &header, &meta)) {
					header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
					char path[PATH_MAX], rel_path[PATH_MAX];
	       			memset(path, 0, PATH_MAX);
	   				memset(rel_path, 0, PATH_MAX);
					strcpy(path, client->arg.path);
					int pathlen;
					recv_message(client->conn_fd, &pathlen, sizeof(int));
					recv_message(client->conn_fd, rel_path, pathlen);
					strcat(path, rel_path);
			        // uint8_t client_hash[MD5_DIGEST_LENGTH];
			        // memset(client_hash, 0, MD5_DIGEST_LENGTH);
					
					if(S_ISDIR(meta.message.body.stat.st_mode)){
			            if(!opendir(path)){
			            	fprintf(stderr, "MKDIR: %s\n", path);
			  				char mkdir[PATH_MAX + 10] = "mkdir ";
			  				strcat(mkdir, path);
			  				system(mkdir);
			  				// int wd = inotify_add_watch(fd, path, IN_CREATE | IN_DELETE | IN_ATTRIB | IN_MODIFY);
							// if(strlen(WD[wd]))	memset(WD[wd], 0, PATH_MAX);
							// strcpy(WD[wd], path);
			            }
					}
					else if(S_ISREG(meta.message.body.stat.st_mode)){
						// md5_file(path, server_hash);
						// if(!memcmp(meta.message.body.hash, server_hash, MD5_DIGEST_LENGTH)){
						// 	header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
						// 	send_message(client->conn_fd, &header, sizeof(header));
						// }
						// else{
							// header.res.status = CSIEBOX_PROTOCOL_STATUS_MORE;
							// send_message(client->conn_fd, &header, sizeof(header));
	           				fprintf(stderr, "CREATING REG...\n%s\n", path);
							FILE *fp = fopen(path, "w");
							int blksize = meta.message.body.stat.st_blksize;
							char read_buf[blksize];
							int read_cnt = 0;
							while(1){
				                memset(read_buf, 0, blksize);
				                recv_message(client->conn_fd, &read_cnt, sizeof(int));
				                if(!read_cnt) break;
				                // fprintf(stderr, "read_cnt = %d\n", read_cnt);
				                recv_message(client->conn_fd, read_buf, read_cnt);
				                // fprintf(stderr, "read_buf = %s\n", read_buf);
								fwrite(read_buf, sizeof(char), read_cnt, fp);
							}
							fclose(fp);
	           				fprintf(stderr, "-------SUCCESS-------\n");
						// }
	       			}
			        else if(S_ISLNK(meta.message.body.stat.st_mode)){
			        	char buf[PATH_MAX];
			            memset(buf, 0, PATH_MAX);
			            int len;
			            len = readlink(path, buf, PATH_MAX);
			            // if(len >= 0)  md5(buf, len, server_hash);
			            // if(!memcmp(meta.message.body.hash, server_hash, MD5_DIGEST_LENGTH)){
			            // 	header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
			            // 	send_message(client->conn_fd, &header, sizeof(header));
			            // }
			            // else{
				            // header.res.status = CSIEBOX_PROTOCOL_STATUS_MORE;
				            // send_message(client->conn_fd, &header, sizeof(header));
				            fprintf(stderr, "CREATING LINK\n%s -> ", path);
				            char symlink[PATH_MAX];
				            memset(symlink, 0, PATH_MAX);
				            int leng;
				            recv_message(client->conn_fd, &leng, sizeof(int));
				            recv_message(client->conn_fd, symlink, leng);
				            char create_link[PATH_MAX+10] = "ln -s ";
				            strcat(create_link, symlink);
				            strcat(create_link, " ");
				            strcat(create_link, path);
				            fprintf(stderr, "%s\n", symlink);
			            	system(create_link);
			            	fprintf(stderr, "-------SUCCESS-------\n");
			            // }
					}
					struct utimbuf time;
					time.actime = meta.message.body.stat.st_atime;
					time.modtime = meta.message.body.stat.st_mtime;
					utime(path, &time);
					//====================
					//        TODO: here is where you handle sync_meta and even sync_file request from client
					//====================
	       		}
				break;
			case CSIEBOX_PROTOCOL_OP_SYNC_HARDLINK:
				fprintf(stderr, "sync hardlink\n");
				csiebox_protocol_hardlink hardlink;
				if (complete_message_with_header(client->conn_fd, &header, &hardlink)) {
					char srcpath[PATH_MAX], targetpath[PATH_MAX];
					memset(srcpath, 0, PATH_MAX);
					memset(targetpath, 0, PATH_MAX);
					strcpy(srcpath, client->arg.path);
					strcpy(targetpath, client->arg.path);
					char path1[PATH_MAX], path2[PATH_MAX];
					memset(path1, 0, PATH_MAX);
					memset(path2, 0, PATH_MAX);
					recv_message(client->conn_fd, &path1, hardlink.message.body.srclen);
					recv_message(client->conn_fd, &path2, hardlink.message.body.targetlen);
					strcat(srcpath, path1);
					strcat(targetpath, path2);
					fprintf(stderr, "CREATING HARDLINK...\n%s -> %s\n", srcpath, targetpath);
					char h_link[PATH_MAX*2 + 10] = "ln ";
					strcat(h_link, targetpath);
					strcat(h_link, " ");
					strcat(h_link, srcpath);
					system(h_link);
				}
				break;
			case CSIEBOX_PROTOCOL_OP_SYNC_END:
				fprintf(stderr, "END!!!!!!!!!!!!!!!!!\n");
				return 0;
				break;
			default:
				fprintf(stderr, "unknown op\n");
				break;
		}
	}
	// }
	return 0;
}
//this is where client sends request, you sould write your code here
int csiebox_client_run(csiebox_client* client) {
	if (!login(client)) {
		fprintf(stderr, "login fail\n");
		return 0;
	}
	fprintf(stderr, "login success\n");

	memset(I_node, 0, sizeof(I_node));

	memset(WD, 0, sizeof(WD));
	int length, i = 0;
	int wd;
	memset(buffer, 0, EVENT_BUF_LEN);
	fd = inotify_init();
	if (fd < 0) {
	  perror("inotify_init");
	}
	wd = inotify_add_watch(fd, client->arg.path, IN_CREATE | IN_DELETE | IN_ATTRIB | IN_MODIFY);
	strcpy(WD[wd], client->arg.path);
	fprintf(stderr, "OPENDIR\n");
	DIR *Cdir = opendir(client->arg.path);
	struct dirent *ptr;
	int empty = 1;
	while(ptr = readdir(Cdir)){
		if(ptr->d_name[0] == '.')	continue;
		empty = 0;
	}
	closedir(Cdir);
	fprintf(stderr, "OPENDIR2\n");
	Cdir = opendir(client->arg.path);
	if(!empty){
		fprintf(stderr, "UPLOADING...\n");
		if(tree_walk_client(Cdir, "", client) == -1){
			fprintf(stderr, "tree_walk_client fail\n");
			return 0;
		}
	}
	else{
		fprintf(stderr, "DOWNLOADING...\n");
		csiebox_protocol_header header;
		header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
		header.req.op = CSIEBOX_PROTOCOL_OP_DOWNLOAD;
		send_message(client->conn_fd, &header, sizeof(header));
		if(!Download(client))	fprintf(stderr, "DOWNLOAD COMPLETE\n");
		else fprintf(stderr, "DOWNLOAD FAIL\n");
	}
	walk(Cdir, "", client);
	closedir(Cdir);

	monitor(client);
	// fprsintf(stderr, "MONITER COMPLETE\n");
	//====================
	//        TODO: add your client-side code here
	//====================
	  
  
	return 1;
}

void csiebox_client_destroy(csiebox_client** client) {
  csiebox_client* tmp = *client;
  *client = 0;
  if (!tmp) {
    return;
  }
  close(tmp->conn_fd);
  free(tmp);
}

//read config file
static int parse_arg(csiebox_client* client, int argc, char** argv) {
  if (argc != 2) {
    return 0;
  }
  FILE* file = fopen(argv[1], "r");
  if (!file) {
    return 0;
  }
  fprintf(stderr, "reading config...\n");
  size_t keysize = 20, valsize = 20;
  char* key = (char*)malloc(sizeof(char) * keysize);
  char* val = (char*)malloc(sizeof(char) * valsize);
  ssize_t keylen, vallen;
  int accept_config_total = 5;
  int accept_config[5] = {0, 0, 0, 0, 0};
  while ((keylen = getdelim(&key, &keysize, '=', file) - 1) > 0) {
    key[keylen] = '\0';
    vallen = getline(&val, &valsize, file) - 1;
    val[vallen] = '\0';
    fprintf(stderr, "config (%d, %s)=(%d, %s)\n", keylen, key, vallen, val);
    if (strcmp("name", key) == 0) {
      if (vallen <= sizeof(client->arg.name)) {
        strncpy(client->arg.name, val, vallen);
        accept_config[0] = 1;
      }
    } else if (strcmp("server", key) == 0) {
      if (vallen <= sizeof(client->arg.server)) {
        strncpy(client->arg.server, val, vallen);
        accept_config[1] = 1;
      }
    } else if (strcmp("user", key) == 0) {
      if (vallen <= sizeof(client->arg.user)) {
        strncpy(client->arg.user, val, vallen);
        accept_config[2] = 1;
      }
    } else if (strcmp("passwd", key) == 0) {
      if (vallen <= sizeof(client->arg.passwd)) {
        strncpy(client->arg.passwd, val, vallen);
        accept_config[3] = 1;
      }
    } else if (strcmp("path", key) == 0) {
      if (vallen <= sizeof(client->arg.path)) {
        strncpy(client->arg.path, val, vallen);
        accept_config[4] = 1;
      }
    }
  }
  free(key);
  free(val);
  fclose(file);
  int i, test = 1;
  for (i = 0; i < accept_config_total; ++i) {
    test = test & accept_config[i];
  }
  if (!test) {
    fprintf(stderr, "config error\n");
    return 0;
  }
  return 1;
}

static int login(csiebox_client* client) {
  csiebox_protocol_login req;
  memset(&req, 0, sizeof(req));
  req.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
  req.message.header.req.op = CSIEBOX_PROTOCOL_OP_LOGIN;
  req.message.header.req.datalen = sizeof(req) - sizeof(req.message.header);
  memcpy(req.message.body.user, client->arg.user, strlen(client->arg.user));
  md5(client->arg.passwd,
      strlen(client->arg.passwd),
      req.message.body.passwd_hash);
  fprintf(stderr, "send login\n");
  fprintf(stderr, "sizeof req %d\n", sizeof(req));
  if (!send_message(client->conn_fd, &req, sizeof(req))) {
    fprintf(stderr, "send fail\n");
    return 0;
  }
  fprintf(stderr, "login sent\n");
  csiebox_protocol_header header;
  memset(&header, 0, sizeof(header));
  if (recv_message(client->conn_fd, &header, sizeof(header))) {
    if (header.res.magic == CSIEBOX_PROTOCOL_MAGIC_RES &&
        header.res.op == CSIEBOX_PROTOCOL_OP_LOGIN &&
        header.res.status == CSIEBOX_PROTOCOL_STATUS_OK) {
      client->client_id = header.res.client_id;
      return 1;
    } else {
      return 0;
    }
  }
  return 0;
}
