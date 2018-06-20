#include "csiebox_server.h"

#include "csiebox_common.h"
#include "connect.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <dirent.h>
#include <utime.h>
#include <pthread.h>

static int parse_arg(csiebox_server* server, int argc, char** argv);
static void handle_request(csiebox_server* server, int conn_fd, csiebox_protocol_header header);
static int get_account_info(
  csiebox_server* server,  const char* user, csiebox_account_info* info);
static void login(
  csiebox_server* server, int conn_fd, csiebox_protocol_login* login);
static void logout(csiebox_server* server, int conn_fd);
static char* get_user_homedir(
  csiebox_server* server, csiebox_client_info* info);

#define DIR_S_FLAG (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)//permission you can use to create new file
#define REG_S_FLAG (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)//permission you can use to create new directory

#define NUM_HANDLER_THREADS 6

int MAXFDS;
struct timeval timeout = {3, 0};
struct Inode{
	int inode;
	char i_path[PATH_MAX];
};
struct Inode I_node[100000];
int inode_cnt = 0;

//read config file, and start to listen
void csiebox_server_init(
	csiebox_server** server, int argc, char** argv) {
	csiebox_server* tmp = (csiebox_server*)malloc(sizeof(csiebox_server));
	if (!tmp) {
		fprintf(stderr, "server malloc fail\n");
		return;
	}
	memset(tmp, 0, sizeof(csiebox_server));
	if (!parse_arg(tmp, argc, argv)) {
		fprintf(stderr, "Usage: %s [config file]\n", argv[0]);
		free(tmp);
		return;
	}
	int fd = server_start();
	if (fd < 0) {
		fprintf(stderr, "server fail\n");
		free(tmp);
		return;
	}
	tmp->client = (csiebox_client_info**)
		malloc(sizeof(csiebox_client_info*) * getdtablesize());
	if (!tmp->client) {
		fprintf(stderr, "client list malloc fail\n");
		close(fd);
		free(tmp);
		return;
	}
	memset(tmp->client, 0, sizeof(csiebox_client_info*) * getdtablesize());
	tmp->listen_fd = fd;
	*server = tmp;
}

//wait client to connect and handle requests from connected socket fd
//===============================
//		TODO: you need to modify code in here and handle_request() to support I/O multiplexing
//===============================

int csiebox_server_run(csiebox_server* server) {
	fd_set readfds, master;
	FD_ZERO(&master);
	FD_ZERO(&readfds);
	while (1) {
		int conn_fd, conn_len;
		struct sockaddr_in addr;
		FD_ZERO(&readfds);
		readfds = master;
		FD_SET(server->listen_fd, &readfds);
		memset(&addr, 0, sizeof(addr));
		conn_len = 0;
		if(MAXFDS <= server->listen_fd) MAXFDS = server->listen_fd+1;
		select(MAXFDS, &readfds, NULL, NULL, NULL);
		for(int i = 3; i < MAXFDS; i++){
			if(FD_ISSET(i, &readfds)){
				if(i == server->listen_fd){
					fprintf(stderr, "listen is set\n");
					conn_fd = accept(server->listen_fd, (struct sockaddr*)&addr, (socklen_t*)&conn_len);
					fprintf(stderr, "conn_fd %d\n", conn_fd);
					if (conn_fd < 0) {
						if (errno == ENFILE) {
							fprintf(stderr, "out of file descriptor table\n");
							continue;
						}
						else if (errno == EAGAIN || errno == EINTR) {
							continue;
						}
						else {
							fprintf(stderr, "accept err\n");
							fprintf(stderr, "code: %s\n", strerror(errno));
							break;
						}
					}
					FD_SET(conn_fd, &master);
					if(conn_fd >= MAXFDS)	MAXFDS = conn_fd+1;		
				}
				else{
					csiebox_protocol_header header;
					memset(&header, 0, sizeof(header));
					int nbytes = recv(i, &header, sizeof(header), MSG_WAITALL);
					fprintf(stderr, "nbytes = %d\n", nbytes);
					fprintf(stderr, "sizeof header: %d\n", sizeof(header));
					if(nbytes <= 0){
						if(nbytes == 0){
							fprintf(stderr, "socket %d hung up\n", i);
						}
						else{
							// perror("recv error\n");
							fprintf(stderr, "recv error\n");
						}
						close(i);
						FD_CLR(i, &master);
						fprintf(stderr, "end of connection\n");
						// logout(server, i);
					}
					else{
						fprintf(stderr, "header OP = %d\n", header.req.op);
						handle_request(server, i, header);
					}
				}
			}
		}	
	}
	return 1;
}

void csiebox_server_destroy(csiebox_server** server) {
  csiebox_server* tmp = *server;
  *server = 0;
  if (!tmp) {
    return;
  }
  close(tmp->listen_fd);
  int i = getdtablesize() - 1;
  for (; i >= 0; --i) {
    if (tmp->client[i]) {
      free(tmp->client[i]);
    }
  }
  free(tmp->client);
  free(tmp);
}

//read config file
static int parse_arg(csiebox_server* server, int argc, char** argv) {
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
  int accept_config_total = 2;
  int accept_config[2] = {0, 0};
  while ((keylen = getdelim(&key, &keysize, '=', file) - 1) > 0) {
    key[keylen] = '\0';
    vallen = getline(&val, &valsize, file) - 1;
    val[vallen] = '\0';
    fprintf(stderr, "config (%d, %s)=(%d, %s)\n", keylen, key, vallen, val);
    if (strcmp("path", key) == 0) {
      if (vallen <= sizeof(server->arg.path)) {
        strncpy(server->arg.path, val, vallen);
        accept_config[0] = 1;
      }
    } else if (strcmp("account_path", key) == 0) {
      if (vallen <= sizeof(server->arg.account_path)) {
        strncpy(server->arg.account_path, val, vallen);
        accept_config[1] = 1;
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
}

int sync_meta_server(char path[PATH_MAX], char rel_path[PATH_MAX], int conn_fd){
	fprintf(stderr, "sync_meta_server\n");
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
				if(!send_message(conn_fd, &hardlink, sizeof(hardlink))){
					fprintf(stderr, "send hardlink req fail\n");
					return -1;
				}
				if(!send_message(conn_fd, rel_path, strlen(rel_path))){
					fprintf(stderr, "send source path fail\n");
					return -1;
				}
				if(!send_message(conn_fd, I_node[i].i_path, strlen(I_node[i].i_path))){
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
	if(!send_message(conn_fd, &req, sizeof(req))){
		fprintf(stderr, "send meta req fail\n");
		return -1;
	}
	int pathlen = strlen(rel_path);
	// fprintf(stderr, "sync_meta_server send pathlen\n");
	if(!send_message(conn_fd, &pathlen, sizeof(int))){
		fprintf(stderr, "send pathlen fail\n");
		return -1;
	}
	// fprintf(stderr, "sync_meta_server send path\n");
	if(!send_message(conn_fd, rel_path, strlen(rel_path))){
		fprintf(stderr, "send path fail\n");
		return -1;
	}
	if(!S_ISDIR(req.message.body.stat.st_mode)){
		csiebox_protocol_header header;
		memset(&header, 0, sizeof(header));
		if(S_ISREG(req.message.body.stat.st_mode)){
			// fprintf(stderr, "SENDING REG...\n%s\n", path);
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
					send_message(conn_fd, &numbytes, sizeof(int));
					send_message(conn_fd, buffer, numbytes);
				}
			}
			int x = 0;
			send_message(conn_fd, &x, sizeof(int));
			fclose(fp);
			// fprintf(stderr, "-------SUCCESS-------\n");
		}
		if(S_ISLNK(req.message.body.stat.st_mode)){
			fprintf(stderr, "SENDING LINK...\n%s\n", path);
			char buf[PATH_MAX];
			int len;
			memset(buf, 0, PATH_MAX);
			len = readlink(path, buf, PATH_MAX);
			send_message(conn_fd, &len, sizeof(int));
			send_message(conn_fd, buf, len);
			// fprintf(stderr, "-------SUCCESS-------\n");
			return 1;
		}
	}
	fprintf(stderr, "sync_meta_server done\n");
	return 0;
}

int tree_walk_server(DIR *dir, char username[], char rel_path[], csiebox_server* server, int conn_fd){
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
		strcpy(tmp, server->arg.path);
		strcat(tmp, "/");
		strcat(tmp, username);
		char tmp_rel[PATH_MAX];
		strcpy(tmp_rel, rel_path);
		strcat(tmp_rel, "/");
		strcat(tmp_rel, d_name);
		strcat(tmp, tmp_rel);
		// fprintf(stderr, "path: %s\nrel_path: %s\n", tmp, tmp_rel);

		int a = sync_meta_server(tmp, tmp_rel, conn_fd);
		if(a == -1)	return -1;
		else if(a == 1)	continue;
		
		tree_walk_server(opendir(tmp), username, tmp_rel, server, conn_fd);
	}
	return 0;
}

//this is where the server handle requests, you should write your code here
static void handle_request(csiebox_server* server, int conn_fd, csiebox_protocol_header header) {
	// csiebox_protocol_header header;
	// memset(&header, 0, sizeof(header));
	char username[30];
	memset(username, 0, 30);
	// while (recv_message(conn_fd, &header, sizeof(header))) {
		if (header.req.magic != CSIEBOX_PROTOCOL_MAGIC_REQ) {
     		fprintf(stderr, "header.req.magic !\n");
			return;
		}
		switch (header.req.op){
			case CSIEBOX_PROTOCOL_OP_LOGIN:
				fprintf(stderr, "login\n");
				csiebox_protocol_login req;
				if (complete_message_with_header(conn_fd, &header, &req)) {
					login(server, conn_fd, &req);
					strcpy(username, server->client[conn_fd]->account.user);
					fprintf(stderr, "=================username: %s==================\n", username);
       			}
				break;
			case CSIEBOX_PROTOCOL_OP_SYNC_META:
				fprintf(stderr, "sync_meta\n");
				csiebox_protocol_meta meta;
				if (complete_message_with_header(conn_fd, &header, &meta)) {
					header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
					header.res.op = CSIEBOX_PROTOCOL_OP_SYNC_META;
					strcpy(username, server->client[conn_fd]->account.user);
					char path[PATH_MAX], rel_path[PATH_MAX];
          			memset(path, 0, PATH_MAX);
       				memset(rel_path, 0, PATH_MAX);
					strcpy(path, server->arg.path);
					strcat(path, "/");
					strcat(path, username);
					int pathlen;
					recv_message(conn_fd, &pathlen, sizeof(int));
					recv_message(conn_fd, rel_path, pathlen);
					strcat(path, rel_path);
			        uint8_t server_hash[MD5_DIGEST_LENGTH];
			        memset(server_hash, 0, MD5_DIGEST_LENGTH);
					if(S_ISDIR(meta.message.body.stat.st_mode)){
			            if(!opendir(path)){
			              // fprintf(stderr, "MKDIR: %s\n", path);
			  				char mkdir[PATH_MAX + 10] = "mkdir ";
			  				strcat(mkdir, path);
			  				system(mkdir);
			            }
					}
					else if(S_ISREG(meta.message.body.stat.st_mode)){
						md5_file(path, server_hash);
						if(!memcmp(meta.message.body.hash, server_hash, MD5_DIGEST_LENGTH)){
							header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
							fprintf(stderr, "OK\n");
							send_message(conn_fd, &header, sizeof(header));
						}
						else{
							header.res.status = CSIEBOX_PROTOCOL_STATUS_MORE;
							fprintf(stderr, "MORE\n");
							send_message(conn_fd, &header, sizeof(header));
              				// fprintf(stderr, "CREATING REG...\n%s\n", path);
							FILE *fp = fopen(path, "w");
							int blksize = meta.message.body.stat.st_mode;
							char read_buf[blksize];
							int read_cnt = 0;
							while(1){
				                memset(read_buf, 0, blksize);
				                recv_message(conn_fd, &read_cnt, sizeof(int));
				                if(!read_cnt) break;
				                // fprintf(stderr, "read_cnt = %d\n", read_cnt);
				                recv_message(conn_fd, read_buf, read_cnt);
				                // fprintf(stderr, "read_buf = %s\n", read_buf);
								fwrite(read_buf, sizeof(char), read_cnt, fp);
							}
							fclose(fp);
              				// fprintf(stderr, "-------SUCCESS-------\n");
						}
         			}
			        else if(S_ISLNK(meta.message.body.stat.st_mode)){
			        	char buf[PATH_MAX];
			            memset(buf, 0, PATH_MAX);
			            int len;
			            len = readlink(path, buf, PATH_MAX);
			            if(len >= 0)  md5(buf, len, server_hash);
			            if(!memcmp(meta.message.body.hash, server_hash, MD5_DIGEST_LENGTH)){
			            	header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
			            	send_message(conn_fd, &header, sizeof(header));
			            }
			            else{
				            header.res.status = CSIEBOX_PROTOCOL_STATUS_MORE;
				            send_message(conn_fd, &header, sizeof(header));
				            // fprintf(stderr, "CREATING LINK\n%s -> ", path);
				            char symlink[PATH_MAX];
				            memset(symlink, 0, PATH_MAX);
				            int len;
				            recv_message(conn_fd, &len, sizeof(int));
				            recv_message(conn_fd, symlink, len);
				            char create_link[PATH_MAX+10] = "ln -s ";
				            strcat(create_link, symlink);
				            strcat(create_link, " ");
				            strcat(create_link, path);
				            fprintf(stderr, "%s\n", symlink);
			            	system(create_link);
			            	// fprintf(stderr, "-------SUCCESS-------\n");
			            }
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
				if (complete_message_with_header(conn_fd, &header, &hardlink)) {
					char srcpath[PATH_MAX], targetpath[PATH_MAX];
					strcpy(username, server->client[conn_fd]->account.user);
					memset(srcpath, 0, PATH_MAX);
					memset(targetpath, 0, PATH_MAX);
					strcpy(srcpath, server->arg.path);
					strcat(srcpath, "/");
					strcat(srcpath, username);
					strcpy(targetpath, server->arg.path);
					strcat(targetpath, "/");
					strcat(targetpath, username);
					char path1[PATH_MAX], path2[PATH_MAX];
					memset(path1, 0, PATH_MAX);
					memset(path2, 0, PATH_MAX);
					recv_message(conn_fd, &path1, hardlink.message.body.srclen);
					recv_message(conn_fd, &path2, hardlink.message.body.targetlen);
					strcat(srcpath, path1);
					strcat(targetpath, path2);
					// fprintf(stderr, "CREATING HARDLINK...\n%s -> %s\n", srcpath, targetpath);
					char h_link[PATH_MAX*2 + 10] = "ln ";
					strcat(h_link, targetpath);
					strcat(h_link, " ");
					strcat(h_link, srcpath);
					system(h_link);
					struct utimbuf time;
					utime(srcpath, &time);
					//====================
					//        TODO: here is where you handle sync_hardlink request from client
					//====================
				}
				break;
			case CSIEBOX_PROTOCOL_OP_SYNC_END:
				fprintf(stderr, "sync end\n");
				fprintf(stderr, "END!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
				csiebox_protocol_header end;
					//====================
					//        TODO: here is where you handle synchronization request from client
					//====================
				break;
			case CSIEBOX_PROTOCOL_OP_RM:
				fprintf(stderr, "rm\n");
				csiebox_protocol_rm rm;
				if (complete_message_with_header(conn_fd, &header, &rm)) {
			        strcpy(username, server->client[conn_fd]->account.user);
			        char rel_path[PATH_MAX];
			        memset(rel_path, 0, PATH_MAX);
			        char path[PATH_MAX];
			        memset(path, 0, PATH_MAX);
			        strcpy(path, server->arg.path);
			        strcat(path, "/");
			        strcat(path, username);
			        int pathlen;
			        recv_message(conn_fd, &pathlen, sizeof(int));
			        recv_message(conn_fd, rel_path, pathlen);
			        // fprintf(stderr, "REMOVING...\n%s\n", rel_path);
			        strcat(path, rel_path);
			        char remove[PATH_MAX + 10] = "rm -rf ";
			        strcat(remove, path);
			        system(remove);
			        // fprintf(stderr, "-------SUCCESS-------\n");
					//====================
					//        TODO: here is where you handle rm file or directory request from client
					//====================
				}
				break;
			case CSIEBOX_PROTOCOL_OP_DOWNLOAD:
				fprintf(stderr, "~~~~~~~~~~~~~~~~DOWNLOADING~~~~~~~~~~~~~~~~~\n");
				memset(I_node, 0, sizeof(I_node));
				strcpy(username, server->client[conn_fd]->account.user);
				char home[PATH_MAX];
				strcpy(home, server->arg.path);
				strcat(home, "/");
				strcat(home, username);
				DIR *Sdir = opendir(home);
				fprintf(stderr, "START READING\n");
				if(readdir(Sdir)){
					if(tree_walk_server(Sdir, username, "", server, conn_fd) == -1){
						fprintf(stderr, "tree_walk_server fail\n");
					}
				}
				fprintf(stderr, "FINISH READING\n");
				closedir(Sdir);
				csiebox_protocol_header head;
				head.req.op = CSIEBOX_PROTOCOL_OP_SYNC_END;
				if(!send_message(conn_fd, &head, sizeof(head))){
					fprintf(stderr, "FCUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUuu\n");
				}
				break;
			default:
				fprintf(stderr, "unknown op %x\n", header.req.op);
				break;
		}
	// }
	// fprintf(stderr, "end of connection\n");
	// logout(server, conn_fd);
}

//open account file to get account information
static int get_account_info(
  csiebox_server* server,  const char* user, csiebox_account_info* info) {
  FILE* file = fopen(server->arg.account_path, "r");
  if (!file) {
    return 0;
  }
  size_t buflen = 100;
  char* buf = (char*)malloc(sizeof(char) * buflen);
  memset(buf, 0, buflen);
  ssize_t len;
  int ret = 0;
  int line = 0;
  while ((len = getline(&buf, &buflen, file) - 1) > 0) {
    ++line;
    buf[len] = '\0';
    char* u = strtok(buf, ",");
    if (!u) {
      fprintf(stderr, "illegal form in account file, line %d\n", line);
      continue;
    }
    if (strcmp(user, u) == 0) {
      memcpy(info->user, user, strlen(user));
      char* passwd = strtok(NULL, ",");
      if (!passwd) {
        fprintf(stderr, "illegal form in account file, line %d\n", line);
        continue;
      }
      md5(passwd, strlen(passwd), info->passwd_hash);
      ret = 1;
      break;
    }
  }
  free(buf);
  fclose(file);
  return ret;
}

//handle the login request from client
static void login(
  csiebox_server* server, int conn_fd, csiebox_protocol_login* login) {
  int succ = 1;
  csiebox_client_info* info =
    (csiebox_client_info*)malloc(sizeof(csiebox_client_info));
  memset(info, 0, sizeof(csiebox_client_info));
  if (!get_account_info(server, login->message.body.user, &(info->account))) {
    fprintf(stderr, "cannot find account\n");
    succ = 0;
  }
  if (succ &&
      memcmp(login->message.body.passwd_hash,
             info->account.passwd_hash,
             MD5_DIGEST_LENGTH) != 0) {
    fprintf(stderr, "passwd miss match\n");
    succ = 0;
  }

  csiebox_protocol_header header;
  memset(&header, 0, sizeof(header));
  header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
  header.res.op = CSIEBOX_PROTOCOL_OP_LOGIN;
  header.res.datalen = 0;
  if (succ) {
    if (server->client[conn_fd]) {
      free(server->client[conn_fd]);
    }
    info->conn_fd = conn_fd;
    server->client[conn_fd] = info;
    header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
    header.res.client_id = info->conn_fd;
    char* homedir = get_user_homedir(server, info);
    fprintf(stderr, "HOMEDIR: %s\n", homedir);
    mkdir(homedir, DIR_S_FLAG);
    free(homedir);
  } else {
    header.res.status = CSIEBOX_PROTOCOL_STATUS_FAIL;
    free(info);
  }
  send_message(conn_fd, &header, sizeof(header));
}

static void logout(csiebox_server* server, int conn_fd) {
  free(server->client[conn_fd]);
  server->client[conn_fd] = 0;
  close(conn_fd);
}

static char* get_user_homedir(
  csiebox_server* server, csiebox_client_info* info) {
  char* ret = (char*)malloc(sizeof(char) * PATH_MAX);
  memset(ret, 0, PATH_MAX);
  sprintf(ret, "%s/%s", server->arg.path, info->account.user);
  return ret;
}

