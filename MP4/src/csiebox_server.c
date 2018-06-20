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
#include <sys/select.h>
#include <fts.h>
#include <dirent.h>

static int parse_arg(csiebox_server* server, int argc, char** argv);
// static void handle_request(csiebox_server* server, int conn_fd);
static int get_account_info(
  csiebox_server* server,  const char* user, csiebox_account_info* info);
static void login(
  csiebox_server* server, int conn_fd, csiebox_protocol_login* login);
static void logout(csiebox_server* server, int conn_fd);
static char* get_user_homedir(
  csiebox_server* server, csiebox_client_info* info);
static int handle_download(csiebox_server *server,int conn_fd);

#define DIR_S_FLAG (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)//permission you can use to create new file
#define REG_S_FLAG (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)//permission you can use to create new directory
#define OK 0
#define BUSY 1
#define BLOCK 2
//read config file, and start to listen
//=====================================
//        TODO
//You should add your code of initializing 
//thread pool here
//=====================================
int num_requests = 0;
int thread_cnt = 0, thread_num;
int undone[2000] = {0};
int thread_idle[16] = {0};
int thread_client[16];


struct request{
  int thread_id;
  csiebox_server *server;
};

void discard_request(csiebox_server *server, int conn_fd){
  int status = BUSY;
  csiebox_protocol_header header;
  memset(&header, 0, sizeof(header));
  if(!recv_message(conn_fd, &header, sizeof(header))){
    fprintf(stderr, "end of connection\n");
    logout(server, conn_fd);
    return;
  }
  if (header.req.magic != CSIEBOX_PROTOCOL_MAGIC_REQ) {
    return;
  }
  switch (header.req.op) {
    case CSIEBOX_PROTOCOL_OP_SYNC_META:
      fprintf(stderr, "discard meta\n");
      csiebox_protocol_meta meta;
      if(complete_message_with_header(conn_fd, &header, &meta))
        send_message(conn_fd, &status, sizeof(int));
      break;
    case CSIEBOX_PROTOCOL_OP_SYNC_HARDLINK:
      fprintf(stderr, "discard hardlink\n");
      csiebox_protocol_hardlink hardlink;
      if(complete_message_with_header(conn_fd, &header, &hardlink))
        send_message(conn_fd, &status, sizeof(int));
      break;
    case CSIEBOX_PROTOCOL_OP_SYNC_END:
      fprintf(stderr, "discard sync end\n");
      csiebox_protocol_header end;

      break;
    case CSIEBOX_PROTOCOL_OP_RM:
      fprintf(stderr, "discard rm\n");
      csiebox_protocol_rm rm;
      if(complete_message_with_header(conn_fd, &header, &rm))
        send_message(conn_fd, &status, sizeof(int));
      break;
    default:
      fprintf(stderr, "unknown op %x\n", header.req.op);
      break;
  }
}

void send_ok(int conn_fd){
  int status = OK;
  send_message(conn_fd, &status, sizeof(status));
}

void handle_request(csiebox_server *server, int conn_fd)
{
  csiebox_protocol_header header;
  memset(&header, 0, sizeof(header));
  if(!recv_message(conn_fd, &header, sizeof(header))){
    fprintf(stderr, "end of connection\n");
    logout(server, conn_fd);
    return;
  }
  if (header.req.magic != CSIEBOX_PROTOCOL_MAGIC_REQ) {
    return;
  }
  switch (header.req.op) {
    case CSIEBOX_PROTOCOL_OP_LOGIN:
      fprintf(stderr, "login\n");
      csiebox_protocol_login req;
      if (complete_message_with_header(conn_fd, &header, &req)) {
        login(server, conn_fd, &req);
        handle_download(server,conn_fd);
        csiebox_protocol_header sync_end;
        memset(&sync_end, 0, sizeof(csiebox_protocol_header));
        sync_end.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
        sync_end.req.op   = CSIEBOX_PROTOCOL_OP_SYNC_END;
        send_message(conn_fd, &sync_end, sizeof(sync_end));
      }
      break;
    case CSIEBOX_PROTOCOL_OP_SYNC_META:
      fprintf(stderr, "sync meta\n");
      csiebox_protocol_meta meta;
      if (complete_message_with_header(conn_fd, &header, &meta)) {
        send_ok(conn_fd);
        //====================
        //        TODO
        // You should add exclusive lock on file that is currenting synchronizing
        //====================
        server_sync_meta(meta, conn_fd, server);
                
      }
      break;
    case CSIEBOX_PROTOCOL_OP_SYNC_HARDLINK:
      fprintf(stderr, "sync hardlink\n");
      csiebox_protocol_hardlink hardlink;
      if (complete_message_with_header(conn_fd, &header, &hardlink)) {
        send_ok(conn_fd);

        server_sync_hardlink( hardlink, conn_fd, server);
      }
      break;
    case CSIEBOX_PROTOCOL_OP_SYNC_END:
      fprintf(stderr, "sync end\n");
      csiebox_protocol_header end;

      break;
    case CSIEBOX_PROTOCOL_OP_RM:
      fprintf(stderr, "rm\n");
      csiebox_protocol_rm rm;
      if (complete_message_with_header(conn_fd, &header, &rm)) {
        send_ok(conn_fd);
        server_rm(rm, conn_fd, server);
      }
      break;
    default:
      fprintf(stderr, "unknown op %x\n", header.req.op);
      break;
  }
  // sleep(1);
}

void* thread_run(void* data){
  struct request* a_request = (struct request*)data;
  // fprintf(stderr, "thread id = %d\n", a_request->thread_id);
  while(1){
    fprintf(stderr, "Thread '%d' BEFORE HANDLING :%d\n", a_request->thread_id, thread_client[a_request->thread_id]);
    while(!thread_idle[a_request->thread_id]){}
    fprintf(stderr, "Thread '%d' HANDLING REQUEST FROM: %d\n", a_request->thread_id, thread_client[a_request->thread_id]);
    handle_request(a_request->server, thread_client[a_request->thread_id]);
    // sleep(1);
    undone[thread_client[a_request->thread_id]] = 0;
    thread_idle[a_request->thread_id] = 0;
  }
  free(a_request);
}

void thread_init(csiebox_server *server){
  // fprintf(stderr, "thread_num = %d\n", thread_num);
  pthread_t p_threads[thread_num];
  for(int i = 0; i < thread_num; i++){
    struct request* a_request = (struct request*)malloc(sizeof(struct request));
    // fprintf(stderr, "i = %d\n", i);
    a_request->thread_id = i;
    a_request->server = server;
    pthread_create(&(p_threads[i]), NULL, thread_run, (void *)a_request);
  }
  // free(a_request);
  sleep(3);
}

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

 thread_num = (*server)->arg.thread_num;
 thread_init(*server);
}

//wait client to connect and handle requests from connected socket fd
int csiebox_server_run(csiebox_server* server) {
  int conn_fd, conn_len;
  struct sockaddr_in addr;
  fd_set read_set;
  int max_fd = -1;
  int i = 0;
  
  FD_ZERO(&read_set);
  FD_SET(server->listen_fd,&read_set);
  max_fd = server->listen_fd;

  while (1) {
    usleep(1000);
  select( max_fd+1, &read_set, NULL, NULL, NULL);
  if( FD_ISSET(server->listen_fd, &read_set)){
    memset(&addr, 0, sizeof(addr));
      conn_len = 0;
      // waiting client connect
      conn_fd = accept(
        server->listen_fd, (struct sockaddr*)&addr, (socklen_t*)&conn_len);
      if (conn_fd < 0) {
      if (errno == ENFILE) {
            fprintf(stderr, "out of file descriptor table\n");
          } else if (errno == EAGAIN || errno == EINTR) {

          } else {
            fprintf(stderr, "accept err\n");
            fprintf(stderr, "code: %s\n", strerror(errno));
         }
       FD_ZERO(&read_set);
       FD_SET(server->listen_fd, &read_set);
       max_fd = server->listen_fd;
       for( i = 0; i < getdtablesize(); ++i )
       {
         if( !server->client[i])
          continue;
           FD_SET(server->client[i]->conn_fd, &read_set);
         max_fd = max_fd > server->client[i]->conn_fd ? max_fd : server->client[i]->conn_fd;
       }
       continue;
      }
      handle_request(server, conn_fd);
  }
  else{
    for( i = 0; i < getdtablesize(); ++i )
    {
      if( !server->client[i])
        continue;
      if( FD_ISSET(server->client[i]->conn_fd, &read_set))
      {
        // while(1){
          int flag = 0;
          if(server->client[i] != NULL){
            if(undone[server->client[i]->conn_fd]){
              // fprintf(stderr, "UNDONE--------------------------\n");
              // while(undone[server->client[i]->conn_fd]){
              // }
              continue;
            }
          }
          for(int j = 0; j < thread_num; j++){
            if(!thread_idle[j]){
              // sleep(1);
              flag = 1;
              undone[server->client[i]->conn_fd] = 1;
              thread_client[j] = server->client[i]->conn_fd;
              thread_idle[j] = 1;
              break;
            }
          }
          if(!flag){
            // fprintf(stderr, "BUSY\n");
            discard_request(server, server->client[i]->conn_fd);
          }
          // break;
        // }
      }
    }
  }
  FD_ZERO(&read_set);
  FD_SET(server->listen_fd, &read_set);
  max_fd = server->listen_fd;
  for( i = 0; i < getdtablesize(); ++i )
  {
    if( !server->client[i])
      continue;
    FD_SET(server->client[i]->conn_fd, &read_set);
    max_fd = max_fd > server->client[i]->conn_fd ? max_fd : server->client[i]->conn_fd;
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
//=============================
//      TODO
// You should add your code of reading thread_num from server.cfg here
//=============================
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
  int accept_config_total = 3;
  int accept_config[3] = {0, 0, 0};
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
    } else if (strcmp("thread_num",key) == 0) {
      server->arg.thread_num = (int) strtol(val, (char **)NULL, 10);
    accept_config[2] = 1;       
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

static int handle_download(csiebox_server *server,int conn_fd)
{
  FTS *fts;
  FTSENT *ftsent_head;
  FTSENT *p1,*p2;
  struct dirent *dir;
  DIR *Dir;
  char path[PATH_MAX];
  char *user_dir = get_user_homedir( server, server->client[conn_fd]);
  char *a[] = {user_dir,NULL};
  int wd;
  int numFD = 0;
  csiebox_protocol_status status;

  if( !(Dir = opendir(user_dir)))
  {
    fprintf(stderr,"opendir fail: %s\n",user_dir);
    return -1;
  }
  while( dir = readdir(Dir) )
  {
    fprintf(stderr,"%s\n",dir->d_name);
    numFD++;
  }
  closedir(Dir);
  fprintf(stderr,"Num of file and dir: %d\n",numFD);

  if( numFD < 3 )
  {
    // if cdir is empty, download from server
    fprintf(stderr,"empty dir, end download\n");
    return -1;
  }

  fts = fts_open( a, FTS_PHYSICAL |  FTS_NOCHDIR, NULL);
  if( fts == NULL )
  {
    fprintf(stderr, "fts fail\n");
    return -1;
  }
  
  while( ( ftsent_head = fts_read(fts)) != NULL )
  {
    ftsent_head = fts_children( fts,0);

    for( p1 = ftsent_head; p1 != NULL; p1 = p1->fts_link )
    {   
      memset(path,0,PATH_MAX);
      sprintf(path,"%s/%s",p1->fts_path,p1->fts_name);
      // if the file is hidden, ignore it
      if( p1->fts_name[0] == '.' )
      {
        continue;
      }
      if( strcmp(path, user_dir) ==0 )
      {
        continue;
      }
      switch( p1->fts_info )
      {
        case FTS_D:
          fprintf(stderr,"start sync dir %s\n",path);
          status = server_send_meta( path, conn_fd, server);
          if( status != CSIEBOX_PROTOCOL_STATUS_OK )
          {
            fprintf( stderr, "receive status fail\n");
          }
          break;
        case FTS_F:
          if( p1->fts_statp->st_nlink == 1)
          { 
            // there is no hard link
            fprintf(stderr, "start sync file %s\n",path);

            status = server_send_meta( path, conn_fd, server);
            if( status == CSIEBOX_PROTOCOL_STATUS_OK )
            {
              fprintf(stderr,"receive status ok\n");
            } 
            else if( status == CSIEBOX_PROTOCOL_STATUS_MORE )
            {
              server_send_file(path, conn_fd, server);
            }
            else
            {
              fprintf(stderr,"receive status fail\n");
            }
          }
          else
          {
            // there might be hard link
            p2 = ftsent_head;
            char path2[PATH_MAX];
            while(p2 != p1 )
            {
              memset(path2,0,PATH_MAX);
              sprintf(path2,"%s/%s",p2->fts_path,p2->fts_name);
              if( p2->fts_statp->st_ino == p1->fts_statp->st_ino )
              {
                // if it is a hardlink
                fprintf(stderr, "start sync hardlink %s\n",path);
                server_send_hardlink(path, path2, conn_fd, server);
                break;
              }
              p2 = p2->fts_link;
            }
            if( p2 == p1 )
            {
              fprintf(stderr, "start sync file %s\n",path);

              status = server_send_meta( path, conn_fd, server);
              if( status == CSIEBOX_PROTOCOL_STATUS_OK )
              {
                fprintf(stderr,"receive status ok\n");
              } 
              else if( status == CSIEBOX_PROTOCOL_STATUS_MORE )
              {
                server_send_file(path, conn_fd, server);
              }
              else
              {
                fprintf(stderr,"receive status fail\n");
              }
            }
          }       
          break;
        case FTS_SL:
          fprintf(stderr, "start sync symbolic %s\n",path);
          status = server_send_meta( path, conn_fd, server);
          if( status == CSIEBOX_PROTOCOL_STATUS_OK )
          {
            fprintf(stderr,"receive status ok\n");
          } 
          else if( status == CSIEBOX_PROTOCOL_STATUS_MORE )
          {
            server_send_symblink(path, conn_fd, server);
          }
          else
          {
            fprintf(stderr,"receive status fail\n");
          }
          break;
        case FTS_SLNONE:
          fprintf(stderr, "start sync symbolic %s\n",path);
          status = server_send_meta( path, conn_fd, server);
          if( status == CSIEBOX_PROTOCOL_STATUS_OK )
          {
            fprintf(stderr,"receive status ok\n");
          } 
          else if( status == CSIEBOX_PROTOCOL_STATUS_MORE )
          {
            server_send_symblink(path, conn_fd, server);
          }
          else
          {
            fprintf(stderr,"receive status fail\n");
          }
          break;
        default:
          fprintf(stderr,"Unknown type of fts_info\n");
          break;
      }
    }
  }
}