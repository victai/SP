#include "csiebox_common.h"

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <bsd/md5.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>

void md5(const char* str, size_t len, uint8_t digest[MD5_DIGEST_LENGTH]) {
  MD5_CTX ctx;
  MD5Init(&ctx);
  MD5Update(&ctx, (const uint8_t*)str, len);
  MD5Final(digest, &ctx);
}

int md5_file(const char* path, uint8_t digest[MD5_DIGEST_LENGTH]) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    return 0;
  }
  char buf[4096];
  size_t len;
  MD5_CTX ctx;
  MD5Init(&ctx);
  while ((len = read(fd, buf, 4096)) > 0) {
    MD5Update(&ctx, (const uint8_t*)buf, len);
  }
  MD5Final(digest, &ctx);
  close(fd);
  return 1;
}

int recv_message(int conn_fd, void* message, size_t len) {
  if (len == 0) {
    return 0;
  }
  int actual = recv(conn_fd, message, len, MSG_WAITALL);
  fprintf(stderr, "..........RECV_MESSAGE..........\n");
  // fprintf(stderr, "len: %d actual: %d\n", len, actual);
  return actual == len;
  // return recv(conn_fd, message, len, MSG_WAITALL) == len;
}

//used to receive complete header
int complete_message_with_header(
  int conn_fd, csiebox_protocol_header* header, void* result) {
  memcpy(result, header->bytes, sizeof(csiebox_protocol_header));
  int actual = recv(conn_fd,
              result + sizeof(csiebox_protocol_header),
              header->req.datalen,
              MSG_WAITALL);
  fprintf(stderr, "...........COMPLETE MESSAGE..........\n");
  fprintf(stderr, "len: %d actual: %d\n", header->req.datalen, actual);
  // return recv(conn_fd,
  //             result + sizeof(csiebox_protocol_header),
  //             header->req.datalen,
  //             MSG_WAITALL) == header->req.datalen;
}

int send_message(int conn_fd, void* message, size_t len) {
  if (len == 0) {
    return 0;
  }
  int actual = send(conn_fd, message, len, 0);
  fprintf(stderr, "..........SEND_MESSAGE..........\n");
  // fprintf(stderr, "len: %d actual: %d\n", len, actual);
  return actual == len;
  // return send(conn_fd, message, len, 0) == len;
}
