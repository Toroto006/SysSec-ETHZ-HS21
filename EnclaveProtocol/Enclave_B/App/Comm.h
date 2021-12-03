#ifndef _COMM_H_
#define _COMM_H_

#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Centrally define ports
#define PORT 8080
#define MSG_LEN 1024

int init_server();
int send_msg(char *message);
ssize_t recv_msg(char *buffer);
int close_server();

#endif /* !_COMM_H_ */