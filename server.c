// https://dev.to/jeffreythecoder/how-i-built-a-simple-http-server-from-scratch-using-c-739

/* https://beej.us/guide/bgnet/
create socket
bing socket to address
listen on address
block on accept until connection is made
read on connected socket
figure out how to respond
write back on the connected socket
close the connection
go back to blocking on accept
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <unistd.h>
#include <stddef.h>
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L // suggested these two and I'm not sure why

#define HOST "127.0.0.1"
#define PORT 8080
#define WEBROOT "./www"
#define TIMEOUT 10

static int send_all(int fd, const void *data, size_t len) {

}