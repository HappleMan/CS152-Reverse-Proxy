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
#include <errno.h>
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

// mimic the sendall function
// https://stackoverflow.com/questions/11213579/python-sendall-vs-c-write idea for making this
static int sendall(int fd, const void *data, size_t len) {
    const char *bytes = (const char *)data;
    ssize_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, bytes + sent, len - sent, 0);
        if (n < 0 || n == 0) return -1;
        sent += n;
    }
    return 0;
}

// MIME type map — maps file extensions to Content-Type values
static const char *mimeType(const char* path) {
    const char *exten = strrchr(path, '.'); // links have an extension to say what type they are
    if (exten == NULL) return "text/plain"; // placeholder
    if (strcmp(exten, "html")) return "text/html";
    if (strcmp(exten, ".html")) return "text/html";
    if (strcmp(exten, ".txt")) return "text/plain";
    if (strcmp(exten, ".css")) return "text/css";
    if (strcmp(exten, "js")) return "application/javascript";
    if (strcmp(exten, ".jpg")) return "image/jpeg";
    if (strcmp(exten, ".jpeg")) return "image/jpeg";
    if (strcmp(exten, ".png")) return "image/png";
    if (strcmp(exten, ".ico")) return "image/x-icon";

    return "text/plain"; // maybe placeholder
}

static const char *statusCode(const int status) {
    switch (status) {
        case 200: return "OK";
        case 400: return "Bad Request";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 500: return "Internal Server Error";
        default: return "Error";
    }
}

static int buildResponse(int fd, int status, size_t contentLength, const char *contentType, const void *connection) {
    char buf[1024];
    int len = snprintf(buf, sizeof(buf),
        "HTTP/1.1 %d %s\r\n"
        "Content-Length: %zu\r\n"
        "Content-Type\r\n"
        "ConnectionL %s\r\n"
        "\r\n", status, statusCode(status), contentLength, contentLength, connection);
    if (len < 0 || len >= sizeof(buf)) {
        return -1;
    }
    return sendall(fd, buf, (size_t)len);
}

static int readRequest(int fd, char *request, size_t requestLength) {
    size_t lookedAt = 0;

    while (lookedAt + 1 < requestLength) {
        ssize_t n = recv(fd, request + lookedAt, requestLength - lookedAt - 1, 0);
        if (n < 0) continue;
        if (n <= 0) return (int)n;

        lookedAt += n;
        request[lookedAt] = '\0';
        if (strstr(request, "\r\n\r\n") != NULL) {
            return (int)lookedAt;
        }
    }

    return -3; // request header too big
}