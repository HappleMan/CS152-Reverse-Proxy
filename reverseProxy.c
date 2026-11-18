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

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L // suggested these two and I'm not sure why

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
#include <sys/stat.h>
#include <stddef.h>
#include <limits.h>
#include <pthread.h>
#include <sys/time.h>
#include <ctype.h>
#include <limits.h>

// The address and port where the origin server listens. The reverse proxy will forward requests to this server.
#define HOST "127.0.0.1"
#define PORT "8081"
#define FORWARD "127.0.0.1"
#define FORWARD_PORT "8080"
#define MAX_BODY 1048576

// Default directory containing files served by the origin server.
#define ROOT "./www"

// Number of seconds an idle connection remains open.
#define TIMEOUT 10

// Size of buffer for reading files and sending responses.
#define BUFFERSIZE 8192

// Maximum size of incoming HTTP header allowed.
#define MAX_REQUEST (16384 + MAX_BODY)

// Canonical path of the webroot, initialized in main.
static char webroot[PATH_MAX];

/*
 * Information passed from the main accept loop to a client thread.
 *
 * fd = Connected client socket.
 * address = Client's network address.
 * persistent = Whether the connection may handle multiple requests.
 */
struct connection_args { // instead of the dict
    int fd;
    struct sockaddr_storage address;
    int persistent;
};

// mimic the sendall function
// https://stackoverflow.com/questions/11213579/python-sendall-vs-c-write idea for making this
/**
 * Sends all bytes in a buffer through a socket.
 *
 * send() is allowed to send fewer bytes than requested, so this function
 * repeatedly calls send() until the entire buffer has been transmitted.
 *
 * @param fd     Connected socket file descriptor.
 * @param data   Buffer containing the bytes to send.
 * @param len    Number of bytes to send.
 *
 * @return 0 on success, or -1 if the connection fails.
 */
static int sendall(int fd, const void *data, size_t len) {
    const char *bytes = (const char *)data;
    ssize_t sent = 0;
    // https://man7.org/linux/man-pages/man2/send.2.html
    while (sent < len) {
        ssize_t n = send(fd, bytes + sent, len - sent, 0);
        if (n < 0 || n == 0) return -1;
        sent += n;
    }
    return 0;
}

// MIME type map — maps file extensions to Content-Type values
/**
 * Determines the MIME type for a file based on its extension.
 *
 * The MIME type is sent to the client in the HTTP Content-Type header.
 *
 * @param path File path whose extension should be examined.
 *
 * @return A string containing the appropriate MIME type.
 */
static const char *mimeType(const char* path) {
    const char *exten = strrchr(path, '.'); // Files have an extension to determine their MIME type.
    if (exten == NULL) return "text/html"; // placeholder
    if (strcmp(exten, ".html") == 0) return "text/html";
    if (strcmp(exten, ".txt") == 0) return "text/plain";
    if (strcmp(exten, ".css") == 0) return "text/css";
    if (strcmp(exten, ".js") == 0) return "application/javascript";
    if (strcmp(exten, ".jpg") == 0) return "image/jpeg";
    if (strcmp(exten, ".jpeg") == 0) return "image/jpeg";
    if (strcmp(exten, ".png") == 0) return "image/png";
    if (strcmp(exten, ".ico") == 0) return "image/x-icon";

    return "text/plain"; // maybe placeholder
}

/**
 * Converts an HTTP status code into its phrase.
 *
 * For example, status code 200 corresponds to "OK", while 404 corresponds
 * to "Not Found".
 *
 * @param status HTTP status code.
 *
 * @return The phrase associated with the status code.
 */
static const char *statusCode(const int status) {
    switch (status) {
        case 200: return "OK";
        case 400: return "Bad Request";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 500: return "Internal Server Error";
        case 413: return "Payload Too Large";
        case 502: return "Bad Gateway";
        default: return "Error";
    }
}

/**
 * Constructs and sends the HTTP response headers.
 *
 * The response body is sent separately by serveRequest(). This function
 * sends the status line, Content-Length, Content-Type, and Connection
 * headers, followed by the blank line that ends the HTTP header section.
 *
 * @param fd             Connected client socket.
 * @param status         HTTP status code.
 * @param contentLength  Number of bytes in the response body.
 * @param contentType   MIME type of the response body.
 * @param connection     Connection behavior, such as "close" or
 *                       "keep-alive".
 *
 * @return 0 on success, or -1 if the headers cannot be sent.
 */
static int buildResponse(int fd, int status, size_t contentLength, const char *contentType, const char *connection) {
    char buf[1024];
    int len = snprintf(buf, sizeof(buf),
        "HTTP/1.1 %d %s\r\n"
        "Content-Length: %zu\r\n"
        "Content-Type: %s\r\n"
        "Connection: %s\r\n"
        "\r\n", status, statusCode(status), contentLength, contentType, connection);
    if (len < 0 || len >= sizeof(buf)) {
        return -1;
    }
    return sendall(fd, buf, (size_t)len);
}

/**
 * Helper to figure out the content length so we don't rely on \r\n\r\n
 * @param request Destination buffer for the raw request.
 * @return content length
 */
static long getContentLength(const char *request) {
    char *end;

    const char *header = strcasestr(request, "Content-Length:");

    if (header == NULL) {
        return 0;
    }

    const char *value = header + strlen("Content-Length:");

    while (*value != '\0' && isspace((unsigned char)*value)) {
        value++;
    }

    errno = 0;
    long length = strtol(value, &end, 10);

    if (value == end ||
        errno == ERANGE ||
        length < 0 ||
        length > MAX_BODY) {
        return -1;
        }

    return length;
}
/**
 * Reads an HTTP request from a connected client socket.
 *
 * This function reads until it finds the end of the HTTP request headers,
 * represented by "\r\n\r\n". It does not process the request; it only
 * collects the raw request bytes.
 *
 * @param fd             Connected client socket.
 * @param request        Destination buffer for the raw request.
 * @param requestLength  Capacity of the request buffer.
 *
 * @return Number of bytes read, 0 if the client disconnects, or -2 if the
 *         request headers are too large.
 */
static int readRequest(int fd, char *request, size_t requestLength) {
    size_t lookedAt = 0; // total
    size_t headerLength = 0;
    long contentLength = 0;
    char *headerEnd;

    while (lookedAt + 1 < requestLength) {
        // https://man7.org/linux/man-pages/man2/recv.2.html
        ssize_t n = recv(fd, request + lookedAt, requestLength - lookedAt - 1, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }

        if (n <= 0) return (int)n;

        lookedAt += (size_t)n;
        request[lookedAt] = '\0';
        headerEnd = strstr(request, "\r\n\r\n");
        if (headerEnd != NULL) {
            headerLength = (size_t)(headerEnd - request) + 4;
            break;
        }
    }

    if (headerLength == 0) {
        return -2; // request header too big
    }

    contentLength = getContentLength(request);

    if (contentLength < 0) {
        return -3; // content(header + body) too big
    }

    if (headerLength + (size_t)contentLength >= requestLength) {
        return -3; // entire request does not fit
    }

    while (lookedAt < headerLength + (size_t)contentLength) {
        ssize_t received = recv(fd, request + lookedAt, requestLength - lookedAt - 1, 0);
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }

        if (received = 0) {
            return -1;
        }

        lookedAt += (size_t)received;
        request[lookedAt] = '\0';
    }

    return (int)lookedAt;
}


// https://safeguard.sh/resources/blog/path-traversal-prevention-in-c-with-pathgetfullpath
// https://man7.org/linux/man-pages/man3/realpath.3.html
/**
 * Checks whether a canonical file path remains inside the web root.
 *
 * realpath() resolves ".." components and symbolic links before this
 * function is called. Comparing the canonical paths prevents a client from
 * accessing files outside the configured web directory.
 *
 * @param path Canonical path of the requested file.
 *
 * @return Nonzero if the path is inside the web root; otherwise zero.
 */
static int pathCheck(const char *path) {
    size_t len = strlen(webroot);
    return strcmp(path, webroot) == 0 || (strncmp(path, webroot, len) == 0 && path[len] == '/');
}


/**
 * Returns a file from the directory to client. Built for admin panel and custom error pages
 *
 * @param fd          Connected client socket.
 * @param request     Raw HTTP request.
 * @param connection  Value for the HTTP Connection header.
 * @param path        The path of the file.
 */
// const char *request
static int returnFile(int fd, const char *connection, char *path) {
    FILE *file;
    struct stat fileInfo;
    char buf[BUFFERSIZE];
    size_t bytesRead;

    if (stat(path, &fileInfo) < 0 || !S_ISREG(fileInfo.st_mode)) {
        return 1;
    }

    file = fopen(path, "rb");
    if (file == NULL) {
        return 1;
    }

    if (buildResponse(fd, 200, (size_t)fileInfo.st_size, mimeType(path), connection) < 0) {
        fclose(file);
        return 2;
    }

    // Load the file in chunks, needed for large files.
    while ((bytesRead = fread(buf, 1, sizeof(buf), file)) > 0) {
        if (sendall(fd, buf, bytesRead) < 0)
            break;
    }
    fclose(file);
    return 0;
}

/**
 * Processes information about the accessing client to determine if the request to the server is legitimate.
 * 
 * This function will use access times as well as content analysis to determine if the accessor is a bot or scraper.
 *
 * @param fd          Connected client socket.
 * @param request     Raw HTTP request.
 * @param connection  Value for the HTTP Connection header.
 * @param path        The path of the client's request.
 */
// static void scanTraffic(int fd, const char *request, const char *connection, char *path) {

static int scanTraffic(const char *request) {
    int verdict = 0;

    
    return verdict;
}


/**
 * Processes one HTTP request and sends the appropriate response.
 *
 * This function parses the request line, verifies that the method is GET,
 * safely resolves the requested file path, opens the file, sends the HTTP
 * headers, and streams the file contents to the client.
 *
 * @param fd          Connected client socket.
 * @param request     Raw HTTP request.
 * @param connection  Value for the HTTP Connection header.
 */
static void serveRequest(int fd, const char *request, size_t requestLength, const char *connection) {
    char buf[BUFFERSIZE];
    char method[16];
    char version[16];
    char path[1024];
    char fullPath[8192];
    //FILE *file;
    //size_t bytesRead;
    struct stat fileInfo;
    //char canonPath[PATH_MAX];
    int verdict;

    // Parse the method, URL path, and HTTP version from the request line.
    int fields = sscanf(request, "%15s %1023s %15s", method, path, version);
    if (fields != 3) {
        buildResponse(fd, 400, 0, "text/plain", "close");
        return;
    }

    if (strcmp(method, "GET") != 0 && strcmp(method, "HEAD") != 0 && strcmp(method, "POST") != 0 && strcmp(method, "PUT") != 0 &&
        strcmp(method, "PATCH") != 0 && strcmp(method, "DELETE") != 0 && strcmp(method, "OPTIONS") != 0) {
        buildResponse(fd, 405, 0, "text/plain", "close");
        return;
    }

    // https://man7.org/linux/man-pages/man3/realpath.3.html
    /*
     * Reject the request if:
     * The URL is not an absolute path.
     * It exceeds fullPath.
     */
    if (path[0] != '/' || snprintf(fullPath, sizeof(fullPath),
        "%s%s", webroot, path) >= sizeof(fullPath)) {
        buildResponse(fd, 404, 0, "text/plain", connection);
        return;
    }

    //Determine if requesting the admin panel. I was gonna use a switch case but C switch and strings are not friends.
    if (strcmp(path, "/reverse_proxy/admin") == 0) { // TODO: Maybe add authentication
        char adminPath[PATH_MAX];
        snprintf(adminPath, sizeof(adminPath), "%s/admin.html", webroot);
        if (returnFile(fd, connection, adminPath) == 0) {
            return;
        }

        buildResponse(fd, 500, 0, "text/plain", "close");
        return;
    }// TODO: accept payloads for admin panel requests

    //Verdict of 0 = passed analysis, allowed access. Verdict otherwise determines reason for denied request.
    if ((verdict = scanTraffic(request)) != 0) {
        buildResponse(fd, 403, 0, "text/plain", connection); // TODO: Replace forbidden response with custom response page
        return;
    } 

    //Traffic validated, make forwarded request and buffer back

    // prob need to delete
    //char redirectUrl[8192], redirectRequest[8192];
    //sprintf(redirectUrl, "%s%s", "https://example.com", path);

    //make forwarded request, write to file
    //https://stackoverflow.com/questions/11208299/how-to-make-an-http-get-request-in-c-without-libcurl

    struct sockaddr_in addr;
    int fwsock;
    
    fwsock = socket(AF_INET, SOCK_STREAM, 0);
    if (fwsock < 0) {
        buildResponse(fd, 500, 0, "text/plain", "close");
        return;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);

    inet_pton(AF_INET, FORWARD, &addr.sin_addr);

    if (connect(fwsock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fwsock);
        buildResponse(fd, 502, 0, "text/plain", "close");
        return;
    }

    /*
    // form request
    int reqlen = snprintf(redirectRequest, 1024, "GET %s HTTP/1.1\r\nHost: %s:%s\r\nConnection: close\r\n\r\n", path, FORWARD, FORWARD_PORT);
    // write request

    ssize_t nbytes_total, nbytes_last;
    nbytes_total = 0;
    while (nbytes_total < reqlen)
    {
        nbytes_last = write(fwsock, redirectRequest + nbytes_total, reqlen - nbytes_total);
        if (nbytes_last < -1) {
            perror("write");
            //return;
        }
        nbytes_total += nbytes_last;
    }
    */
    // I'm pretty sure you just need to do this
    if (sendall(fwsock, request, requestLength) < 0) {
        close(fwsock);
        buildResponse(fd, 502, 0, "text/plain", "close");
        return;
    }
    
    // read response directly to buffer
    int n;
    
    while ((n = read(fwsock, buf, BUFFERSIZE)) > 0) {
        if (sendall(fd, buf, n) < 0)
        
        break;
    }
    
    //Must send after for exact content size.
    // if we do the above, then we don't need this
   // buildResponse(fd, 200, n, "text/html", connection); //specific minetype can be adjusted later, for now assuming most is gonna be html
    close(fwsock);
}

/**
 * Determines whether an HTTP request asks the server to close the connection.
 *
 * Persistent HTTP/1.1 connections remain open unless the client sends a
 * Connection: close header.
 *
 * @param request Raw HTTP request.
 *
 * @return Nonzero if the request contains Connection: close; otherwise zero.
 */
static int closeRequest(const char *request) {
    const char *header = strcasestr(request, "Connection:");
    if (header == NULL)
        return 0;
    return strncasecmp(header + strlen("Connection:"), " close", (size_t)6) == 0 ||
           strcasestr(header, "close") != NULL;
}

/**
 * Handles one client connection.
 *
 * In persistent mode, this function can process multiple HTTP requests on
 * the same connection. In non-persistent mode, it processes one request and
 * closes the connection. A receive timeout prevents idle persistent
 * connections from remaining open forever.
 *
 * @param raw_args Pointer to a connection_args structure allocated by main().
 *
 * @return Always returns NULL because it is used as a pthread start routine.
 */
static void *connectThread(void *raw_args)
{
    struct connection_args *args = raw_args;
    int clientFd = args->fd;
    int persistent = args->persistent;
    char request[MAX_REQUEST];
    struct timeval timeout = { TIMEOUT, 0 };

    // The accepted socket is stored in heap memory because the main thread passes it to a detached thread. The thread is responsible for freeing the structure and closing the socket.
    free(args);
    // Stops a persistent client from keeping the connection open without sending another request.
    if (persistent)
        setsockopt(clientFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    // https://linux.die.net/man/2/setsockopt
    // SOL_SOCKET is used as the level argument to configure options at the socket API layer, it means that the option we want to modify is protocol-independent and is handled by the socket framework
    // https://man7.org/linux/man-pages/man7/socket.7.html
    // SO_RCVTIMEO limits how long a blocking receive operation waits for incoming data. This prevents an idle persistent client from occupying a thread forever.

    // ;; for persistent mode, it should continue to process requests until the client closes the connection or the connection times out.
    for (;;) {
        int result = readRequest(clientFd, request, sizeof(request));
        if (result == 0)
            break;
        if (result == -1)
            break;
        if (result == -2) {
            buildResponse(clientFd, 400, 0, "text/plain", "close");
            break;
        }
        if (result == -3) {
            buildResponse(clientFd, 413, 0, "text/plain", "close");
        }

        if (!persistent || closeRequest(request)) {
            serveRequest(clientFd, request, (size_t)result, "close");
            break;
        }

        serveRequest(clientFd, request, (size_t)result, "keep-alive");
    }

    close(clientFd);
    return NULL;
}

/**
 * Creates, configures, binds, and listens on the server socket.
 *
 * getaddrinfo() converts the host and port strings into an address structure.
 * socket() creates the endpoint, bind() assigns the address, and listen()
 * marks the socket as a passive listening socket.
 *
 * @return Listening socket file descriptor, or -1 if setup fails.
 */
static int makeListener(void)
{
    struct addrinfo hints;
    struct addrinfo *results = NULL;
    struct addrinfo *rp;
    int fd = -1;
    int yes = 1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    // Convert HOST and PORT into usable socket address structures.
    if (getaddrinfo(HOST, PORT, &hints, &results) != 0)
        return -1;

    for (rp = results; rp != NULL; rp = rp->ai_next) {
        // Create the listening socket.
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0)
            continue;
        // Allow the port to be reused after the server exits
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        // SO_REUSEADDR is a socket option that allows a socket to forcibly bind to a port that is still tied up by an old connection.
        // https://learn.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse
        // Assign the IP address and port to the socket.
        if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0 &&
            listen(fd, 64) == 0) // Mark the socket as ready to accept incoming connections.
            break;
        close(fd);
        fd = -1;
    }

    freeaddrinfo(results);
    return fd;
}

int main(int argc, char **argv)
{
    // Get the mode from the command-line argument
    const char *mode = argc > 1 ? argv[1] : "persistent";
    int persistent = strcmp(mode, "persistent") == 0;
    int single_threaded = strcmp(mode, "single-threaded") == 0;
    int listener;

    if (!persistent && !single_threaded && strcmp(mode, "non-persistent") != 0) {
        return EXIT_FAILURE;
    }

    // Resolve the web root to give pathCheck() a directory to compare with files.
    const char *rootArgument = argc > 2 ? argv[2] : ROOT;

    if (realpath(rootArgument, webroot) == NULL) {
        perror("invalid web root");
        return EXIT_FAILURE;
    }

    signal(SIGPIPE, SIG_IGN);
    listener = makeListener();
    if (listener < 0) {
        perror("could not create listener");
        return EXIT_FAILURE;
    }

    printf("Reverse Proxy listening at http://%s:%s\n", HOST, PORT);
    printf("Redirecting traffic to http://%s:%s\n", FORWARD, FORWARD_PORT);

    for (;;) {
        struct connection_args *args;
        pthread_t thread;
        socklen_t length;

        args = calloc(1, sizeof(*args));
        if (args == NULL)
            continue;

        length = sizeof(args->address);
        // Wait for client connection.
        args->fd = accept(listener, (struct sockaddr *)&args->address, &length);
        if (args->fd < 0) {
            free(args);
            if (errno == EINTR)
                continue;
            perror("accept");
            break;
        }
        args->persistent = persistent;

        if (single_threaded) {
            connectThread(args);
        } else if (pthread_create(&thread, NULL, connectThread, args) == 0) { // https://man7.org/linux/man-pages/man3/pthread_create.3.html
            pthread_detach(thread); // https://man7.org/linux/man-pages/man3/pthread_detach.3.html
        } else {
            close(args->fd);
            free(args);
        }
    }

    close(listener);
    return EXIT_FAILURE;
}
