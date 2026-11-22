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
#include <time.h>
#include <stdbool.h>

// The address and port where the origin server listens. The reverse proxy will forward requests to this server.
#define HOST "127.0.0.1"
#define PORT "8081"
#define FORWARD "127.0.0.1"
#define FORWARD_PORT "8080"
#define MAX_BODY 1048576
#define MAX_CLIENTS 1024
#define MAX_HISTORY 1024
#define ACCESS_WINDOW 10 // 10 seconds for now for testing. will change later to probably 1 hour
#define MAX_ACCESS_THRESHOLD 10 // just say that 10 accesses in 10 seconds is reportable, can change later
#define MAX_VIOLATIONS 10 // 10 counts of rapid acesses gets you banned

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

// need to lock threads to prevent overriding for log.csv
static pthread_mutex_t logMutex = PTHREAD_MUTEX_INITIALIZER;

// need to lock threads to prevent overriding for the different clients
static pthread_mutex_t clientsMutex = PTHREAD_MUTEX_INITIALIZER;

// need to lock threads to prevent overriding for adding clients to the blacklist
static pthread_mutex_t blacklistMutex = PTHREAD_MUTEX_INITIALIZER;

// need to lock threads to prevent overriding for adding special endpoints
static pthread_mutex_t specialEndpointMutex = PTHREAD_MUTEX_INITIALIZER;

// need to lock threads to prevent overriding for adding ai detection endpoints
static pthread_mutex_t contentEndpointMutex = PTHREAD_MUTEX_INITIALIZER;


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

struct get_event {
    time_t timestamp;
    char path[1024]; // only the path so we don't have to worry about any memory from pointing to the request
    int sequence; // keep track of the sequence so that the counter doesn't try to count previous counts
};

struct client_info { // per client, has the client's IP address, the event history, and how many counts of access
    int used; // used for the clients array: 0 for empty, 1 for has a client
    char ip[INET6_ADDRSTRLEN];
    struct get_event history[MAX_HISTORY]; // client's requests
    size_t history_size;

    int violations;
    int last_special;
    int next_sequence;
};

static struct client_info clients[MAX_CLIENTS]; // list of clients

/**
 * Looks through the list of clients to see if the client we're looking at is already in the list and if not, adds them
 * @param ip IP address of the client we're looking for
 * @return the struct of the client we're looking for
 */
static struct client_info *getClient(const char *ip) {
    size_t unused = MAX_CLIENTS;

    // go through the client list to see if they're already in it
    for (size_t i = 0; i < MAX_CLIENTS; i++) {
        // if the client at index i is used and their IP address matches the IP we're comparing, that's the client we want
        if (clients[i].used && strcmp(clients[i].ip, ip) == 0) {
            return &clients[i];
        }

        // if we don't find the match, and we haven't changed unused yet, set unused to the index of the first empty spot
        if (!clients[i].used && unused == MAX_CLIENTS) {
            unused = i;
        }
    }

    // if we go through the entire list and we didn't change unused then something happened, like the list is full.
    if (unused == MAX_CLIENTS) {
        return NULL;
    }

    clients[unused].used = 1; // set used to 1 to say there's a client there now

    // copy the IP address into the IP address field
    strncpy(clients[unused].ip, ip,sizeof(clients[unused].ip) - 1);

    // replace last char with null
    clients[unused].ip[sizeof(clients[unused].ip) - 1] = '\0';

    // set the history_size to 0 since the client is just being added
    clients[unused].history_size = 0;
    clients[unused].violations = 0;
    clients[unused].last_special = 0;
    clients[unused].next_sequence = 0;

    return &clients[unused]; // return the new client
}
 
/**
 * Looks at the path of the request to see if it contains a specified endpoint
 * @param path path to look at and see if it contains any of the special endpoints
 * @return 1 for contains a special endpoint and 0 for does not contain the special endpoint
 */
static int isSpecialEndpoint(const char *path) {
    char line[512];

    pthread_mutex_lock(&specialEndpointMutex);
    FILE *file = fopen("specialEndpoints.csv", "r");

    if (file == NULL) {
        pthread_mutex_unlock(&specialEndpointMutex);
        return 0;
    }


    while (fgets(line, sizeof(line), file) != NULL) {
        char ln[256];
        if (sscanf(line, "%255[^,]", ln) == 1) {
            ln[strcspn(ln, "\r\n")] = '\0';
            if (ln[0] == '\0') {
                continue;
            }
            
            if (strcmp(path, ln) == 0)
            { // if the line is equal to the path
                fclose(file);
                pthread_mutex_unlock(&specialEndpointMutex);
                return 1;
            }
        }
    }

    fclose(file);
    pthread_mutex_unlock(&specialEndpointMutex);

    return 0;
}

/**
 * Adds an endpoint to the list of special endpoints, which identify bot behavior.
 * @param endpoint The endpoint to add
 */
static int addSpecialEndpoint(char *endpoint) {
    pthread_mutex_lock(&specialEndpointMutex);

    // "a" for append to write at the end of the file
    FILE *file = fopen("specialEndpoints.csv", "a");

    if (file == NULL) {
        pthread_mutex_unlock(&specialEndpointMutex);
        perror("error opening specialEndpoints.csv");
        return 1;
    }

    // add a client with IP address, reason, expiration time(0 is permanent)
    if (fprintf(file, "%s\n", endpoint) < 0) {
        fclose(file);
        pthread_mutex_unlock(&specialEndpointMutex);
        return 1;
    }

    fclose(file);
    pthread_mutex_unlock(&specialEndpointMutex);

    return 0;
}

/**
 * Adds an endpoint to the list of endpoints whose content is scanned for AI-generation.
 * @param endpoint The endpoint to add
 * @param index The index in input that is scanned
 */
static int addContentEndpoint(char *endpoint, char *index) {
    pthread_mutex_lock(&contentEndpointMutex);

    // "a" for append to write at the end of the file
    FILE *file = fopen("contentEndpoints.csv", "a");

    if (file == NULL) {
        pthread_mutex_unlock(&contentEndpointMutex);
        perror("error opening contentEndpoints.csv");
        return 1;
    }

    // add a client with IP address, reason, expiration time(0 is permanent)
    if (fprintf(file, "%s,%s\n", endpoint, index) < 0) {
        fclose(file);
        pthread_mutex_unlock(&contentEndpointMutex);
        return 1;
    }

    fclose(file);
    pthread_mutex_unlock(&contentEndpointMutex);

    return 0;
}

/**
 * Looks at the path of the request to see if it contains a specified endpoint
 * @param path path to look at and see if it contains any of the special endpoints
 * @return 1 for contains a special endpoint and 0 for does not contain the special endpoint
 */
static int scanForAI(const char *path, const char *request) {
    char line[512];

    pthread_mutex_lock(&contentEndpointMutex);
    FILE *file = fopen("contentEndpoints.csv", "r");

    if (file == NULL) {
        pthread_mutex_unlock(&contentEndpointMutex);
        perror("error opening contentEndpoints.csv");
        return 0;
    }


    while (fgets(line, sizeof(line), file) != NULL) {
        char ln[256];
        char content[256];
        if (sscanf(line, "%255[^,],%255[^,]", ln,content) == 2) {
            content[strlen(content) - 1] =  '\0';
            
            if (strcmp(path, ln) == 0)
            { // if the line is equal to the path

                //Scanning request for matching content index


                            fclose(file);
                            pthread_mutex_unlock(&contentEndpointMutex);
                            return 1;
            }
        }
    }

    fclose(file);
    pthread_mutex_unlock(&contentEndpointMutex);

    return 0;
}

/**
 * Counts access to a special endpoint and then rapid access to other pages
 * @param client specific client we're looking at
 * @param now time to compare the timestamp to for the access window
 * @param specialSequence the sequence that triggers the rapid access
 * @return false for is there's no special endpoint entries or if the pageCount after the access is less than the threshold. Return true for if the number of pages that are accessed within the window meets the threshold.
 */
static size_t countRapidAccess(const struct client_info *client, time_t now, int *specialSequence) {
    size_t latestSpecialIndex = MAX_HISTORY; // get the latest special endpoint access so then we can see rapid access to pages after

    *specialSequence = 0;
    // go through the client's history to get the age of each entry to see if it's inside the access window and if it is, see if it's an access to a special endpoint
    for (size_t i = 0; i < client->history_size; i++) {
        time_t age = now - client->history[i].timestamp;
        // if the age is within the access window and is one of the special endpoints, then add 1 to the number of special accesses
        if (age >= 0 && age <= ACCESS_WINDOW && isSpecialEndpoint(client->history[i].path))
        {
            latestSpecialIndex = i;
        }
    }
    
    // if you go through the history and the latestSpecialIndex doesn't change or it's the latest entry, then there wasn't rapid access
    if (latestSpecialIndex == MAX_HISTORY) {
        return 0;
    }
    
    *specialSequence = client->history[latestSpecialIndex].sequence;
    
    size_t pageCount = 0; // keeps track of how many pages were accessed after the special endpoint
    
    // start at the entry after the special endpoint to look at rapid access
    for (size_t i = latestSpecialIndex + 1; i < client->history_size; i++) {
        time_t age = now - client->history[i].timestamp;
        // if the entry has an age within the window then increment the count
        if (age >= 0 && age <= ACCESS_WINDOW && !isSpecialEndpoint(client->history[i].path)) {
            pageCount++;
        }
    }
    
    return pageCount;
}

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
 * Finds the body of a HTTP request by looking after
 * headers\r\n
 * \r\n
 * body
 * Find the empty line and use the content length to see how many bytes are in the body. *body points to the request/.
 * @param request the request we're looking at
 * @param requestLength number of bytes in the request
 * @param body pointer to the beginning of the body
 * @param bodyLength size of the body in bytes
 * @return 0 on success, -1 on any sort of error
 */
static int getPayload(const char *request, size_t requestLength, const char **body, size_t *bodyLength) {
    const char *bodyStart;
    long contentLength;

    // HTTP headers have a blank line followed by \r\n\r\n so then strstr points to the beginning of the sequence
    bodyStart = strstr(request, "\r\n\r\n");

    // error check(no \r\n\r\n)
    if (bodyStart == NULL) {
        return -1;
    }

    bodyStart += 4; // move past \r\n\r\n

    contentLength = getContentLength(request);

    // if getContentLength is <0, something happened and we shouldn't continue
    if (contentLength < 0) {
        return -1;
    }

    // make sure that the complete body is in the request by checking bytes before the body + bytes in the body > thrn the request
    if ((size_t)(bodyStart - request) + (size_t)contentLength > requestLength) {
        return -1;
    }


    // "return" a pointer to the body to look at the body in place
    *body = bodyStart;
    *bodyLength = (size_t)contentLength;

    return 0;
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

        if (received == 0) {
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
 * Function to add a client to the blacklist
 * @param clientIP IP address of the client to be banned
 * @param reason The reason the client is banned
 * @param expiration How long the client is banned
 * @return 0 on success, 1 on error
 */
static int addToBlacklist(char *clientIP, char *reason, time_t expiration) {
    pthread_mutex_lock(&blacklistMutex);

    // "a" for append to write at the end of the file
    FILE *file = fopen("blacklist.csv", "a");

    if (file == NULL) {
        pthread_mutex_unlock(&blacklistMutex);
        perror("error opening blacklist.csv");
        return 1;
    }

    // add a client with IP address, reason, expiration time(0 is permanent)
    if (fprintf(file, "%s,%s,%ld\n", clientIP, reason, expiration) < 0) {
        fclose(file);
        pthread_mutex_unlock(&blacklistMutex);
        return 1;
    }

    fclose(file);
    pthread_mutex_unlock(&blacklistMutex);

    return 0;
}

/**
 * Checks the blacklist file to see if a client is blacklisted
 * @param clientIP
 * @return 1 for blacklisted client, 0 otherwise
 */
static int isBlacklisted(const char *clientIP) {
    char line[512];
    char ip[INET6_ADDRSTRLEN];
    char reason[256];
    long expiration;

    pthread_mutex_lock(&blacklistMutex);
    // should be r instead of w+ because w+ erases the content first
    FILE *file = fopen("blacklist.csv", "r");

    if (file == NULL) {
        pthread_mutex_unlock(&blacklistMutex);
        return 0;
    }

    time_t now = time(NULL);

    while (fgets(line, sizeof(line), file) != NULL) {
        // sscanf returns how many values were read so if it's not 3, skip the line
        if (sscanf(line, "%45[^,],%255[^,],%ld", ip, reason, &expiration) == 3) {
            if (strcmp(clientIP, ip) == 0 && (expiration == 0 || expiration > now)) { // if the expiration is 0, then it's a permanent ban. If it's past now, the ban is still active
                fclose(file);
                pthread_mutex_unlock(&blacklistMutex);
                return 1;
            }
        }
    }

    fclose(file);
    pthread_mutex_unlock(&blacklistMutex);
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

static int scanTraffic(const char *clientIP, const char *path, size_t *rapidCountOut, int *violationCountOut, int *newViolationOut) {
//static int scanTraffic(char* clientIP, char* path, char* method, const char* request, size_t* rapidCountOut, int* violationCountOut, int* newViolationOut) {
    //int verdict = 0;

    //Check path
    

    //Check ip

    time_t now = time(NULL);
    struct client_info *client;
    int specialSequence = 0;
    size_t rapidCount;
    int violationCount;
    int newViolation = 0;
    int shouldBlacklist = 0;
    int blacklistResult;

    if (rapidCountOut != NULL) {
        *rapidCountOut = 0;
    }

    if (violationCountOut != NULL) {
        *violationCountOut = 0;
    }

    if (newViolationOut != NULL) {
        *newViolationOut = 0;
    }

    blacklistResult = isBlacklisted(clientIP);

    // moved up here so that it doesn't do unnecessary work if the client is blacklisted
    if (blacklistResult == 1) {
        return 1;
    }

    if (blacklistResult < 0) {
        return -1;
    }

    pthread_mutex_lock(&clientsMutex);

    client = getClient(clientIP);

    if (client == NULL) {
        pthread_mutex_unlock(&clientsMutex);
        return -1;
    }

    // get rid of oldest entry if the history is full
    if (client->history_size >= MAX_HISTORY) {
        memmove(client->history, client->history + 1, (MAX_HISTORY - 1) * sizeof(client->history[0]));
        client->history_size = MAX_HISTORY - 1;
    }

    // add to the client's history
    client->history[client->history_size].timestamp = now;

    strncpy(client->history[client->history_size].path, path, sizeof(client->history[client->history_size].path) - 1);

    client->history[client->history_size].path[sizeof(client->history[client->history_size].path) - 1] = '\0';

    client->history[client->history_size].sequence = ++client->next_sequence;

    client->history_size++;

    rapidCount = countRapidAccess(client, now, &specialSequence);

    if (rapidCount >= MAX_ACCESS_THRESHOLD && specialSequence != 0 && specialSequence != client->last_special) {
        client->violations++;
        client->last_special = specialSequence;
        newViolation = 1;
    }

    violationCount = client->violations;

    if (newViolation &&
        violationCount >= MAX_VIOLATIONS) {
        shouldBlacklist = 1;
        }

    if (rapidCountOut != NULL) {
        *rapidCountOut = rapidCount;
    }

    if (violationCountOut != NULL) {
        *violationCountOut = violationCount;
    }

    if (newViolationOut != NULL) {
        *newViolationOut = newViolation;
    }

    pthread_mutex_unlock(&clientsMutex);

    if (shouldBlacklist) {
        if (addToBlacklist(clientIP, "10 rapid-access violations", 0) != 0) {
            return -1;
        }

        return 2;
    }

    // If content scan path, check if content is ai generated.
    if (strcmp(method, "POST") == 0) {

    }

    
    return 0; //allowed!
}

/**
 * Returns a string verdict from integer
 * @param verdict integer verdict
 * @return A message
 */

static char* verdictReason(int verdict) {
    switch(verdict) {
        case 0: return "none";
        case 1: return "Blacklisted address";
        case 2: return "Suspicious activity";
        case 3: return "AG-Generated content";
        default: return "Server error";
    }
}

/**
 * Logs an event(access to a special endpoint)
 * @param ip ip address of the requesting client
 * @param method method of the request
 * @param path requested path
 * @param flagged whether the access was flagged
 * @param reason why we logged the access
 */
static int logEvent(const char *ip, const char *method, const char *path, const int flagged, const char *reason) {
    pthread_mutex_lock(&logMutex); // need to lock so that multiple threads try to write to log.csv at the same time
    FILE *logFile;
    time_t now;
    struct tm timeInfo;
    char timestamp[64];

    now = time(NULL);
    localtime_r(&now, &timeInfo);

    strftime(timestamp,
             sizeof(timestamp),
             "%Y-%m-%d %H:%M:%S",
             &timeInfo);

    logFile = fopen("log.csv", "a");

    if (logFile == NULL) {
        pthread_mutex_unlock(&logMutex);
        perror("fopen log.csv");
        return 1;
    }
    //Switching formatting to csv for ease of parsing later.
    //timestamp, date, ip, method, path, flagged, reason
    fprintf(logFile, "%ld,%s,%s,%s,%s,%d,%s\n", now,timestamp, ip, method, path, flagged, reason);
    
    //fprintf(logFile, "[%s] IP=%s Method=%s Path=%s Reason=%s\n", timestamp, ip, method, path, reason);

    fclose(logFile);

    pthread_mutex_unlock(&logMutex);
    return 0;
}

/**
 * Pangram has different APIs for text and images so need to make sure to one used with text has text
 * @param request the HTTP request
 * @return 0 on success for a content type of text or json
 */
static int isText(const char *request) {
    return strcasestr(request, "Content-Type: text/") != NULL || strcasestr(request, "Content-Type: application/json") != NULL;
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
static void serveRequest(int fd, const char *request, size_t requestLength, const char *connection, char* clientIP) {
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
        //char adminPath[PATH_MAX];g
        //snprintf(adminPath, sizeof(adminPath), "%s/admin.html", webroot);

        if (returnFile(fd, connection, "admin.html") == 0)
        { // This is correct because it's on the side of the reverse proxy, not the end server.
            return;
        }

        buildResponse(fd, 500, 0, "text/plain", "close");
        return;
    } else if (strcmp(path, "/reverse_proxy/get_data") == 0) { //Get data to populate admin webpage
        if (returnFile(fd, connection, "log.csv") == 0) { //Placeholder
            return;
        }

        buildResponse(fd, 500, 0, "text/plain", "close");
        return;
    } else if (strcmp(path, "/reverse_proxy/get_blacklist") == 0) { //Get data to populate admin webpage
        if (returnFile(fd, connection, "blacklist.csv") == 0) { //Placeholder
            return;
        }

        buildResponse(fd, 500, 0, "text/plain", "close");
        return;
    } else if (strcmp(path, "/reverse_proxy/get_special_endpoints") == 0) { //Get data to populate admin webpage
        if (returnFile(fd, connection, "specialEndpoints.csv") == 0) { //Placeholder
            return;
        }

        buildResponse(fd, 500, 0, "text/plain", "close");
        return;
    } else if (strncmp(path, "/reverse_proxy/add_special_endpoint", strlen("/reverse_proxy/add_special_endpoint")) == 0) { //Get data to populate admin webpage
        char halfPath[1024];
        char arg[1024];
        if (sscanf(path, "%1023[^=]=%1023[^\r\n]", halfPath, arg) != 2) {
            buildResponse(fd, 400, 0, "text/plain", connection);
            return;
        }
        printf("%s\n", arg);
        if (strlen(arg) != 0)
        {
            if (addSpecialEndpoint(arg) == 0) {
                buildResponse(fd, 200, 0, "text/plain", "close");
                return;
            }
        }

        buildResponse(fd, 500, 0, "text/plain", "close");
        return;
    }

    // Verdict of 0 = passed analysis, allowed access. Verdict otherwise determines reason for denied request.
    size_t rapidCount = 0;
    int violationCount = 0;
    int newViolation = 0;

    verdict = scanTraffic(clientIP, path, &rapidCount, &violationCount, &newViolation);

    if (newViolation) {
        char reason[256];
        snprintf(reason, sizeof(reason), "Rapid violation #%d: %zu requests in %d seconds", violationCount, rapidCount, ACCESS_WINDOW);
        logEvent(clientIP, method, path, 2, reason);
    }

    if (verdict == 1 || verdict == 2) {
        if (!newViolation) {
            logEvent(clientIP, method, path, verdict, verdictReason(verdict));
        }
        buildResponse(fd, 403, 0, "text/plain", connection);
        return;
    }

    //Traffic validated, make forwarded request and buffer back
    //Browser just requests this repeatedly, best not to log
    if (!newViolation && verdict == 0 && strcmp(path, "/favicon.ico") != 0) {
        logEvent(clientIP, method, path, 0, "none");
    }

    // these request types almost always have a body(delete only sometimes)
    if ((strcmp(method, "POST") == 0 || strcmp(method, "PUT") == 0 || strcmp(method, "PATCH") == 0 || strcmp(method, "DELETE") == 0) && isText(request)) {
        const char *payload;
        size_t payloadLength;
        char pangramResult[128];

        if (getPayload(request, requestLength, &payload, &payloadLength) == 0 && payloadLength > 0) {

            int pangramStatus = checkTextWithPangram(payload, payloadLength, pangramResult, sizeof(pangramResult));

            // checkTextWithPangram returns 0 if nothing went wrong
            if (pangramStatus == 0) {
                // put the result of the AI check. flag the AI content but don't ban, leave that to the admin
                logEvent(clientIP, method, path,2, pangramResult);
            } else {
                logEvent(clientIP, method, path,0, "Pangram error");
            }
        }
    }

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
 * convert the socket address of a client from binary to readable IP address
 * @param address pointer to the client's sockaddr_storage address
 * @param output output buffer
 * @param outputSize size of buffer
 * @return 0 on success, -1 if address cannot be converted or is not supported
 */
static int getIPAddr(const struct sockaddr_storage *address, char *output, size_t outputSize) {
    void *addressData;

    if (address->ss_family == AF_INET) { // what kind of address is this
        struct sockaddr_in *ipv4;

        ipv4 = (struct sockaddr_in *)address;
        addressData = &ipv4->sin_addr; // sin_addr = IPv4 address
    } else if (address->ss_family == AF_INET6) { // what kind of address is it
        struct sockaddr_in6 *ipv6;

        ipv6 = (struct sockaddr_in6 *)address;
        addressData = &ipv6->sin6_addr; // sin6_addr = IPv6 address
    } else {
        return -1;
    }

    if (inet_ntop(address->ss_family, addressData, output, outputSize) == NULL) { // inet_ntop = the conversion
        return -1;
    }

    return 0;
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
    char clientIP[INET6_ADDRSTRLEN]; // minimun buffer needed for a IPv6
    char request[MAX_REQUEST];
    struct timeval timeout = { TIMEOUT, 0 };


    if (getIPAddr(&args->address, clientIP, sizeof(clientIP)) < 0) {
        strcpy(clientIP, "unknown");
    }


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
            break;
        }

        if (!persistent || closeRequest(request)) {
            serveRequest(clientFd, request, (size_t)result, "close", clientIP);
            break;
        }

        serveRequest(clientFd, request, (size_t)result, "keep-alive", clientIP);
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
    const char *mode = argc > 1 ? argv[1] :
            "persistent";
            int persistent = strcmp(mode, "persistent") == 0;
            int single_threaded = strcmp(mode, "single-threaded") == 0;
            int listener;

            if (!persistent && !single_threaded && strcmp(mode, "non-persistent") != 0)
            {
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
