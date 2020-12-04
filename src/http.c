#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <liburing.h>
#include <arpa/inet.h>

#include "http.h"
#include "logger.h"
#include "timer.h"

#define Queue_Depth 512
#define MAXLINE 8192
#define SHORTLINE 512
#define WEBROOT "./www"


#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

struct io_uring ring;

static ssize_t writen(int fd, void *usrbuf, size_t n)
{
    ssize_t nwritten;
    char *bufp = usrbuf;

    for (size_t nleft = n; nleft > 0; nleft -= nwritten) {
        if ((nwritten = write(fd, bufp, nleft)) <= 0) {
            if (errno == EINTR) /* interrupted by sig handler return */
                nwritten = 0;   /* and call write() again */
            else {
                log_err("errno == %d\n", errno);
                return -1; /* errrno set by write() */
            }
        }
        bufp += nwritten;
    }

    return n;
}

static char *webroot = NULL;

typedef struct {
    const char *type;
    const char *value;
} mime_type_t;

static mime_type_t mime[] = {{".html", "text/html"},
                             {".xml", "text/xml"},
                             {".xhtml", "application/xhtml+xml"},
                             {".txt", "text/plain"},
                             {".pdf", "application/pdf"},
                             {".png", "image/png"},
                             {".gif", "image/gif"},
                             {".jpg", "image/jpeg"},
                             {".css", "text/css"},
                             {NULL, "text/plain"}};

int init_ring()
{
    int ret = io_uring_queue_init(Queue_Depth, &ring, 0) ;
    return ret ;
}

struct io_uring_cqe *wait_cqe()
{
    struct io_uring_cqe *cqe;
    int ret = io_uring_wait_cqe(&ring, &cqe) ;
    assert(ret>0 && "io_uring_wait_cqe");

    io_uring_cqe_seen(&ring, cqe) ;
    return cqe;
}

static void parse_uri(char *uri, int uri_length, char *filename)
{
    assert(uri && "parse_uri: uri is NULL");
    uri[uri_length] = '\0';

    /* TODO: support query string, i.e.
     *       https://example.com/over/there?name=ferret
     * Reference: https://en.wikipedia.org/wiki/Query_string
     */
    char *question_mark = strchr(uri, '?');
    int file_length;
    if (question_mark) {
        file_length = (int) (question_mark - uri);
        debug("file_length = (question_mark - uri) = %d", file_length);
    } else {
        file_length = uri_length;
        debug("file_length = uri_length = %d", file_length);
    }

    /* uri_length can not be too long */
    if (uri_length > (SHORTLINE >> 1)) {
        log_err("uri too long: %.*s", uri_length, uri);
        return;
    }

    strcpy(filename, webroot);
    debug("before strncat, filename = %s, uri = %.*s, file_len = %d", filename,
          file_length, uri, file_length);
    strncat(filename, uri, file_length);

    char *last_comp = strrchr(filename, '/');
    char *last_dot = strrchr(last_comp, '.');
    if (!last_dot && filename[strlen(filename) - 1] != '/')
        strcat(filename, "/");

    if (filename[strlen(filename) - 1] == '/')
        strcat(filename, "index.html");

    debug("served filename = %s", filename);
}

static void do_error(int fd,
                     char *cause,
                     char *errnum,
                     char *shortmsg,
                     char *longmsg)
{
    char header[MAXLINE], body[MAXLINE];

    sprintf(body,
            "<html><title>Server Error</title>"
            "<body>\n%s: %s\n<p>%s: %s\n</p>"
            "<hr><em>web server</em>\n</body></html>",
            errnum, shortmsg, longmsg, cause);

    sprintf(header,
            "HTTP/1.1 %s %s\r\n"
            "Server: seHTTPd\r\n"
            "Content-type: text/html\r\n"
            "Connection: close\r\n"
            "Content-length: %d\r\n\r\n",
            errnum, shortmsg, (int) strlen(body));

    writen(fd, header, strlen(header));
    writen(fd, body, strlen(body));
}

static const char *get_file_type(const char *type)
{
    if (!type)
        return "text/plain";

    int i;
    for (i = 0; mime[i].type; ++i) {
        if (!strcmp(type, mime[i].type))
            return mime[i].value;
    }
    return mime[i].value;
}

static const char *get_msg_from_status(int status_code)
{
    if (status_code == HTTP_OK)
        return "OK";

    if (status_code == HTTP_NOT_MODIFIED)
        return "Not Modified";

    if (status_code == HTTP_NOT_FOUND)
        return "Not Found";

    return "Unknown";
}

static void serve_static(int fd,
                         char *filename,
                         size_t filesize,
                         http_out_t *out)
{
    char header[MAXLINE];

    const char *dot_pos = strrchr(filename, '.');
    const char *file_type = get_file_type(dot_pos);

    sprintf(header, "HTTP/1.1 %d %s\r\n", out->status,
            get_msg_from_status(out->status));

    if (out->keep_alive) {
        sprintf(header, "%sConnection: keep-alive\r\n", header);
        sprintf(header, "%sKeep-Alive: timeout=%d\r\n", header,
                TIMEOUT_DEFAULT);
    }

    if (out->modified) {
        char buf[SHORTLINE];
        sprintf(header, "%sContent-type: %s\r\n", header, file_type);
        sprintf(header, "%sContent-length: %zu\r\n", header, filesize);
        struct tm tm;
        localtime_r(&(out->mtime), &tm);
        strftime(buf, SHORTLINE, "%a, %d %b %Y %H:%M:%S GMT", &tm);
        sprintf(header, "%sLast-Modified: %s\r\n", header, buf);
    }

    sprintf(header, "%sServer: seHTTPd\r\n", header);
    sprintf(header, "%s\r\n", header);

    size_t n = (size_t) add_write_request(fd, header, strlen(header));
    assert(n == strlen(header) && "writen error");
    if (n != strlen(header)) {
        log_err("n != strlen(header)");
        return;
    }

    if (!out->modified)
        return;

    int srcfd = open(filename, O_RDONLY, 0);
    assert(srcfd > 2 && "open error");
    /* TODO: use sendfile(2) for zero-copy support */
    char *srcaddr = mmap(NULL, filesize, PROT_READ, MAP_PRIVATE, srcfd, 0);
    assert(srcaddr != (void *) -1 && "mmap error");
    close(srcfd);

    add_write_request(fd, srcaddr, filesize);
    
    munmap(srcaddr, filesize);
}

static inline int init_http_out(http_out_t *o, int fd)
{
    o->fd = fd;
    o->keep_alive = false;
    o->modified = true;
    o->status = 0;
    return 0;
}

void add_accept_request(int sockfd)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring) ;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    io_uring_prep_accept(sqe, sockfd, (struct sockaddr*)&client_addr, &client_addr_len, 0);

    http_request_t *request = malloc(sizeof(http_request_t));

    init_http_request(request, sockfd, WEBROOT, 0);
    io_uring_sqe_set_data(sqe, request);
    io_uring_submit(&ring);
}


void add_read_request(int clientfd)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring) ;
    http_request_t *request = malloc(sizeof(http_request_t) + sizeof(struct iovec));

    init_http_request(request, clientfd, WEBROOT, 1);

    request->iov[0].iov_base = malloc(sizeof(char) * 1024);
    request->iov[0].iov_len  = 1024;

    io_uring_prep_readv(sqe, clientfd, &request->iov[0], 1, 0);
    io_uring_sqe_set_data(sqe, request);
    io_uring_submit(&ring);
}


size_t add_write_request(int fd, void *usrbuf, size_t n)
{
    char *bufp = usrbuf;
    
    //printf("%s",bufp);

    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring) ;
    http_request_t *request = malloc(sizeof(http_request_t) + sizeof(struct iovec));
    request->event_type = 2;
    request->iovec_count = 1;
    unsigned long len = strlen(bufp);
    request->iov[0].iov_base = malloc(sizeof(char) * len);
    request->iov[0].iov_len = len;
    memcpy(request->iov[0].iov_base, bufp, len);
    io_uring_prep_writev(sqe, fd, request->iov, request->iovec_count, 0);
    io_uring_sqe_set_data(sqe, request);
    io_uring_submit(&ring);

    return n;
}

void handle_request(void *ptr)
{
    http_request_t *r = ptr;
    int fd = r->fd ;
    int rc;
    char filename[SHORTLINE];
    webroot = r->root;

    int n = strlen(r->iov[0].iov_base);
    strncpy(r->buf, r->iov[0].iov_base, n);

    r->last += n;

    rc = http_parse_request_line(r);
    rc = http_parse_request_body(r);

    http_out_t *out = malloc(sizeof(http_out_t));
    init_http_out(out, fd);
    
    parse_uri(r->uri_start, r->uri_end - r->uri_start, filename);

    struct stat sbuf;
    if (stat(filename, &sbuf) < 0) {
        do_error(fd, filename, "404", "Not Found", "Can't find the file");
        return;
    }
    if (!(S_ISREG(sbuf.st_mode)) || !(S_IRUSR & sbuf.st_mode)) {
        do_error(fd, filename, "403", "Forbidden", "Can't read the file");
        return;
    }

    out->mtime = sbuf.st_mtime;

    http_handle_header(r, out);

    if (!out->status) 
        out->status = HTTP_OK;

    serve_static(fd, filename, sbuf.st_size, out);

    if(!out->keep_alive) {
        printf("no keep alive!\n");
        free(out);
        rc = http_close_conn(r);
        printf("close conn rc = %d\n",rc);
        return ;
    }
    add_timer(r, TIMEOUT_DEFAULT, http_close_conn);


    free(out);
}

