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
#include <time.h>

#include "http.h"
#include "logger.h"
#include "timer.h"

#define Queue_Depth 2048
#define MAXLINE 8192
#define SHORTLINE 512
#define WEBROOT "./www"

#define MAX_CONNECTIONS 1024
#define MAX_MESSAGE_LEN 2048
char bufs[MAX_CONNECTIONS][MAX_MESSAGE_LEN] = {0};
int group_id = 8888;

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

struct io_uring ring;

static void add_read_request(http_request_t *request);
static void add_write_request(int fd, void *usrbuf, size_t n, http_request_t *r);
static void add_provide_buf(int bid);

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

void init_ring()
{
    struct io_uring_params params;
    memset(&params, 0, sizeof(params));

    int ret = io_uring_queue_init_params(Queue_Depth, &ring, &params);
    assert(ret >= 0 && "io_uring_queue_init");
    
    if (!(params.features & IORING_FEAT_FAST_POLL)) {
        printf("IORING_FEAT_FAST_POLL not available in the kernel, quiting...\n");
        exit(0);
    }
    
    struct io_uring_probe *probe;
    probe = io_uring_get_probe_ring(&ring);
    if (!probe || !io_uring_opcode_supported(probe, IORING_OP_PROVIDE_BUFFERS)) {
        printf("Buffer select not supported, skipping...\n");
        exit(0);
    }
    free(probe);

    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;

    sqe = io_uring_get_sqe(&ring);
    io_uring_prep_provide_buffers(sqe, bufs, MAX_MESSAGE_LEN, MAX_CONNECTIONS, group_id, 0);

    io_uring_submit(&ring);
    io_uring_wait_cqe(&ring, &cqe);
    if (cqe->res < 0) {
        printf("cqe->res = %d\n", cqe->res);
        exit(1);
    }
    io_uring_cqe_seen(&ring, cqe);
}

void io_uring_loop() {
    printf("server start : \n");

    while(1)
    {
        struct io_uring_cqe *cqe ;
        unsigned head;
        unsigned count = 0;

        io_uring_for_each_cqe(&ring, head, cqe){
            ++count;
            http_request_t *req = io_uring_cqe_get_data(cqe);

            switch(req->event_type) {
                case 0: {
                    int fd = cqe->res;
                    add_accept_request(req->fd);
                
                    http_request_t *request = malloc(sizeof(http_request_t) );
                    init_http_request(request, fd, WEBROOT);

                    add_timer(request, TIMEOUT_DEFAULT, http_close_conn);
                    add_read_request(request);
                    free(req);
                    break ;
                }

                case 1: {
                    int read_len = cqe->res;
                    req->bid = ( cqe->flags >> IORING_CQE_BUFFER_SHIFT );
                    handle_request(req, read_len);
                    break ;
                }

                case 2: {
                    add_read_request(req);
                    break ;
                }

                case 3: {
                    free(req);
                    break;
                }

                case 4: {
                    close(req->fd);
                    free(req);
                    break;
                }
            }
        }
        io_uring_cq_advance(&ring, count);        
    }
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
                         http_out_t *out,
                         http_request_t *r)
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

    add_write_request(fd, header, strlen(header), r);

    if (!out->modified)
        return;

    int srcfd = open(filename, O_RDONLY, 0);
    assert(srcfd > 2 && "open error");

    int n = sendfile(fd, srcfd, 0, filesize);
    assert(n == filesize && "sendfile");

    close(srcfd);
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
    request->event_type = 0 ;
    request->fd = sockfd ;

    io_uring_sqe_set_data(sqe, request);
    io_uring_sqe_set_flags(sqe, 0);
    io_uring_submit(&ring);
}


static void add_read_request(http_request_t *request)
{
    int clientfd = request->fd ;
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring) ;
    io_uring_prep_recv(sqe, clientfd, NULL, MAX_MESSAGE_LEN, 0);
    io_uring_sqe_set_flags(sqe, IOSQE_BUFFER_SELECT);
    sqe->buf_group = group_id;

    request->event_type = 1;
    io_uring_sqe_set_data(sqe, request);

    io_uring_submit(&ring);
}

static void add_write_request(int fd, void *usrbuf, size_t n, http_request_t *r)
{
    char *bufp = usrbuf;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring) ;
    http_request_t *request = r;
    request->event_type = 2;
    unsigned long len = strlen(bufp);

    io_uring_prep_send(sqe, fd, bufp, len, 0);
    io_uring_sqe_set_data(sqe, request);
    io_uring_sqe_set_flags(sqe, 0);

    io_uring_submit(&ring);
}

static void add_provide_buf(int bid) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_provide_buffers(sqe, bufs[bid], MAX_MESSAGE_LEN, 1, group_id, bid);
    http_request_t *req = malloc(sizeof(http_request_t));
    req->event_type = 3 ;

    io_uring_sqe_set_data(sqe, req);
    io_uring_submit(&ring);
}

void handle_request(void *ptr, int n)
{
    http_request_t *r = ptr;
    int fd = r->fd ;
    int rc;
    char filename[SHORTLINE];
    webroot = r->root;

    clock_t t1, t2;

    del_timer(r);
    for(;;) {
        t1 = clock();
        if (n==0)
            goto err;

        else if (n < 0) {
            if (errno != EAGAIN) {
                log_err("read err, and errno = %d",errno);
                goto err;
            }
            break;
        }

        char *plast = &r->buf[r->last % MAX_BUF];
        size_t remain_size =
            MIN(MAX_BUF - (r->last - r->pos) - 1, MAX_BUF - r->last % MAX_BUF);

        if (n > remain_size) {
            goto close ;
        }

        strncpy(plast, bufs[r->bid], n);
        add_provide_buf(r->bid);

        r->last += n;
        rc = http_parse_request_line(r);

        debug("uri = %.*s", (int) (r->uri_end - r->uri_start),
            (char *) r->uri_start);

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

        serve_static(fd, filename, sbuf.st_size, out, r);

        if(!out->keep_alive || remain_size < 6000) {
            free(out);
            goto close;
        }
        free(out);

        t2 = clock();
        //printf("%lf\n", (t2-t1)/(double)(CLOCKS_PER_SEC));

        break;
    }
    add_timer(r, TIMEOUT_DEFAULT, http_close_conn);
    return ;
err:
close:
    r->event_type = 4;
    //rc = http_close_conn(r);
    //assert(rc == 0 && "do_request: http_close_conn");
}

