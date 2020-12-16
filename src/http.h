#ifndef HTTP_H
#define HTTP_H

#include <errno.h>
#include <stdbool.h>
#include <time.h>
#include <liburing.h>

#include "list.h"

enum http_parser_retcode {
    HTTP_PARSER_INVALID_METHOD = 10,
    HTTP_PARSER_INVALID_REQUEST,
    HTTP_PARSER_INVALID_HEADER
};

enum http_method {
    HTTP_UNKNOWN = 0x0001,
    HTTP_GET = 0x0002,
    HTTP_HEAD = 0x0004,
    HTTP_POST = 0x0008,
};

enum http_status {
    HTTP_OK = 200,
    HTTP_NOT_MODIFIED = 304,
    HTTP_NOT_FOUND = 404,
};

#define MAX_BUF 8124

typedef struct {
    void *root;
    int fd;
    int epfd;
    //char buf[MAX_BUF]; /* ring buffer */
    char *buf;
    size_t pos, last;
    int state;
    void *request_start;
    int method;
    void *uri_start, *uri_end;
    int http_major, http_minor;
    void *request_end;

    struct list_head list; /* store http header */
    void *cur_header_key_start, *cur_header_key_end;
    void *cur_header_value_start, *cur_header_value_end;

    void *timer;

    int bid ;    
    int event_type ;
    int iovec_count ;
    void *ptr ;
    //struct iovec iov[];
} http_request_t;

typedef struct {
    int fd;
    bool keep_alive;
    time_t mtime;  /* the modified time of the file */
    bool modified; /* compare If-modified-since field with mtime to decide
                    * whether the file is modified since last time
                    */
    int status;
} http_out_t;

typedef struct {
    void *key_start, *key_end; /* not include end */
    void *value_start, *value_end;
    list_head list;
} http_header_t;

typedef int (*http_header_handler)(http_request_t *r,
                                   http_out_t *o,
                                   char *data,
                                   int len);

typedef struct {
    char *name;
    http_header_handler handler;
} http_header_handle_t;

void http_handle_header(http_request_t *r, http_out_t *o);
int http_close_conn(http_request_t *r);

static inline void init_http_request(http_request_t *r,
                                     int fd,
                                     char *root)
{
    r->fd = fd;
    r->pos = r->last = 0;
    r->state = 0;
    r->root = root;
    INIT_LIST_HEAD(&(r->list));
}

/* TODO: public functions should have conventions to prefix http_ */
void do_request(void *infd);
void handle_request(void *ptr, int n);
void add_accept_request(int sockfd);
void add_provide_buf(int bid);
//void add_read_request(http_request_t *req);
//void add_write_request(int fd, void *usrbuf, size_t n, http_request_t *r);

void init_ring();
void io_uring_loop();

int http_parse_request_line(http_request_t *r);
int http_parse_request_body(http_request_t *r);

#endif
