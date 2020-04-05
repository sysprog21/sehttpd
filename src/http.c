#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "http.h"
#include "logger.h"
#include "timer.h"

#define MAXLINE 8192
#define SHORTLINE 512

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

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

    strcpy(filename, webroot);

    /* uri_length can not be too long */
    if (uri_length > (SHORTLINE >> 1)) {
        log_err("uri too long: %.*s", uri_length, uri);
        return;
    }

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
    char buf[SHORTLINE];

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
        sprintf(header, "%sContent-type: %s\r\n", header, file_type);
        sprintf(header, "%sContent-length: %zu\r\n", header, filesize);
        struct tm tm;
        localtime_r(&(out->mtime), &tm);
        strftime(buf, SHORTLINE, "%a, %d %b %Y %H:%M:%S GMT", &tm);
        sprintf(header, "%sLast-Modified: %s\r\n", header, buf);
    }

    sprintf(header, "%sServer: seHTTPd\r\n", header);
    sprintf(header, "%s\r\n", header);

    size_t n = (size_t) writen(fd, header, strlen(header));
    assert(n == strlen(header) && "writen error");
    if (n != strlen(header)) {
        log_err("n != strlen(header)");
        return;
    }

    if (!out->modified)
        return;

    int srcfd = open(filename, O_RDONLY, 0);
    assert(srcfd > 2 && "open error");
    /* TODO: use sendfile(2) for zero-cop support */
    char *srcaddr = mmap(NULL, filesize, PROT_READ, MAP_PRIVATE, srcfd, 0);
    assert(srcaddr != (void *) -1 && "mmap error");
    close(srcfd);

    n = writen(fd, srcaddr, filesize);

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

void do_request(void *ptr)
{
    http_request_t *r = ptr;
    int fd = r->fd;
    int rc;
    char filename[SHORTLINE];
    webroot = r->root;

    del_timer(r);
    for (;;) {
        char *plast = &r->buf[r->last % MAX_BUF];
        size_t remain_size =
            MIN(MAX_BUF - (r->last - r->pos) - 1, MAX_BUF - r->last % MAX_BUF);

        int n = read(fd, plast, remain_size);
        assert(r->last - r->pos < MAX_BUF && "request buffer overflow!");

        if (n == 0) /* EOF */
            goto err;

        if (n < 0) {
            if (errno != EAGAIN) {
                log_err("read err, and errno = %d", errno);
                goto err;
            }
            break;
        }

        r->last += n;
        assert(r->last - r->pos < MAX_BUF && "request buffer overflow!");

        /* about to parse request line */
        rc = http_parse_request_line(r);
        if (rc == EAGAIN)
            continue;
        if (rc != 0) {
            log_err("rc != 0");
            goto err;
        }

        debug("uri = %.*s", (int) (r->uri_end - r->uri_start),
              (char *) r->uri_start);

        rc = http_parse_request_body(r);
        if (rc == EAGAIN)
            continue;
        if (rc != 0) {
            log_err("rc != 0");
            goto err;
        }

        /* handle http header */
        http_out_t *out = malloc(sizeof(http_out_t));
        if (!out) {
            log_err("no enough space for http_out_t");
            exit(1);
        }

        init_http_out(out, fd);

        parse_uri(r->uri_start, r->uri_end - r->uri_start, filename);

        struct stat sbuf;
        if (stat(filename, &sbuf) < 0) {
            do_error(fd, filename, "404", "Not Found", "Can't find the file");
            continue;
        }

        if (!(S_ISREG(sbuf.st_mode)) || !(S_IRUSR & sbuf.st_mode)) {
            do_error(fd, filename, "403", "Forbidden", "Can't read the file");
            continue;
        }

        out->mtime = sbuf.st_mtime;

        http_handle_header(r, out);
        assert(list_empty(&(r->list)) && "header list should be empty");

        if (!out->status)
            out->status = HTTP_OK;

        serve_static(fd, filename, sbuf.st_size, out);

        if (!out->keep_alive) {
            debug("no keep_alive! ready to close");
            free(out);
            goto close;
        }
        free(out);
    }

    struct epoll_event event = {
        .data.ptr = ptr,
        .events = EPOLLIN | EPOLLET | EPOLLONESHOT,
    };
    epoll_ctl(r->epfd, EPOLL_CTL_MOD, r->fd, &event);

    add_timer(r, TIMEOUT_DEFAULT, http_close_conn);
    return;

err:
close:
    /* TODO: handle the timeout raised by inactive connections */
    rc = http_close_conn(r);
    assert(rc == 0 && "do_request: http_close_conn");
}
