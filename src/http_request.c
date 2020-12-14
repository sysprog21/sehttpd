#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* for the sake of strptime(3) */
#endif

#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "http.h"

int http_close_conn(http_request_t *r)
{
    /* An open file description continues to exist until all file descriptors
     * referring to it have been closed. A file descriptor is removed from an
     * epoll set only after all the file descriptors referring to the
     * underlying open file description have been closed (or before if the
     * descriptor is explicitly removed using epoll_ctl(2) EPOLL_CTL_DEL).
     */
    free(r->iov[0].iov_base);
    close(r->fd);
    free(r);
    return 0;
}

static int http_process_ignore(http_request_t *r UNUSED,
                               http_out_t *out UNUSED,
                               char *data UNUSED,
                               int len UNUSED)
{
    return 0;
}

static int http_process_connection(http_request_t *r UNUSED,
                                   http_out_t *out,
                                   char *data,
                                   int len)
{
    if (!strncasecmp("keep-alive", data, len))
        out->keep_alive = true;
    return 0;
}

static int http_process_if_modified_since(http_request_t *r UNUSED,
                                          http_out_t *out,
                                          char *data,
                                          int len UNUSED)
{
    struct tm tm;
    if (!strptime(data, "%a, %d %b %Y %H:%M:%S GMT", &tm))
        return 0;

    time_t client_time = mktime(&tm);
    double time_diff = difftime(out->mtime, client_time);
    /* TODO: use custom absolute value function rather without libm */
    if (fabs(time_diff) < 1e-6) { /* Not modified */
        out->modified = false;
        out->status = HTTP_NOT_MODIFIED;
    }
    return 0;
}

static http_header_handle_t http_headers_in[] = {
    {"Host", http_process_ignore},
    {"Connection", http_process_connection},
    {"If-Modified-Since", http_process_if_modified_since},
    {"", http_process_ignore}};

void http_handle_header(http_request_t *r, http_out_t *o)
{
    list_head *pos;
    list_for_each (pos, &(r->list)) {
        http_header_t *header = list_entry(pos, http_header_t, list);
        for (http_header_handle_t *header_in = http_headers_in;
             strlen(header_in->name) > 0; header_in++) {
            if (!strncmp(header->key_start, header_in->name,
                         header->key_end - header->key_start)) {
                int len = header->value_end - header->value_start;
                (*(header_in->handler))(r, o, header->value_start, len);
                break;
            }
        }

        /* delete it from the original list */
        list_del(pos);
        free(header);
    }
}
