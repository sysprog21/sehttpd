#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <liburing.h>

#include "http.h"
#include "logger.h"
#include "timer.h"

/* the length of the struct epoll_events array pointed to by *events */
#define MAXEVENTS 1024
#define LISTENQ 1024
#define Queue_Depth 512
#define PORT 8081
#define WEBROOT "./www"

//struct io_uring ring ;

static int open_listenfd(int port)
{
    int listenfd, optval = 1;

    /* Create a socket descriptor */
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        return -1;

    /* Eliminate "Address already in use" error from bind. */
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void *) &optval,
                   sizeof(int)) < 0)
        return -1;

    /* Listenfd will be an endpoint for all requests to given port. */
    struct sockaddr_in serveraddr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons((unsigned short) port),
        .sin_zero = {0},
    };
    if (bind(listenfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0)
        return -1;

    /* Make it a listening socket ready to accept connection requests */
    if (listen(listenfd, LISTENQ) < 0)
        return -1;

    return listenfd;
}

/* set a socket non-blocking. If a listen socket is a blocking socket, after
 * it comes out from epoll and accepts the last connection, the next accpet
 * will block unexpectedly.
 */
static int sock_set_non_blocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        log_err("fcntl");
        return -1;
    }

    flags |= O_NONBLOCK;
    int s = fcntl(fd, F_SETFL, flags);
    if (s == -1) {
        log_err("fcntl");
        return -1;
    }
    return 0;
}

/* TODO: use command line options to specify */
int main()
{
    if (sigaction(SIGPIPE,
                  &(struct sigaction){.sa_handler = SIG_IGN, .sa_flags = 0},
                  NULL)) {
        log_err("Failed to install sigal handler for SIGPIPE");
        return 0;
    }

    int listenfd = open_listenfd(PORT);
    assert(listen >= 0 && "open_listenfd");

    int ret = init_ring();
    assert(ret >= 0 && "io_uring_queue_init") ;
    
    
    add_accept_request(listenfd);
   
    printf("server loop start : \n");
    
    while(1)
    {
        //ret = io_uring_wait_cqe(&ring, &cqe) ;
        //assert( ret>0 && "io_uring_wait_cqe") ;
        struct io_uring_cqe *cqe = wait_cqe();       
        http_request_t *req = (http_request_t*) cqe->user_data;
        
        printf("event_type = %d\n", req->event_type) ;
        
        switch(req->event_type) {
            case 0: {
                int fd = cqe->res;
                if(fd < 0) {
                    if((errno == EAGAIN) || (errno == EWOULDBLOCK)) 
                        break;
                }
                add_read_request(fd);
                add_accept_request(listenfd);
                free(req);
                break ;
            }

            case 1: {
                handle_request(req);
                free(req->iov[0].iov_base);
                free(req); 
                break ;
            }

            case 2:
                for (int i = 0 ; i < req->iovec_count ; i++)
                {
                    free(req->iov[i].iov_base);    
                }
                close(req->fd);
                free(req);
                break ;

            default :
                break ;
        }
        
        //io_uring_cqe_seen(&ring, cqe) ;
    }
    
    return 0;
}
