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
#define Queue_Depth 256
#define PORT 8081
#define WEBROOT "./www"

struct io_uring ring ;

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

void add_accept_request(int sockfd)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring) ;
    /*
    int flags = fcntl(sockfd, F_GETFL, 0);
    flags |= O_NONBLOCK;
    io_uring_prep_accept(sqe, sockfd, NULL, NULL, flags) ;
    */
    io_uring_prep_accept(sqe, sockfd, NULL, NULL, 0);

    http_request_t *request = malloc(sizeof(http_request_t));
   
    init_http_request(request, sockfd, WEBROOT, 0);
    io_uring_sqe_set_data(sqe, request);
    io_uring_submit(&ring);
}

void add_read_request(int clientfd)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring) ;
    http_request_t *request = malloc(sizeof(http_request_t)+sizeof(struct iovec)) ;
    init_http_request(request, clientfd, WEBROOT, 1);
    
    request->iov[0].iov_base = malloc(sizeof(1024));
    request->iov[0].iov_len  = 1024;
    
    request->client_socket = clientfd;
    io_uring_prep_readv(sqe, clientfd, &request->iov[0], 1, 0);
    io_uring_sqe_set_data(sqe, request);
    io_uring_submit(&ring); 
}

void add_write_request(int clientfd)
{
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

    int ret = io_uring_queue_init(Queue_Depth, &ring, 0) ;
    struct io_uring_cqe *cqe ;
    assert(ret >= 0 && "io_uring_queue_init") ;

    add_accept_request(listenfd);
   
    printf("server loop start : \n");
    while(1)
    {
        ret = io_uring_wait_cqe(&ring, &cqe) ;
        assert( ret>0 && "io_uring_wait_cqe") ;
        http_request_t* req = (http_request_t*) cqe->user_data;
        
        printf("event_type = %d\n", req->event_type) ;

        switch(req->event_type) {
            //accept request
            case 0:                
                if(cqe->res < 0) {
                    if((errno == EAGAIN) || (errno == EWOULDBLOCK)) 
                        break;
                }

                int rc = sock_set_non_blocking(cqe->res);
                assert(rc == 0 && "sock_set_non_blocking");
                
                http_request_t *client_req = malloc(sizeof(http_request_t));
                init_http_request(client_req, cqe->res, WEBROOT, 1); 

                add_accept_request(listenfd);
                
                break ;
            //read request
            case 1:
                
                break ;
            //write request
            case 2:
                break ;
        }
        
        io_uring_cqe_seen(&ring, cqe) ;
    }
    return 0;
}
