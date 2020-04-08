#!/usr/bin/env bash

# utility function(s) like ProgressBar
source scripts/util.sh

LOCAL_PORT="8081"

wait_server() {
    local port
    port=$1
    for i in {1..20}; do
        # sleep first because this maybe called immediately after server start
        sleep 0.1
        nc -z -w 4 127.0.0.1 $port && break
    done
}

start_http_server() {
    ./sehttpd &	
    server_pid=$!
}

stop_http_server() {
    kill $server_pid
}

test_server_local() {
    local url
    url=http://127.0.0.1:$LOCAL_PORT
    END=1000
    for i in $(seq 1 $END);
    do
        wget --quiet -O /dev/null $url || break
        ProgressBar $i $END
    done
}

pkill -9 sehttpd >/dev/null 2>/dev/null

start_http_server
test_server_local
stop_http_server
printf "\n"
