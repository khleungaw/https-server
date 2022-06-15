//
// Created by Solace on 6/15/2022.
//

#ifndef HTTPS_SERVER_LISTENER_SERVER_H
#define HTTPS_SERVER_LISTENER_SERVER_H

#include "server.h"

namespace https {
    class ListenerServer: public https::Server {
    public:
        ListenerServer(char *certFile, char *keyFile, std::string domain, int httpsPort, int httpPort, const std::string &htmlFilePath);
        void startWithListener(int threadPoolSize);
        void listenerHandleEvents(int *workerEpollFDs, int numWorkers);
        void workerHandleConnections(int epollFD);
        void listenerProcessSockets(int socketFD, int epollFD);
        void workerProcessHTTPS(epoll_event event);
        void workerProcessHTTP(epoll_event event) ;
        void listenerMakeSSLConnection(https::Connection **conPtr);
        static void workerSSLRead(https::Connection **connPtr) ;
        void workerSSLWrite(https::Connection **connPtr);
};
}

#endif //HTTPS_SERVER_LISTENER_SERVER_H
