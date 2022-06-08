//
// Created by Solace on 6/7/2022.
//

#ifndef HTTPS_SERVER_SERVER_H
#define HTTPS_SERVER_SERVER_H

#include "Socket.h"
#include <openssl/ssl.h>

namespace https {
    class Server {
    private:
        int epollFD;
        int sigExitFD;
        Socket httpsSocket;
        Socket httpSocket;
        SSL_CTX *sslCtx;
    public:
        Server(char *certFile, char *keyFile, Socket httpsSocket, Socket httpSocket);
        void handleEpochEvents();
        void end();
        void redirectToHTTPS(int fd);
        void handleHTTPSRequest(int fd);
    };
}


#endif //HTTPS_SERVER_SERVER_H
