//
// Created by Solace on 6/7/2022.
//

#ifndef HTTPS_SERVER_SERVER_H
#define HTTPS_SERVER_SERVER_H

#include <vector>
#include <openssl/ssl.h>
#include <sys/epoll.h>
#include "Socket.h"

namespace https {
    constexpr size_t bufferSize = 4096;

    class Server {
    private:
        int epollFD;
        int sigExitFD;
        int sigPipeFD;
        Socket httpsSocket;
        Socket httpSocket;
        SSL_CTX *sslCtx;
        std::vector<int> connections;
        std::string htmlText;
    public:
        Server(char *certFile, char *keyFile, Socket httpsSocket, Socket httpSocket, const std::string& htmlFilePath);
        void handleEpochEvents();
        void end();
        void redirectToHTTPS(int fd);
        void handleHTTPSRequest(int fd);
        void acceptConnection(int fd, bool isHTTPS);
        std::string sslRead(SSL *ssl, int connectionFD) const;
        SSL* makeSSLConnection(int fd);
        void loadHTML(const std::string &path);
    };
}


#endif //HTTPS_SERVER_SERVER_H
