//
// Created by Solace on 6/7/2022.
//

#ifndef HTTPS_SERVER_SERVER_H
#define HTTPS_SERVER_SERVER_H

#include <vector>
#include <map>
#include <openssl/ssl.h>
#include <sys/epoll.h>
#include "socket.h"
#include "message.h"
#include "connection.h"

namespace https {
    constexpr size_t kBufferSize = 2048;

    class Server {
    private:
        Socket *httpsSocket;
        Socket *httpSocket;
        SSL_CTX *sslCtx;
        int sigExitFD;
        int sigPipeFD;
        int epollFD;
        std::string htmlText;
    public:
        Server(char *certFile, char *keyFile, int httpsPort, int httpPort, const std::string& htmlFilePath);
        static SSL_CTX* setupSSL(char *certFile, char *keyFile );
        static int setupExitFD();
        static int setupPipeFD();
        void setupSocketEpoll();
        void setupSignalEpoll() const;

        void handleEvents();
        void processSigExit();
        void processSocket(int fd);
        void processHTTPS(epoll_event event);
        void processHTTP(epoll_event event) const;
        void sslRead(https::Connection **connPtr) const;
        void sslWrite(https::Connection **connPtr);
        void start(int threadPoolSize);
        void end();
        void makeSSLConnection(https::Connection **conPtr);
        void loadHTML(const std::string &path);
        void rearmConnection(Connection **connPtr, int events) const;
        void rearmSocket(int fd) const;
    };
}


#endif //HTTPS_SERVER_SERVER_H
