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
    protected:
        Socket *httpsSocket;
        Socket *httpSocket;
        SSL_CTX *sslCtx;
        int sigExitFD;
        int sigPipeFD;
        int mainEpollFD;
        std::string htmlText;
        std::string serverDomain;
    public:
        Server(char *certFile, char *keyFile, std::string domain, int httpsPort, int httpPort, const std::string& htmlFilePath);
        static SSL_CTX* setupSSL(char *certFile, char *keyFile );
        static int setupExitFD();
        static int setupPipeFD();
        void setupSocketEpoll();
        void setupSignalEpoll() const;
        void loadHTML(const std::string &path);

        void start(int threadPoolSize);
        void end();
        void handleEvents();
        void processSocket(int socketFD);
        void processHTTPS(epoll_event event);
        void processHTTP(epoll_event event) const;
        void processSigExit();
        __attribute__((unused)) void makeSSLConnection(https::Connection **conPtr);
        void makeSSLConnectionLoop(https::Connection **conPtr);
        void sslRead(https::Connection **connPtr) const;
        void sslWrite(https::Connection **connPtr);
        void rearmConnection(Connection **connPtr, int events) const;
        void rearmSocket(int fd) const;
    };
}


#endif //HTTPS_SERVER_SERVER_H
