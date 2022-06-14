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
        int mainEpollFD;
        std::string htmlText;
    public:
        Server(char *certFile, char *keyFile, int httpsPort, int httpPort, const std::string& htmlFilePath);
        static SSL_CTX* setupSSL(char *certFile, char *keyFile );
        static int setupExitFD();
        static int setupPipeFD();
        void setupSocketEpoll();
        void setupSignalEpoll() const;
        void loadHTML(const std::string &path);

        void start(int threadPoolSize);
        void startWithListener(int threadPoolSize);
        void end();
        void handleEvents();
        void processSocket(int socketFD, int epollFD);
        void processHTTPS(epoll_event event);
        void processHTTP(epoll_event event) const;
        void processSigExit();
        void makeSSLConnection(https::Connection **conPtr);
        void sslRead(https::Connection **connPtr) const;
        void sslWrite(https::Connection **connPtr);
        void rearmConnection(Connection **connPtr, int events) const;
        void rearmSocket(int fd) const;

        //Alternate methods for setup with listener thread
        void handleListenerEvents(int *workerEpollFDs, int numWorkers);
        void handleWorkerEvents(int epollFD);
        void processHTTPS(epoll_event event, int epollFD);
        static void processHTTP(epoll_event , int epollFD) ;
        void makeSSLConnection(https::Connection **conPtr, int epollFD);
        static void sslRead(https::Connection **connPtr, int epollFD) ;
        void sslWrite(https::Connection **connPtr, int epollFD);
        static void rearmConnection(Connection **connPtr, int events, int epollFD) ;
    };
}


#endif //HTTPS_SERVER_SERVER_H
