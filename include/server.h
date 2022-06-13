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
    constexpr size_t bufferSize = 2048;

    class Server {
    private:
        int listenerEpollFD;
        int sigExitFD;
        int sigPipeFD;
        Socket httpsSocket;
        Socket httpSocket;
        SSL_CTX *sslCtx;
        int httpsThreadCount;
        int httpThreadCount;
        int* httpsEpollFDs;
        int* httpEpollFDs;
        std::string htmlText;
    public:
        Server(char *certFile, char *keyFile, Socket httpsSocket, Socket httpSocket, const std::string& htmlFilePath, int httpsThreadCount, int httpThreadCount);
        void handleHTTPS(int epollFD);
        static void handleHTTP(int epollFD);
        static void processRead(https::Connection **connection);
        void processWrite(https::Connection **connection);
        void processSigExit();
        void handleListenerEvents();
        void start();
        void end();
        SSL* makeSSLConnection(int fd);
        void loadHTML(const std::string &path);
        static void closeConnection(https::Connection **connection);
        static void preemptClose(SSL *ssl, int fd);

        static SSL_CTX* setupSSL(char *certFile, char *keyFile );
        static void setupSocketEpoll(int epollFD, https::Socket httpsSocket, https::Socket httpSocket);
        static void setupSignalEpoll(int epollFD, int sigExitFD, int sigPipeFD);
        static int createWorkerEpoll();
        static int setupExitFD();
        static int setupPipeFD();
    };
}


#endif //HTTPS_SERVER_SERVER_H
