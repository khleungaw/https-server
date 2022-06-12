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

namespace https {
    constexpr size_t bufferSize = 2048;

    class Server {
    private:
        int fdCount = 0;
        int listenerEpollFD;
        int sigExitFD;
        int sigPipeFD;
        Socket httpsSocket;
        Socket httpSocket;
        SSL_CTX *sslCtx;
        int* httpsEpollFDs;
        int httpEpollFD;
        std::string htmlText;
        std::map<int, SSL*> *connectionsSSLs;
        std::map<int, https::HttpRequest*> *connectionsRequests;
    public:
        Server(char *certFile, char *keyFile, Socket httpsSocket, Socket httpSocket, const std::string& htmlFilePath, int threadCount);
        void handleHTTPS(int epollFD, int workerID);
        void handleHTTP(int epollFD);
        static https::HttpRequest *processRead(SSL *ssl);
        void processWrite(SSL *ssl, https::HttpRequest *request);
        void processSigExit();
        void handleListenerEvents(int threadCount);
        void start(int threadCount);
        void end();
        SSL* makeSSLConnection(int fd);
        void loadHTML(const std::string &path);
        void closeConnection(SSL *ssl, int fd, int workerID);

        static SSL_CTX* setupSSL(char *certFile, char *keyFile );
        static void setupSocketEpoll(int epollFD, https::Socket httpsSocket, https::Socket httpSocket);
        static void setupSignalEpoll(int epollFD, int sigExitFD, int sigPipeFD);
        static int createWorkerEpoll();
        static int setupExitFD();
        static int setupPipeFD();
    };
}


#endif //HTTPS_SERVER_SERVER_H
