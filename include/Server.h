//
// Created by Solace on 6/7/2022.
//

#ifndef HTTPS_SERVER_SERVER_H
#define HTTPS_SERVER_SERVER_H

#include <vector>
#include <map>
#include <openssl/ssl.h>
#include <sys/epoll.h>
#include "Socket.h"
#include "utils.h"

namespace https {
    constexpr size_t bufferSize = 2048;

    class Server {
    private:
        int fdCount = 0;
        int socketEpollFD;
        int signalEpollFD;
        int sigExitFD;
        int sigPipeFD;
        Socket httpsSocket;
        Socket httpSocket;
        SSL_CTX *sslCtx;
        int* httpsEpollFDs;
        int httpEpollFD;
        std::string htmlText;
        std::map<int, SSL*> *workersConnections;
    public:
        Server(char *certFile, char *keyFile, Socket httpsSocket, Socket httpSocket, const std::string& htmlFilePath, int threadCount);
        static SSL_CTX* setupSSL(char *certFile, char *keyFile );
        static int setupSocketEpoll(https::Socket httpsSocket, https::Socket httpSocket);
        static int setupSignalEpoll(int sigExitFD, int sigPipeFD);
        static int createWorkerEpoll();
        static int setupExitFD();
        static int setupPipeFD();
        void handleHTTPS(int epollFD, int workerID);
        void processRead(int epollFD, SSL *ssl, int workerID);
        void processWrite(SSL *ssl, const HttpRequest& request, int workerID);
        void handleHTTP(int epollFD);
        void handleSignalEvents();
        void handleSocketEvents(int threadCount);
        void start(int threadCount);
        void end();
        SSL* makeSSLConnection(int fd);
        void loadHTML(const std::string &path);
        void closeConnection(SSL *ssl, int workerID);
        static void rearmEpoll(int epollFD, int fd);
    };
}


#endif //HTTPS_SERVER_SERVER_H
