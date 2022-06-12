//
// Created by Solace on 6/7/2022.
//

#include <iostream>
#include <cstring>
#include <csignal>
#include <thread>
#include <algorithm>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <fstream>
#include "server.h"
#include "socket.h"
#include "message.h"

https::Server::Server(char *certFile, char *keyFile, Socket httpsSocket, Socket httpSocket, const std::string& htmlFilePath, int threadCount)
        : httpsSocket(httpsSocket), httpSocket(httpSocket) {
    loadHTML(htmlFilePath);
    sslCtx = setupSSL(certFile, keyFile);
    sigExitFD = setupExitFD();
    sigPipeFD = setupPipeFD();
    threadCount = std::max(threadCount, 1);

    //Setup listener epoll
    listenerEpollFD = epoll_create1(0);
    setupSocketEpoll(listenerEpollFD, httpsSocket, httpSocket);
    setupSignalEpoll(listenerEpollFD, sigExitFD, sigPipeFD);

    //Setup worker epolls
    httpsEpollFDs = new int[threadCount];
    connectionsSSLs = new std::map<int, SSL*>[threadCount];
    connectionsRequests = new std::map<int, https::HttpRequest*>[threadCount];
    for (int i = 0; i < threadCount; i++) {
        httpsEpollFDs[i] = createWorkerEpoll();
        connectionsSSLs[i] = std::map<int, SSL*>();
        connectionsRequests[i] = std::map<int, https::HttpRequest*>();
    }
    httpEpollFD = createWorkerEpoll();
}

void https::Server::start(int threadCount) {
    std::cout << "\n--------------------Server  Starting--------------------" << std::endl;

    //Create worker threads to handle HTTPS connections
    for (int i = 0; i < threadCount; i++) {
        std::thread workerThread(&https::Server::handleHTTPS, this, httpsEpollFDs[i], i);
        workerThread.detach();
    }

    //Create a thread to handle HTTP connections
    std::thread httpThread(&https::Server::handleHTTP, this, httpEpollFD);
    httpThread.detach();

    //Starts listening for httpsEpollFDs
    handleListenerEvents(threadCount);
}

void https::Server::end() {
    //Clean up
    SSL_CTX_free(sslCtx);
    httpSocket.end();
    httpsSocket.end();
}

void https::Server::handleHTTPS(int epollFD, int workerID) {
    while (true) {
        //Wait for epoll event
        struct epoll_event epollEvents[10000];
        int waitResult = epoll_wait(epollFD, epollEvents, 10000, -1);
        if (waitResult < 0) {
            std::string error = std::strerror(errno);
            throw std::runtime_error("Worker Wait Failed: " + error);
        }

        for (int i = 0; i < waitResult; i++) {
            int fd = epollEvents[i].data.fd;
            std::cout << "Worker " << workerID << ": "<<"EPOLLIN: "<< (epollEvents[i].events & EPOLLIN) << " , EPOLLOUT:" << (epollEvents[i].events & EPOLLOUT) << std::endl;

            if (epollEvents[i].events & EPOLLIN) { //EPOLLIN
                SSL *ssl;
                //Check if SSL has been established
                if (connectionsSSLs[workerID][fd] == nullptr) {
                    //Make SSL Connection
                    ssl = makeSSLConnection(fd);
                    if (ssl == nullptr) {
                        std::cout << "Failed to make SSL Connection" << std::endl;
                        close(fd);
                        SSL_free(ssl);
                        std::cout << "-------------------Closing Connection-------------------" << std::endl;
                        continue;
                    }
                    connectionsSSLs[workerID][fd] = ssl;
                } else {
                    //Get SSL Connection
                    ssl = connectionsSSLs[workerID][fd];
                    std::cout << "AM I HERE" << std::endl;
                }
                //Read immediately
                connectionsRequests[workerID][fd] = processRead(ssl);
            }
            if (epollEvents[i].events & EPOLLOUT) { //EPOLLOUT
                //Check if SSL has been established
                if (connectionsSSLs[workerID][fd] == nullptr) {
                    //Make SSL Connection
                    SSL *ssl = makeSSLConnection(fd);
                    if (ssl == nullptr) {
                        std::cout << "Failed to make SSL Connection" << std::endl;
                        close(fd);
                        SSL_free(ssl);
                        std::cout << "-------------------Closing Connection-------------------" << std::endl;
                        continue;
                    }
                    connectionsSSLs[workerID][fd] = ssl;
                    continue;
                }

                //Check if request has been received
                https::HttpRequest* request = connectionsRequests[workerID][fd];
                if (connectionsRequests[workerID][fd] != nullptr) {
                    SSL* ssl = connectionsSSLs[workerID][fd];
                    processWrite(ssl, request);
                    //Close connection
                    closeConnection(ssl, fd, workerID);
                }

                continue;
            }
            if ((epollEvents[i].events & EPOLLERR) || (epollEvents[i].events & EPOLLHUP)) {
                //Get SSL
                SSL *ssl = connectionsSSLs[workerID][fd];
                closeConnection(ssl, fd, workerID);
            }
        }
    }
}

void https::Server::handleHTTP(int epollFD) {
    while (true) {
        //Wait for epoll event
        struct epoll_event epollEvent{};
        int waitResult = epoll_wait(epollFD, &epollEvent, 1, -1);
        if (waitResult < 0) {
            std::string error = std::strerror(errno);
            throw std::runtime_error("HTTP Wait Failed: " + error);
        }
        int connectionFD = epollEvent.data.fd;

        //Get https port
        int httpsPort = httpsSocket.getPort();

        //Read request from fd until EOF
        std::string req;
        while (true) {
            char buffer[1024];
            ssize_t readResult = read(connectionFD, buffer, 1024);
            if (readResult < 0) {
                //Check for EAGAIN/EWOULDBLOCK
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                } else {
                    std::cout << "Read Failed: " << std::strerror(errno) << std::endl;
                    break;
                }
            } else if (readResult == 0) { //EOF
                break;
            } else {
                req += buffer;
            }
        }

        //Print request
        std::cout << req << std::endl;

        //Prepare response
        std::string domain = std::getenv("DOMAIN") ? getenv("DOMAIN") : "172.18.201.161";
        char resBuffer[1024];
        std::string response =
                "HTTP/1.1 301 Moved Permanently\r\n"
                "Connection: close\r\n"
                "Location: https://" + domain + ":" + std::to_string(httpsPort) + "/\r\n\r\n";
        strcpy(resBuffer, response.c_str());

        //Write until EOF
        ssize_t bytesWritten = 0;
        while (bytesWritten < response.length()) {
            ssize_t writeResult = write(connectionFD, resBuffer + bytesWritten, response.length() - bytesWritten);
            if (writeResult < 0) {
                //Check for EAGAIN/EWOULDBLOCK
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue;
                } else {
                    std::cout << "Write Failed: " << std::strerror(errno) << std::endl;
                    break;
                }
            } else {
                bytesWritten += writeResult;
            }
        }


        //Close connection
        close(connectionFD);

        std::cout << "-------------------Closing Connection-------------------" << std::endl;
    }
}

SSL* https::Server::makeSSLConnection(int fd) {
    //Create new ssl state
    SSL *ssl = SSL_new(sslCtx);
    if (ssl == nullptr) {
        char buffer[256];
        ERR_error_string(ERR_get_error(), buffer);
        std::string error(buffer);
        throw std::runtime_error("Creating SSL State Failed: "+error);
    }

    //Copy client to SSL
    SSL_set_fd(ssl, fd);

    //Handshake
    while (true) {
        int handShakeResult = SSL_accept(ssl);
        if (handShakeResult <= 0) { //Unsuccessful handshake
            int sslError = SSL_get_error(ssl, handShakeResult);
            switch (sslError) {
                case SSL_ERROR_WANT_ACCEPT | SSL_ERROR_WANT_CONNECT | SSL_ERROR_WANT_READ |SSL_ERROR_WANT_WRITE | SSL_ERROR_WANT_X509_LOOKUP:
                    continue;
                case SSL_ERROR_SSL:
                    std::cout << "SSL_ERROR_SSL" << std::endl;
                    return nullptr;
                case SSL_ERROR_ZERO_RETURN:
                    break;
                case SSL_ERROR_SYSCALL:
                    if (errno == EINTR) {
                        continue;
                    } else {
                        std::cout << "Error: " << std::strerror(errno) << std::endl;
                        return nullptr;
                    }
                default:
                    continue;
            }
        } else {
            std::cout << "Handshake Successful" << std::endl;
            break;
        }
    }

    return ssl;
}

void https::Server::loadHTML(const std::string &path) {
    //Open file
    std::ifstream file(path);
    if (!file.is_open()) {
        throw std::runtime_error("Opening HTML File Failed");
    }
    //Write into memory
    htmlText = std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
}

void https::Server::setupSocketEpoll(int epollFD, https::Socket httpsSocket, https::Socket httpSocket) {
    //Add sockets to epoll
    struct epoll_event epollEvent{};
    epollEvent.events = EPOLLIN;
    epollEvent.data.fd = httpsSocket.getSocketFD();
    if (epoll_ctl(epollFD, EPOLL_CTL_ADD, httpsSocket.getSocketFD(), &epollEvent) < 0) {
        std::string error = std::strerror(errno);
        throw std::runtime_error("Adding HTTPS Socket to Epoll Failed: " + error);
    }
    epollEvent.data.fd = httpSocket.getSocketFD();
    if (epoll_ctl(epollFD, EPOLL_CTL_ADD, httpSocket.getSocketFD(), &epollEvent) < 0) {
        std::string error = std::strerror(errno);
        throw std::runtime_error("Adding HTTP Socket to Epoll Failed: " + error);
    }
}

SSL_CTX *https::Server::setupSSL(char *certFile, char *keyFile) {
    //Create SSL context with flexible TLS methods
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == nullptr) {
        char buffer[bufferSize];
        ERR_error_string(ERR_get_error(), buffer);
        std::string error(buffer);
        throw std::runtime_error("SSL Context Creation Failed: "+error);
    }

    //Load certificate
    if (SSL_CTX_use_certificate_file(ctx, certFile, SSL_FILETYPE_PEM) <= 0) {
        char buffer[bufferSize];
        ERR_error_string(ERR_get_error(), buffer);
        std::string error(buffer);
        throw std::runtime_error("Loading Certificate Failed: "+error);

    }

    //Load private key
    if (SSL_CTX_use_PrivateKey_file(ctx, keyFile, SSL_FILETYPE_PEM) <= 0) {
        char buffer[bufferSize];
        ERR_error_string(ERR_get_error(), buffer);
        std::string error(buffer);
        throw std::runtime_error("Loading Private Key Failed: "+error);

    }

    //Check if private key matches certificate
    if (SSL_CTX_check_private_key(ctx) <= 0) {
        char buffer[bufferSize];
        ERR_error_string(ERR_get_error(), buffer);
        std::string error(buffer);
        throw std::runtime_error("Checking Private Key Failed: "+error);
    }

    return ctx;
}

void https::Server::setupSignalEpoll(int epollFD, int sigExitFD, int sigPipeFD) {
    //Add SIGINT/SIGTERM to epoll
    struct epoll_event signalExitEvent{};
    signalExitEvent.events = EPOLLIN;
    signalExitEvent.data.fd = sigExitFD;
    if (epoll_ctl(epollFD, EPOLL_CTL_ADD, sigExitFD, &signalExitEvent) < 0) {
        std::string error = std::strerror(errno);
        throw std::runtime_error("Adding SIGINT/SIGTERM to Epoll Failed: " + error);
    }

    //Add SIGPIPE to epoll
    struct epoll_event signalPipeEvent{};
    signalPipeEvent.events = EPOLLIN;
    signalPipeEvent.data.fd = sigPipeFD;
    if (epoll_ctl(epollFD, EPOLL_CTL_ADD, sigPipeFD, &signalPipeEvent) < 0) {
        std::string error = std::strerror(errno);
        throw std::runtime_error("Adding SIGPIPE to Epoll Failed: " + error);
    }
}

int https::Server::setupExitFD() {
    //SIGINT/SIGTERM FD
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    if (pthread_sigmask(SIG_BLOCK, &mask, nullptr) > 0) { //Block signals
        std::string error = std::strerror(errno);
        throw std::runtime_error("Changing Signal Mask Failed: " + error);
    }

    int fd = signalfd(-1, &mask, 0);
    if (fd < 0) {
        std::string error = std::strerror(errno);
        throw std::runtime_error("Creating SIGINT/SIGTERM FD Failed: "+error);
    }

    return fd;
}

int https::Server::setupPipeFD() {
    //SIGPIPE FD
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGPIPE);
    if (pthread_sigmask(SIG_BLOCK, &mask, nullptr) > 0) { //Block signals
        std::string error = std::strerror(errno);
        throw std::runtime_error("Changing Signal Mask Failed: " + error);
    }

    int fd = signalfd(-1, &mask, 0);
    if (fd < 0) {
        std::string error = std::strerror(errno);
        throw std::runtime_error("Creating SIGPIPE FD Failed: "+error);
    }

    return fd;
}

void https::Server::processSigExit() {
    std::cout << "SIGINT or SIGTERM received. Shutting down." << std::endl;
    end();
    exit(1);
}

int https::Server::createWorkerEpoll() {
    //Create epoll
    int epollFD = epoll_create1(0);
    if (epollFD < 0) {
        std::string error = std::strerror(errno);
        throw std::runtime_error("Epoll Creation Failed: " + error);
    }

    return epollFD;
}

void https::Server::handleListenerEvents(int threadCount) {
    int workerIterator = 0;
    while (true) {
        //Wait for epoll event
        struct epoll_event epollEvent{};
        int waitResult = epoll_wait(listenerEpollFD, &epollEvent, 1, -1);
        if (waitResult < 0) {
            std::string error = std::strerror(errno);
            throw std::runtime_error("Socket EPOLL Wait Failed: " + error);
        }

        if (epollEvent.data.fd == sigExitFD) { //SIGINT/SIGTERM
            processSigExit();
        } else if (epollEvent.data.fd == sigPipeFD) { //SIGPIPE
            std::cout << "SIGPIPE received. Ignoring." << std::endl;
        } else { //Socket events
            //Initialize client address
            struct sockaddr_in clientAddress{};
            socklen_t clientAddressLength = sizeof(clientAddress);
            char clientAddressBuffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(clientAddress.sin_addr), clientAddressBuffer, INET_ADDRSTRLEN);

            //Accept client connection
            int socketFD = epollEvent.data.fd;
            int acceptedFD = accept(socketFD, (struct sockaddr *) &clientAddress, &clientAddressLength);
            if (acceptedFD < 0) {
                std::cout << "Accept Failed: " << std::strerror(errno) << std::endl;
                continue;
            }
            fdCount++;

            //Set non-blocking
            https::Socket::setNonBlocking(acceptedFD);

            if (socketFD == httpsSocket.getSocketFD()) {
                std::cout << "--------------------HTTPS Connection--------------------" << std::endl;
                //Distribute client connection to worker thread
                struct epoll_event workerEvent{};
                workerEvent.events = EPOLLIN | EPOLLOUT | EPOLLET;
                workerEvent.data.fd = acceptedFD;
                if (epoll_ctl(httpsEpollFDs[workerIterator], EPOLL_CTL_ADD, acceptedFD, &workerEvent) < 0) {
                    std::string error = std::strerror(errno);
                    throw std::runtime_error("Adding Client Connection to Worker Epoll Failed: " + error);
                }

                //Increment worker iterator
                if (workerIterator == threadCount - 1) {
                    workerIterator = 0;
                } else {
                    workerIterator++;
                }
            } else {
                std::cout << "--------------------HTTP  Connection--------------------" << std::endl;
                //Assign to HTTP epoll
                struct epoll_event httpEvent{};
                httpEvent.events = EPOLLIN | EPOLLET;
                httpEvent.data.fd = acceptedFD;
                if (epoll_ctl(httpEpollFD, EPOLL_CTL_ADD, acceptedFD, &httpEvent) < 0) {
                    std::string error = std::strerror(errno);
                    throw std::runtime_error("Adding Client Connection to HTTP Epoll Failed: " + error);
                }
            }
        }
    }
}

https::HttpRequest* https::Server::processRead(SSL *ssl) {
    //Read client parsedReq until EOF
    std::string req;
    while (true) {
        char buffer[bufferSize];
        int readResult = SSL_read(ssl, buffer, bufferSize);

        if (readResult < 0) {
            int error = SSL_get_error(ssl, readResult);
            if (error == SSL_ERROR_WANT_READ) break;
            if (error == SSL_ERROR_ZERO_RETURN) break;
            if (error == SSL_ERROR_NONE) continue;
            if (error == SSL_ERROR_WANT_WRITE) {
                break;
            }
            std::cout << "SSL Read Failed: " << error << std::endl;
            break;
        } else if (readResult == 0) {
            break;
        } else {
            req += std::string(buffer, readResult);
        }
    }

    //Print request
    std::cout << req << std::endl;

    //Parse request
    return new HttpRequest(req);
}

void https::Server::processWrite(SSL *ssl, https::HttpRequest *request) {
    //Initialise response
    std::string response;

    //Only handle GET requests, reject the rest
    if (request->method != "GET") {
        response = "HTTP/1.1 405 Method Not Allowed\r\n\r\n";
    } else {
        response = https::generateResponse(htmlText);
    }

    //Prepare response
    char resBuffer[response.length()];
    strcpy(resBuffer, response.c_str());
    int resBufferLen = response.length();
    int bytesWritten = 0;

    //Write until EOF
    while (bytesWritten < resBufferLen) {
        int writeResult = SSL_write(ssl, resBuffer + bytesWritten, resBufferLen - bytesWritten);
        if (writeResult <= 0) {
            int error = SSL_get_error(ssl, writeResult);
            //Check if SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE
            if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
                continue; //Write again
            }
            //Else
            std::cout << "SSL Write Failed: " << error << std::endl;
            break;
        } else {
            bytesWritten += writeResult;
        }
    }

    //Delete request
    delete request;
}

void https::Server::closeConnection(SSL *ssl, int fd, int workerID) {
    //Remove from connections maps
    connectionsSSLs[workerID].erase(fd);
    connectionsRequests[workerID].erase(fd);

    //Close SSL connection
    SSL_shutdown(ssl);
    SSL_free(ssl);

    //Close socket
    close(fd);

    std::cout << "-------------------Closing Connection-------------------" << std::endl;
}







