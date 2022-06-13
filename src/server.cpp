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

https::Server::Server(char *certFile, char *keyFile, Socket httpsSocket, Socket httpSocket, const std::string& htmlFilePath, int httpsThreadCount, int httpThreadCount)
        : httpsSocket(httpsSocket), httpSocket(httpSocket) {
    loadHTML(htmlFilePath);
    sslCtx = setupSSL(certFile, keyFile);
    sigExitFD = setupExitFD();
    sigPipeFD = setupPipeFD();
    this->httpsThreadCount = httpsThreadCount;
    this->httpThreadCount = httpThreadCount;

    //Setup listener epoll
    listenerEpollFD = epoll_create1(0);
    setupSocketEpoll(listenerEpollFD, httpsSocket, httpSocket);
    setupSignalEpoll(listenerEpollFD, sigExitFD, sigPipeFD);

    //Setup HTTPS worker epolls
    httpsEpollFDs = new int[httpsThreadCount];
    for (int i = 0; i < httpsThreadCount; i++) {
        httpsEpollFDs[i] = createWorkerEpoll();
        std::cout << "Created epoll FD " << httpsEpollFDs[i] << std::endl;
    }

    //Setup HTTP
    httpEpollFDs = new int[httpThreadCount];
    for (int i = 0; i < httpThreadCount; i++) {
        httpEpollFDs[i] = createWorkerEpoll();
        std::cout << "Created epoll FD " << httpEpollFDs[i] << std::endl;
    }
}

void https::Server::start() {
    std::cout << "\n--------------------Server  Starting--------------------" << std::endl;

    //Create worker threads to handle HTTPS connections
    for (int i = 0; i < httpsThreadCount; i++) {
        std::thread workerThread(&https::Server::handleHTTPS, this, httpsEpollFDs[i]);
        workerThread.detach();
    }

    //Create worker threads to handle HTTP connections
    for (int j = 0; j < httpThreadCount; j++) {
        std::thread workerThread(&https::Server::handleHTTP, httpEpollFDs[j]);
        workerThread.detach();
    }

    //Starts listening for httpsEpollFDs
    handleListenerEvents();
}

void https::Server::end() {
    //Clean up
    SSL_CTX_free(sslCtx);
    httpSocket.end();
    httpsSocket.end();
}

void https::Server::handleHTTPS(int epollFD) {
    while (true) {
        //Wait for epoll event
        struct epoll_event epollEvents[10000];
        int waitResult = epoll_wait(epollFD, epollEvents, 10000, -1);
        if (waitResult < 0) {
            std::string error = std::strerror(errno);
            throw std::runtime_error("Worker Wait Failed: " + error);
        }


        for (int i = 0; i < waitResult; i++) {
            //Get connection struct from epoll event
            auto *connection = (https::Connection *) epollEvents[i].data.ptr;
            int fd = connection->fd;
            std::cout << "Received Connection: " << epollEvents[i].data.ptr << " | "<< connection->state << " | "<< epollEvents[i].events << std::endl;

            if (epollEvents[i].events & EPOLLIN) { //EPOLLIN
                switch (connection->state) {
                    case 0: //TLS not yet established
                        //Establish TLS
                        connection->ssl = makeSSLConnection(fd);
                        //Update state and read if TLS established
                        if (connection->ssl != nullptr) {
                            connection->state = 1;
                            //Read immediately
                            processRead(&connection);
                        } else preemptClose(connection->ssl, connection->fd);
                        break;
                    case 1: //Waiting for read
                        processRead(&connection);
                        break;
                    default:
                        throw std::runtime_error("Invalid Connection State");
                }
            }
            if (epollEvents[i].events & EPOLLOUT) { //EPOLLOUT
                switch (connection->state) {
                    case 0 : //TLS not yet established
                        //Establish TLS
                        connection->ssl = makeSSLConnection(fd);
                        //Update state
                        if (connection->ssl != nullptr) {
                            connection->state = 1;
                        } else preemptClose(connection->ssl, connection->fd);
                        break;
                    case 1: //Waiting for read
                        break; //EPOLLOUT, not certain whether you can write
                    case 2: //Waiting for write
                        processWrite(&connection);
                        //Update connection state
                        connection->state = 1;
                        //closeConnection(&connection);
                        continue;
                    default:
                        throw std::runtime_error("Invalid Connection State");
                }
            }
            if ((epollEvents[i].events & EPOLLERR) || (epollEvents[i].events & EPOLLHUP)) {
                //Get SSL
                closeConnection(&connection);
            }
        }
    }
}

void https::Server::handleHTTP(int epollFD) {
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

            if (epollEvents[i].events & EPOLLOUT) { //EPOLLIN
                //Write response until EOF
                char *res = https::generateRedirect();
                size_t resSize = strlen(res);
                ssize_t bytesWritten = 0;
                while (bytesWritten < resSize) {
                    ssize_t writeResult = write(fd, res, resSize);
                    if (writeResult < 0) {
                        //Check for EAGAIN/EWOULDBLOCK
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            break;
                        } else {
                            std::cout << "Write Failed: " << std::strerror(errno) << std::endl;
                            break;
                        }
                    } else {
                        continue;
                    }
                }

                //Close connection
                shutdown(fd, 0);
                close(fd);
            }
            if ((epollEvents[i].events & EPOLLERR) || (epollEvents[i].events & EPOLLHUP)) {
                //Close connection
                close(fd);
            }
        }
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
            switch (sslError) { //Break = break loop, Continue = keep looping
                case SSL_ERROR_WANT_ACCEPT | SSL_ERROR_WANT_CONNECT | SSL_ERROR_WANT_READ |SSL_ERROR_WANT_WRITE | SSL_ERROR_WANT_X509_LOOKUP | SSL_ERROR_ZERO_RETURN:
                    continue; //Try again
                case SSL_ERROR_SSL:
                    std::cout << "SSL_ERROR_SSL" << std::endl;
                    return ssl;
                case SSL_ERROR_ZERO_RETURN:
                    break;
                case SSL_ERROR_SYSCALL:
                    if (errno == EINTR) {
                        continue;
                    } else {
                        std::cout << "Error: " << std::strerror(errno) << std::endl;
                        return ssl;
                    }
                default:
                    break;
            }
            break;
        } else {
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

void https::Server::handleListenerEvents() {
    int httpsIterator = 0;
    int httpIterator = 0;

    while (true) {
        //Wait for epoll event
        struct epoll_event epollEvents[10000];
        int waitResult = epoll_wait(listenerEpollFD, epollEvents, 10000, -1);
        if (waitResult < 0) {
            std::string error = std::strerror(errno);
            throw std::runtime_error("Socket EPOLL Wait Failed: " + error);
        }

        for (int i = 0; i < waitResult; i++) {
            if (epollEvents[i].data.fd == sigExitFD) { //SIGINT/SIGTERM
                processSigExit();
            } else if (epollEvents[i].data.fd == sigPipeFD) { //SIGPIPE
                std::cout << "SIGPIPE received. Ignoring." << std::endl;
            } else { //Socket events
                //Initialize client address
                struct sockaddr_in clientAddress{};
                socklen_t clientAddressLength = sizeof(clientAddress);
                char clientAddressBuffer[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(clientAddress.sin_addr), clientAddressBuffer, INET_ADDRSTRLEN);

                //Accept client connection
                int socketFD = epollEvents[i].data.fd;
                int acceptedFD = accept(socketFD, (struct sockaddr *) &clientAddress, &clientAddressLength);
                if (acceptedFD < 0) {
                    std::cout << "Accept Failed: " << std::strerror(errno) << std::endl;
                    continue;
                }

                //Set non-blocking
                https::Socket::setNonBlocking(acceptedFD);

                if (socketFD == httpsSocket.getSocketFD()) {
                    std::cout << "--------------------HTTPS Connection--------------------" << std::endl;
                    //Create struct connection for client
                    auto *connection = new https::Connection(acceptedFD, httpsSocket.getPort());
                    //Distribute client connection to worker thread
                    struct epoll_event workerEvent{};
                    workerEvent.events = EPOLLIN | EPOLLOUT | EPOLLET;
                    workerEvent.data.ptr = connection;
                    std::cout << "Adding Connection: " << connection << std::endl;
                    if (epoll_ctl(httpsEpollFDs[httpsIterator], EPOLL_CTL_ADD, acceptedFD, &workerEvent) < 0) {
                        std::string error = std::strerror(errno);
                        throw std::runtime_error("Adding Client Connection to Worker Epoll Failed: " + error);
                    }

                    //Increment worker iterator
                    if (httpsIterator == httpsThreadCount - 1) {
                        httpsIterator = 0;
                    } else {
                        httpsIterator++;
                    }
                } else {
                    std::cout << "--------------------HTTP  Connection--------------------" << std::endl;
                    //Distribute client connection to worker thread
                    struct epoll_event workerEvent{};
                    workerEvent.events = EPOLLOUT | EPOLLET;
                    workerEvent.data.fd = acceptedFD;
                    if (epoll_ctl(httpEpollFDs[httpIterator], EPOLL_CTL_ADD, acceptedFD, &workerEvent) < 0) {
                        std::string error = std::strerror(errno);
                        throw std::runtime_error("Adding Client Connection to Worker Epoll Failed: " + error);
                    }

                    //Increment worker iterator
                    if (httpIterator == httpThreadCount - 1) {
                        httpIterator = 0;
                    } else {
                        httpIterator++;
                    }
                }
            }
        }
    }
}

void https::Server::processRead(https::Connection **conPtr) {
    auto *connection = *conPtr;
    //Read client parsedReq until EOF
    std::string req;
    while (true) {
        char buffer[bufferSize];
        int readResult = SSL_read(connection->ssl, buffer, bufferSize);
        //std::cout << "Read Result: " << readResult << std::endl;

        if (readResult < 0) {
            int error = SSL_get_error(connection->ssl, readResult);
            //std::cout << "SSL Read Error: " << error << std::endl;
            if (error == SSL_ERROR_WANT_READ) break;
            if (error == SSL_ERROR_ZERO_RETURN) break;
            if (error == SSL_ERROR_NONE) continue;
            if (error == SSL_ERROR_WANT_WRITE) break;
            std::cout << "SSL Read Failed: " << error << std::endl;
            break;
        } else if (readResult == 0) { //EOF
            break;
        } else {
            req += std::string(buffer, readResult);
        }
    }

    if (req.length() > 0) {
        //Update connection with after parsing
        std::stringstream requestStream(req);
        std::string line;
        for (int i = 0; std::getline(requestStream, line); i++) {
            if (i == 0) {
                //Parse the first line
                std::stringstream firstLineStream(line);
                std::string firstLine;
                std::getline(firstLineStream, firstLine, ' ');
                connection->method = firstLine;
                std::getline(firstLineStream, firstLine, ' ');
                connection->path = firstLine;
                std::getline(firstLineStream, firstLine, ' ');
                connection->version = firstLine;
            } else {
                break;
            }
        }

        //Update connection state
        connection->state = 2;
    } else {
        return; //No data to read
    }

    std::cout << "Read Connection: " << connection << " | " << connection->state << " | " << connection->method << std::endl;
}

void https::Server::processWrite(https::Connection **conPtr) {
    auto *connection = *conPtr;
    //Initialise response
    std::string response;

    //Only handle GET requests, reject the rest
    if (connection->method == "GET") {
        response = https::generateResponse(htmlText);
    } else {
        response = "HTTP/1.1 405 Method Not Allowed\r\n\r\n";
    }

    //Prepare response
    char resBuffer[response.length()];
    strcpy(resBuffer, response.c_str());
    int resBufferLen = response.length();
    int bytesWritten = 0;

    std::cout << "Writing Connection: " << connection << " | " << connection->method << std::endl;

    //Write until EOF
    while (bytesWritten < resBufferLen) {
        int writeResult = SSL_write(connection->ssl, resBuffer + bytesWritten, resBufferLen - bytesWritten);
        if (writeResult <= 0) {
            int error = SSL_get_error(connection->ssl, writeResult);
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
}

void https::Server::closeConnection(https::Connection **conPtr) {
    auto *connection = *conPtr;
    //Close SSL connection
    SSL_shutdown(connection->ssl);
    SSL_free(connection->ssl);

    //Close socket
    close(connection->fd);

    //delete connection;
    delete connection;
}

void https::Server::preemptClose(SSL *ssl, int fd) {
    std::cout << "Accepting SSL Failed. Closing Connection." << std::endl;
    close(fd);
    SSL_free(ssl);
}







