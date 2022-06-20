//
// Created by Solace on 6/15/2022.
//

#include <iostream>
#include <cstring>
#include <thread>
#include <algorithm>
#include <utility>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include "server.h"
#include "socket.h"
#include "message.h"
#include "listener_server.h"

https::ListenerServer::ListenerServer
    (char *certFile, char *keyFile, std::string domain, int httpsPort, int httpPort, const std::string &publicFolderPath) :
    Server(certFile, keyFile, std::move(domain), httpsPort, httpPort, publicFolderPath) {
}

void https::ListenerServer::startWithListener(int threadPoolSize) {
    //Change socket epolls to without EPOLLONESHOT
    struct epoll_event epollEvent{};
    epollEvent.events = EPOLLIN;
    epollEvent.data.fd = httpsSocket->fd;
    if (epoll_ctl(mainEpollFD, EPOLL_CTL_MOD, httpsSocket->fd, &epollEvent) < 0) {
        std::string error = std::strerror(errno);
        throw std::runtime_error("Changing HTTPS Socket Epoll Failed: " + error);
    }
    epollEvent.data.fd = httpSocket->fd;
    if (epoll_ctl(mainEpollFD, EPOLL_CTL_MOD, httpSocket->fd, &epollEvent) < 0) {
        std::string error = std::strerror(errno);
        throw std::runtime_error("Changing HTTP Socket Epoll Failed: " + error);
    }

    //Create epolls for workers
    int epollFDs[threadPoolSize-1];
    for (int i = 0; i < threadPoolSize -1; i++) {
        epollFDs[i] = epoll_create1(0);
    }

    //Create worker threads
    for (int i = 0; i < threadPoolSize-1; i++) {
        std::thread worker(&::https::ListenerServer::workerHandleConnections, this, epollFDs[i]);
        worker.detach();
    }

    //Starts listening
    listenerHandleEvents(epollFDs, threadPoolSize - 1);
}

void https::ListenerServer::listenerHandleEvents(int *workerEpollFDs, int numWorkers) {
    int workerIterator = 0;
    while (true) {
        //Wait for epoll event
        struct epoll_event epollEvents[10000];
        int waitResult = epoll_wait(mainEpollFD, epollEvents, 10000, -1);
        if (waitResult < 0) {
            std::string error = std::strerror(errno);
            throw std::runtime_error("Socket EPOLL Wait Failed: " + error);
        }

        for (int i = 0; i < waitResult; i++) {
            if (epollEvents[i].data.fd == sigExitFD) { //SIGINT/SIGTERM
                processSigExit();
                continue;
            }
            if (epollEvents[i].data.fd == sigPipeFD) { //SIGPIPE
                //Ignore
                continue;
            }
            if (epollEvents[i].data.fd == httpsSocket->fd || //Socket events
                epollEvents[i].data.fd == httpSocket->fd ) {
                listenerProcessSockets(epollEvents[i].data.fd, workerEpollFDs[workerIterator]);
                if (workerIterator == numWorkers - 1) {
                    workerIterator = 0;
                } else {
                    workerIterator++;
                }
            }
        }
    }
}

void https::ListenerServer::workerHandleConnections(int epollFD) {
    while (true) {
        //Wait for epoll event
        struct epoll_event epollEvents[10000];
        int waitResult = epoll_wait(epollFD, epollEvents, 10000, -1);
        if (waitResult < 0) {
            std::string error = std::strerror(errno);
            throw std::runtime_error("Socket EPOLL Wait Failed: " + error);
        }

        for (int i = 0; i < waitResult; i++) {
            auto *connection = (https::Connection *)epollEvents[i].data.ptr;
            if (connection->port == httpsSocket->port)
                workerProcessHTTPS(epollEvents[i]);
            else
                workerProcessHTTP(epollEvents[i]);
        }
    }
}

void https::ListenerServer::listenerProcessSockets(int socketFD, int epollFD) {
    //Initialize client address
    struct sockaddr_in clientAddress{};
    socklen_t clientAddressLength = sizeof(clientAddress);

    //Accept client connection
    int acceptedFD;
    acceptedFD = accept(socketFD, (struct sockaddr *)&clientAddress, &clientAddressLength);
    if (acceptedFD < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return;
        } else {
            std::cout << "Accept Failed: " << std::strerror(errno) << std::endl;
            return;
        }
    }

    //Set non-blocking
    https::Socket::setNonBlocking(acceptedFD);

    //Create struct connection for client
    int port = (socketFD == httpsSocket->fd) ? httpsSocket->port : httpSocket->port;
    uint32_t connectionEvents = (socketFD == httpsSocket->fd) ?
                                (EPOLLIN | EPOLLOUT | EPOLLET) : (EPOLLOUT | EPOLLET);
    auto *connection = new https::Connection(acceptedFD, port);

    //Distribute client connection to worker thread
    struct epoll_event event{};
    event.events = connectionEvents;
    event.data.ptr = connection;
    //std::cout << "Adding Connection: " << connection << std::endl;
    if (epoll_ctl(epollFD, EPOLL_CTL_ADD, acceptedFD, &event) < 0) {
        std::string error = std::strerror(errno);
        throw std::runtime_error("Adding Client Connection to Worker Epoll Failed: " + error);
    }
}

void https::ListenerServer::workerProcessHTTPS(epoll_event event) {
    //Get connection struct from epoll event
    auto *connection = (https::Connection *) event.data.ptr;
    //std::cout << std::this_thread::get_id() <<": Received HTTPS Connection: " << event.data.ptr << " | "<< connection->state << " | "<< event.events << std::endl;

    if ((event.events & EPOLLERR) || (event.events & EPOLLHUP)) {
        //Close connection
        connection->end();
        return;
    }
    if (event.events & EPOLLIN) { //EPOLLIN
        switch (connection->state) {
            case 0: { //TLS not yet established
                //Establish TLS
                listenerMakeSSLConnection(&connection);
                break;
            }
            case 1: //Waiting for read
                workerSSLRead(&connection);
                break;
            case 2: //Waiting for write
                break;
            default:
                throw std::runtime_error("Invalid Connection State");
        }
    }
    if (event.events & EPOLLOUT) { //EPOLLOUT
        switch (connection->state) {
            case 0 : { //TLS not yet established
                listenerMakeSSLConnection(&connection);
                break;
            }
            case 1: //Waiting for read
                break;
            case 2: //Waiting for write
                workerSSLWrite(&connection);
                return;
            default:
                throw std::runtime_error("Invalid Connection State");
        }
    }
}

void https::ListenerServer::workerProcessHTTP(epoll_event event) {
    //Get connection struct from epoll event
    auto *connection = (https::Connection *) event.data.ptr;
    //std::cout << "Received HTTP Connection: " << event.data.ptr << " | "<< connection->state << " | "<< event.events << std::endl;

    if ((event.events & EPOLLERR) || (event.events & EPOLLHUP)) {
        connection->end();
        return;
    }

    if (event.events & EPOLLOUT) { //EPOLLOUT
        std::string res = https::generateRedirect(serverDomain, httpsSocket->port);
        //std::cout << "HTTP Response: \n" << res << std::endl;
        size_t resSize = res.length();
        char *resBuffer = new char[resSize];
        strcpy(resBuffer, res.c_str());
        ssize_t writeResult = write(connection->fd, resBuffer, resSize);
        //std::cout << "Wrote: " << writeResult << std::endl;
        if (writeResult <= 0) {
            switch (errno) {
                case EAGAIN:
                    break;
                default:
                    std::cout << "HTTP Write Failed: " << errno << std::endl;
            }
        } else {
            connection->end();
        }
    }
}

void https::ListenerServer::listenerMakeSSLConnection(https::Connection **conPtr) {
    auto *connection = *conPtr;
    if (connection->ssl == nullptr) {
        //Create new ssl state
        SSL *ssl = SSL_new(sslCtx);
        if (ssl == nullptr) {
            char buffer[256];
            ERR_error_string(ERR_get_error(), buffer);
            std::string error(buffer);
            throw std::runtime_error("Creating SSL State Failed: "+error);
        }

        //Copy client to SSL
        int biosResult = SSL_set_fd(ssl, connection->fd);
        if (biosResult == 0) {
            char buffer[256];
            ERR_error_string(ERR_get_error(), buffer);
        }

        connection->ssl = ssl;
    }

    //Attempt handshake
    int handshakeResult = SSL_accept(connection->ssl);
    if (handshakeResult < 0) { //Handshake failed
        int sslError = SSL_get_error(connection->ssl, handshakeResult);
        //std::cout << "SSL Error: " << sslError << " | " << SSL_state_string_long(connection->ssl) << " | " << SSL_is_init_finished(connection->ssl) << std::endl;
        switch (sslError) {
            case SSL_ERROR_WANT_READ:  //2, Need to read more data
                break;
            case SSL_ERROR_SSL: //1, General SSL error
                char buffer[256];
                std::cout << ERR_error_string(ERR_get_error(), buffer) << std::endl;
                std::cout << SSL_state_string_long(connection->ssl) << std::endl;
                SSL_free(connection->ssl);
                connection->ssl = nullptr;
                connection->end();
                break;
            case SSL_ERROR_WANT_WRITE: //3, Need to write more data
                break;
            case SSL_ERROR_SYSCALL: //System call error
                char buff[256];
                std::cout << ERR_error_string(ERR_get_error(), buff) << std::endl;
                std::cout << "System Call Error: " << std::strerror(errno) << std::endl;
                if (errno == ECONNRESET) {
                    SSL_free(connection->ssl);
                    connection->ssl = nullptr;
                }
                connection->end();
                break;
            default:
                std::cout << "Unknown Error" << std::endl;
                SSL_free(connection->ssl);
                connection->ssl = nullptr;
                connection->end();
        }
    } else { //Handshake successful
        connection->state = 1;
    }
}

void https::ListenerServer::workerSSLRead(https::Connection **connPtr) {
    auto *connection = *connPtr;
    //Read client parsedReq until EOF
    char buffer[kBufferSize];
    int readResult = SSL_read(connection->ssl, buffer, kBufferSize);
    //std::cout << "Read Connection: " << connection << " | " << connection->state << " | " << readResult << std::endl;

    if (readResult <= 0) {
        int error = SSL_get_error(connection->ssl, readResult);
        switch (error) {
            case SSL_ERROR_WANT_READ:
                break;
            case SSL_ERROR_ZERO_RETURN:
                connection->end();
                break;
            case SSL_ERROR_WANT_WRITE:
                break;
            case SSL_ERROR_SSL:
                SSL_free(connection->ssl);
                connection->ssl = nullptr;
                connection->end();
                std::cout << "SSL Write Failed: " << error << std::endl;
                break;
            default:
                SSL_free(connection->ssl);
                connection->ssl = nullptr;
                connection->end();
                std::cout << "SSL Write Unknown Error: " << error << std::endl;
                break;
        }
    } else if (readResult <= kBufferSize) { //Read successful
        connection->setReq(buffer);
        connection->state = 2;
    } else { //Read too large , retry with larger buffer size
        char largerBuffer[readResult];
        readResult = SSL_read(connection->ssl, largerBuffer, readResult);
        if (readResult < 0) {
            throw std::runtime_error("SSL Second Read Failed");
        } else {
            connection->setReq(largerBuffer);
            connection->state = 2;
        }
    }
}

void https::ListenerServer::workerSSLWrite(https::Connection **connPtr) {
    auto *connection = *connPtr;
    //Initialise response
    char *buffer;
    int bufferSize;

    //Only handle GET requests, reject the rest
    if (connection->method == "GET") {
        //Check if the requested file exists
        if (files.count(connection->path) == 0) {
            //Generate 404 response
            bufferSize = 26;
            buffer = new char[bufferSize];
            strcpy(buffer, "HTTP/1.1 404 Not Found\r\n");
        } else {
            char *header = https::generateHeader(files[connection->path]);
            bufferSize = unsignedLongToInt(strlen(header))+unsignedLongToInt(files[connection->path]->size);
            buffer = new char[bufferSize];
            strcpy(buffer, header);
            memcpy(&buffer[strlen(header)], files[connection->path]->data, files[connection->path]->size);
        }
    } else {
        bufferSize = 35;
        buffer = new char[bufferSize];
        strcpy(buffer, "HTTP/1.1 405 Method Not Allowed\r\n");
    }

    //std::cout << "Writing Connection: " << connection << " | " << connection->method << std::endl;

    //Write until EOF
    int writeResult = SSL_write(connection->ssl, buffer, bufferSize);
    if (writeResult <= 0) {
        int error = SSL_get_error(connection->ssl, writeResult);
        switch (error) {
            case SSL_ERROR_WANT_READ:
                break;
            case SSL_ERROR_ZERO_RETURN:
                connection->end();
                break;
            case SSL_ERROR_WANT_WRITE:
                break;
            case SSL_ERROR_SSL:
                SSL_free(connection->ssl);
                connection->ssl = nullptr;
                connection->end();
                std::cout << "SSL Write Failed: " << error << std::endl;
                break;
            default:
                SSL_free(connection->ssl);
                connection->ssl = nullptr;
                connection->end();
                std::cout << "SSL Write Unknown Error: " << error << std::endl;
                break;
        }
    } else {
        connection->state = 1;  //Update connection state
        connection->clearReq(); //Clear request
    }
    delete[] buffer;
}
