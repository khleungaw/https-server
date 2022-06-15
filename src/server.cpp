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
#include <utility>
#include "server.h"
#include "socket.h"
#include "message.h"

https::Server::Server(char *certFile, char *keyFile, std::string domain, int httpsPort, int httpPort, const std::string& htmlFilePath) {
    loadHTML(htmlFilePath);
    serverDomain = std::move(domain);
    //Create sockets
    this->httpsSocket = new Socket(httpsPort);
    this->httpSocket = new Socket(httpPort);
    //Initialize OpenSSL
    sslCtx = setupSSL(certFile, keyFile);
    //Set up fd for signals
    sigExitFD = setupExitFD();
    sigPipeFD = setupPipeFD();
    //Setup listener epoll
    mainEpollFD = epoll_create1(0);
    setupSocketEpoll();
    setupSignalEpoll();
}

SSL_CTX *https::Server::setupSSL(char *certFile, char *keyFile) {
    //Create SSL context with flexible TLS methods
    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    SSL_load_error_strings();

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == nullptr) {
        char buffer[kBufferSize];
        ERR_error_string(ERR_get_error(), buffer);
        std::string error(buffer);
        throw std::runtime_error("SSL Context Creation Failed: "+error);
    }

    //Load certificate
    if (SSL_CTX_use_certificate_file(ctx, certFile, SSL_FILETYPE_PEM) <= 0) {
        char buffer[kBufferSize];
        ERR_error_string(ERR_get_error(), buffer);
        std::string error(buffer);
        throw std::runtime_error("Loading Certificate Failed: "+error);

    }

    //Load private key
    if (SSL_CTX_use_PrivateKey_file(ctx, keyFile, SSL_FILETYPE_PEM) <= 0) {
        char buffer[kBufferSize];
        ERR_error_string(ERR_get_error(), buffer);
        std::string error(buffer);
        throw std::runtime_error("Loading Private Key Failed: "+error);

    }

    //Check if private key matches certificate
    if (SSL_CTX_check_private_key(ctx) <= 0) {
        char buffer[kBufferSize];
        ERR_error_string(ERR_get_error(), buffer);
        std::string error(buffer);
        throw std::runtime_error("Checking Private Key Failed: "+error);
    }

    return ctx;
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

void https::Server::setupSocketEpoll() {
    //Add sockets to epoll
    struct epoll_event epollEvent{};
    epollEvent.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
    epollEvent.data.fd = httpsSocket->fd;
    if (epoll_ctl(mainEpollFD, EPOLL_CTL_ADD, httpsSocket->fd, &epollEvent) < 0) {
        std::string error = std::strerror(errno);
        throw std::runtime_error("Adding HTTPS Socket to Epoll Failed: " + error);
    }
    epollEvent.data.fd = httpSocket->fd;
    if (epoll_ctl(mainEpollFD, EPOLL_CTL_ADD, httpSocket->fd, &epollEvent) < 0) {
        std::string error = std::strerror(errno);
        throw std::runtime_error("Adding HTTP Socket to Epoll Failed: " + error);
    }
}

void https::Server::setupSignalEpoll() const {
    //Add SIGINT/SIGTERM to epoll
    struct epoll_event signalExitEvent{};
    signalExitEvent.events = EPOLLIN | EPOLLONESHOT;
    signalExitEvent.data.fd = sigExitFD;
    if (epoll_ctl(mainEpollFD, EPOLL_CTL_ADD, sigExitFD, &signalExitEvent) < 0) {
        std::string error = std::strerror(errno);
        throw std::runtime_error("Adding SIGINT/SIGTERM to Epoll Failed: " + error);
    }

    //Add SIGPIPE to epoll
    struct epoll_event signalPipeEvent{};
    signalPipeEvent.events = EPOLLIN | EPOLLET;
    signalPipeEvent.data.fd = sigPipeFD;
    if (epoll_ctl(mainEpollFD, EPOLL_CTL_ADD, sigPipeFD, &signalPipeEvent) < 0) {
        std::string error = std::strerror(errno);
        throw std::runtime_error("Adding SIGPIPE to Epoll Failed: " + error);
    }
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

void https::Server::start(int threadPoolSize) {
    //Create worker threads
    for (int i = 0; i < threadPoolSize-1; i++) {
        std::thread worker(&https::Server::handleEvents, this);
        worker.detach();
    }

    //Starts listening
    handleEvents();
}

void https::Server::end() {
    //Clean up
    SSL_CTX_free(sslCtx);
    https::Socket::end(httpsSocket->fd);
    https::Socket::end(httpSocket->fd);
}

void https::Server::handleEvents() {
    while (true) {
        //Wait for epoll event
        struct epoll_event epollEvents[10000];
        int waitResult = epoll_wait(mainEpollFD, epollEvents, 10000, -1);
        if (waitResult < 0) {
            std::string error = std::strerror(errno);
            throw std::runtime_error("Socket EPOLL Wait Failed: " + error);
        }

        for (int i = 0; i < waitResult; i++) {
            if (epollEvents[i].data.fd == httpsSocket->fd || //Socket events
                epollEvents[i].data.fd == httpSocket->fd ) {
                processSocket(epollEvents[i].data.fd);
                continue;
            }
            if (epollEvents[i].data.fd == sigExitFD) { //SIGINT/SIGTERM
                processSigExit();
                continue;
            }
            if (epollEvents[i].data.fd == sigPipeFD) { //SIGPIPE
                //Ignore
                continue;
            }
            //Else, must be connections
            auto *connection = (https::Connection *)epollEvents[i].data.ptr;
            if (connection->port == httpsSocket->port)
                processHTTPS(epollEvents[i]);
            else
                processHTTP(epollEvents[i]);
        }
    }
}

void https::Server::processSocket(int socketFD) {
    //Initialize client address
    struct sockaddr_in clientAddress{};
    socklen_t clientAddressLength = sizeof(clientAddress);

    //Accept client connection
    int acceptedFD;
    acceptedFD = accept(socketFD, (struct sockaddr *)&clientAddress, &clientAddressLength);
    if (acceptedFD < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            rearmSocket(socketFD);
            return;
        } else {
            std::cout << "Accept Failed: " << std::strerror(errno) << std::endl;
            rearmSocket(socketFD);
            return;
        }
    }

    //Set non-blocking
    https::Socket::setNonBlocking(acceptedFD);

    //Create struct connection for client
    int port = (socketFD == httpsSocket->fd) ? httpsSocket->port : httpSocket->port;
    uint32_t connectionEvents = (socketFD == httpsSocket->fd) ?
                                (EPOLLIN | EPOLLET | EPOLLONESHOT) : (EPOLLOUT | EPOLLET | EPOLLONESHOT);
    auto *connection = new https::Connection(acceptedFD, port);

    //Distribute client connection to worker thread
    struct epoll_event event{};
    event.events = connectionEvents;
    event.data.ptr = connection;
    std::cout << "Adding Connection: " << connection << std::endl;
    if (epoll_ctl(mainEpollFD, EPOLL_CTL_ADD, acceptedFD, &event) < 0) {
        std::string error = std::strerror(errno);
        throw std::runtime_error("Adding Client Connection to Worker Epoll Failed: " + error);
    }

    //Rearm
    rearmSocket(socketFD);
}

void https::Server::processHTTPS(epoll_event event) {
    //Get connection struct from epoll event
    auto *connection = (https::Connection *) event.data.ptr;
    std::cout << std::this_thread::get_id() <<": Received HTTPS Connection: " << event.data.ptr << " | "<< connection->state << " | "<< event.events << std::endl;

    if ((event.events & EPOLLERR) || (event.events & EPOLLHUP)) {
        //Close connection
        connection->end();
        return;
    }
    if (event.events & EPOLLIN) { //EPOLLIN
        switch (connection->state) {
            case 0: { //TLS not yet established
                //Establish TLS
                makeSSLConnectionLoop(&connection);
                break;
            }
            case 1: //Waiting for read
                sslRead(&connection);
                break;
            case 2: //Waiting for write
                //rearmConnection(&connection);
                break;
            default:
                throw std::runtime_error("Invalid Connection State");
        }
    }
    if (event.events & EPOLLOUT) { //EPOLLOUT
        switch (connection->state) {
            case 0 : { //TLS not yet established
                makeSSLConnectionLoop(&connection);
                break;
            }
            case 1: //Waiting for read
                //rearmConnection(&connection);
                break; //EPOLLOUT, not certain whether you can write
            case 2: //Waiting for write
                sslWrite(&connection);
                return;
            default:
                throw std::runtime_error("Invalid Connection State");
        }
    }
}

void https::Server::processHTTP(epoll_event event) const {
    //Get connection struct from epoll event
    auto *connection = (https::Connection *) event.data.ptr;
    std::cout << "Received HTTP Connection: " << event.data.ptr << " | "<< connection->state << " | "<< event.events << std::endl;

    if ((event.events & EPOLLERR) || (event.events & EPOLLHUP)) {
        connection->end();
        return;
    }

    if (event.events & EPOLLOUT) { //EPOLLOUT
        std::string res = https::generateRedirect(serverDomain, httpsSocket->port);
        std::cout << "HTTP Response: \n" << res << std::endl;
        size_t resSize = res.length();
        char *resBuffer = new char[resSize];
        strcpy(resBuffer, res.c_str());
        ssize_t writeResult = write(connection->fd, resBuffer, resSize);
        std::cout << "Wrote: " << writeResult << std::endl;
        if (writeResult <= 0) {
            switch (errno) {
                case EAGAIN:
                    rearmConnection(&connection, EPOLLOUT);
                    break;
                default:
                    std::cout << "HTTP Write Failed: " << errno << std::endl;
            }
        } else {
            connection->end();
        }
    }
}

void https::Server::processSigExit() {
    std::cout << "SIGINT or SIGTERM received. Shutting down." << std::endl;
    end();
    exit(1);
}

__attribute__((unused)) void https::Server::makeSSLConnection(https::Connection **conPtr) {
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
            throw std::runtime_error("Setting SSL File Descriptor Failed: "+std::string(buffer));
        }

        connection->ssl = ssl;
    }

    //Attempt handshake until success
    std::cout << std::this_thread::get_id() << ": SSL Handshake : " << connection << " | " << SSL_state_string_long(connection->ssl) << std::endl;
    int handshakeResult = SSL_accept(connection->ssl);
    if (handshakeResult < 0) { //Handshake failed
        int sslError = SSL_get_error(connection->ssl, handshakeResult);
        std::cout << "SSL Error: " << sslError << " | " << SSL_state_string_long(connection->ssl) << " | " << SSL_is_init_finished(connection->ssl) << std::endl;
        switch (sslError) {
            case SSL_ERROR_WANT_READ:  //2, Need to read more data
                rearmConnection(&connection, EPOLLIN);
                break;
            case SSL_ERROR_WANT_WRITE: //3, Need to write more data
                rearmConnection(&connection, EPOLLOUT);
                break;
            case SSL_ERROR_SSL: //1, General SSL error
                char buffer[256];
                std::cout << ERR_error_string(ERR_get_error(), buffer) << std::endl;
                std::cout << SSL_state_string_long(connection->ssl) << std::endl;
                SSL_free(connection->ssl);
                connection->ssl = nullptr;
                connection->end();
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
        rearmConnection(&connection, EPOLLIN);
    }
}

void https::Server::makeSSLConnectionLoop(https::Connection **conPtr) {
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
            throw std::runtime_error("Setting SSL File Descriptor Failed: "+std::string(buffer));
        }

        connection->ssl = ssl;
    }

    //Attempt handshake until success
    std::cout << std::this_thread::get_id() << ": SSL Handshake : " << connection << " | " << SSL_state_string_long(connection->ssl) << std::endl;
    while (true) {
        int handshakeResult = SSL_accept(connection->ssl);
        if (handshakeResult < 0) { //Handshake failed
            int sslError = SSL_get_error(connection->ssl, handshakeResult);
            std::cout << "SSL Error: " << sslError << " | " << SSL_state_string_long(connection->ssl) << " | " << SSL_is_init_finished(connection->ssl) << std::endl;
            switch (sslError) {
                case SSL_ERROR_WANT_READ: { //2, Need to read more data
                    //Use select to wait for more data
                    fd_set readFDs;
                    FD_ZERO(&readFDs);
                    FD_SET(connection->fd, &readFDs);
                    select(connection->fd+1, &readFDs, nullptr, nullptr, nullptr);
                    continue;
                }
                case SSL_ERROR_WANT_WRITE: { //3, Need to write more data
                    //Use select to wait for more data
                    fd_set writeFDs;
                    FD_ZERO(&writeFDs);
                    FD_SET(connection->fd, &writeFDs);
                    select(connection->fd+1, nullptr, &writeFDs, nullptr, nullptr);
                    continue;
                }
                case SSL_ERROR_SSL: //1, General SSL error
                    char buffer[256];
                    std::cout << ERR_error_string(ERR_get_error(), buffer) << std::endl;
                    std::cout << SSL_state_string_long(connection->ssl) << std::endl;
                    SSL_free(connection->ssl);
                    connection->ssl = nullptr;
                    connection->end();
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
            break;
        } else { //Handshake successful
            connection->state = 1;
            //rearmConnection(&connection, EPOLLIN);
            sslRead(conPtr);
            break;
        }
    }
}

void https::Server::sslRead(https::Connection **connPtr) const {
    auto *connection = *connPtr;
    //Read client parsedReq until EOF
    char buffer[kBufferSize];
    int readResult = SSL_read(connection->ssl, buffer, kBufferSize);
    std::cout << std::this_thread::get_id() << ": Read Connection: " << connection << " | " << connection->state << " | " << readResult << std::endl;

    if (readResult <= 0) {
        int error = SSL_get_error(connection->ssl, readResult);
        switch (error) {
            case SSL_ERROR_WANT_READ:
                rearmConnection(&connection, EPOLLIN);
                break;
            case SSL_ERROR_WANT_WRITE:
                rearmConnection(&connection, EPOLLOUT);
                break;
            case SSL_ERROR_ZERO_RETURN: //TLS connection closed
                connection->end();
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
        rearmConnection(&connection, EPOLLOUT);
    } else { //Read too large , retry with larger buffer size
        char largerBuffer[readResult];
        readResult = SSL_read(connection->ssl, largerBuffer, readResult);
        if (readResult < 0) {
            throw std::runtime_error("SSL Second Read Failed");
        } else {
            connection->setReq(largerBuffer);
            connection->state = 2;
            rearmConnection(&connection, EPOLLOUT);
        }
    }
}

void https::Server::sslWrite(https::Connection **connPtr) {
    auto *connection = *connPtr;
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
    int resBufferLen = strIntLength(response.length());
    int bytesWritten = 0;

    std::cout << std::this_thread::get_id() << ": Writing Connection: " << connection << " | " << connection->method << std::endl;

    //Write until EOF
    int writeResult = SSL_write(connection->ssl, resBuffer + bytesWritten, resBufferLen - bytesWritten);
    if (writeResult <= 0) {
        int error = SSL_get_error(connection->ssl, writeResult);
        switch (error) {
            case SSL_ERROR_WANT_READ:
                rearmConnection(&connection, EPOLLIN);
                break;
            case SSL_ERROR_WANT_WRITE:
                rearmConnection(&connection, EPOLLOUT);
                break;
            case SSL_ERROR_ZERO_RETURN:
                connection->end();
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
        rearmConnection(&connection, EPOLLIN);
    }
}

void https::Server::rearmConnection(https::Connection **connPtr, int events) const {
    std::cout << std::this_thread::get_id() << ": Rearm Connection: " << *connPtr << std::endl;
    auto *connection = *connPtr;
    struct epoll_event event{};
    event.events = events | EPOLLET | EPOLLONESHOT;
    event.data.ptr = connection;
    epoll_ctl(mainEpollFD, EPOLL_CTL_MOD, connection->fd, &event);
}

void https::Server::rearmSocket(int fd) const {
    struct epoll_event event{};
    event.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
    event.data.fd = fd;
    epoll_ctl(mainEpollFD, EPOLL_CTL_MOD, fd, &event);
}




