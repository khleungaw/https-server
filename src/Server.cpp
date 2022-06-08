//
// Created by Solace on 6/7/2022.
//

#include <iostream>
#include <unistd.h>
#include <cstring>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <openssl/err.h>
#include <csignal>
#include "../include/Server.h"
#include "Socket.h"

https::Server::Server(char *certFile, char *keyFile, Socket httpsSocket, Socket httpSocket)
        : httpsSocket(httpsSocket), httpSocket(httpSocket) {
    std::cout << "HTTP Socket FD: " << httpsSocket.getSocketFD() << std::endl;
    std::cout << "HTTPS Socket FD: " << httpSocket.getSocketFD() << std::endl;
    //Create SSL context with flexible TLS methods
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    sslCtx = SSL_CTX_new(TLS_server_method());
    if (sslCtx == nullptr) {
        char buffer[256];
        ERR_error_string(ERR_get_error(), buffer);
        std::string error(buffer);
        throw std::runtime_error("SSL Context Creation Failed: "+error);
    }

    //Load certificate
    if (SSL_CTX_use_certificate_file(sslCtx, certFile, SSL_FILETYPE_PEM) <= 0) {
        char buffer[256];
        ERR_error_string(ERR_get_error(), buffer);
        std::string error(buffer);
        throw std::runtime_error("Loading Certificate Failed: "+error);

    }

    //Load private key
    if (SSL_CTX_use_PrivateKey_file(sslCtx, keyFile, SSL_FILETYPE_PEM) <= 0) {
        char buffer[256];
        ERR_error_string(ERR_get_error(), buffer);
        std::string error(buffer);
        throw std::runtime_error("Loading Private Key Failed: "+error);

    }

    //Check if private key matches certificate
    if (SSL_CTX_check_private_key(sslCtx) <= 0) {
        char buffer[256];
        ERR_error_string(ERR_get_error(), buffer);
        std::string error(buffer);
        throw std::runtime_error("Checking Private Key Failed: "+error);
    }

    //Setup epoll
    epollFD = epoll_create1(0);
    if (epollFD < 0) {
        std::string error = std::strerror(errno);
        throw std::runtime_error("Epoll Creation Failed: " + error);
    }

    //Add SIGINT/SIGTERM to epoll
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    if (sigprocmask(SIG_BLOCK, &mask, nullptr) < 0) { //Block signals
        std::string error = std::strerror(errno);
        throw std::runtime_error("Changing Signal Mask Failed: " + error);
    }

    sigExitFD = signalfd(-1, &mask, 0);
    if (sigExitFD < 0) {
        std::string error = std::strerror(errno);
        throw std::runtime_error("Creating SIGINT FD Failed: "+error);
    }

    struct epoll_event signalExitEvent{};
    signalExitEvent.events = EPOLLIN;
    signalExitEvent.data.fd = sigExitFD;
    if (epoll_ctl(epollFD, EPOLL_CTL_ADD, sigExitFD, &signalExitEvent) < 0) {
        std::string error = std::strerror(errno);
        throw std::runtime_error("Adding SIGINT to Epoll Failed: " + error);
    }

    //Add sockets to epoll
    struct epoll_event socketEvent{};
    socketEvent.events = EPOLLIN;
    socketEvent.data.fd = httpsSocket.getSocketFD();
    if (epoll_ctl(epollFD, EPOLL_CTL_ADD, httpsSocket.getSocketFD(), &socketEvent) < 0) {
        std::string error = std::strerror(errno);
        throw std::runtime_error("Adding HTTPS Socket to Epoll Failed: " + error);
    }
    socketEvent.data.fd = httpSocket.getSocketFD();
    if (epoll_ctl(epollFD, EPOLL_CTL_ADD, httpSocket.getSocketFD(), &socketEvent) < 0) {
        std::string error = std::strerror(errno);
        throw std::runtime_error("Adding HTTP Socket to Epoll Failed: " + error);
    }
}

void https::Server::end() {
    //Clean up
    SSL_CTX_free(sslCtx);
    httpSocket.end();
    httpsSocket.end();
}

void https::Server::handleEpochEvents() {
    //Wait for epoll event
    std::cout << "Waiting for client connection..." << std::endl;
    struct epoll_event epollEvent{};
    int epollResult = epoll_wait(epollFD, &epollEvent, 1, -1);
    if (epollResult < 0) {
        std::string error = std::strerror(errno);
        throw std::runtime_error("Waiting on Epoll Failed: " + error);
    }

    //Check if client is coming from https port
    int incomingSocketFD = epollEvent.data.fd;
    if (incomingSocketFD == httpsSocket.getSocketFD()) {
        std::cout << "Client connected on HTTPS port" << std::endl;
        handleHTTPSRequest(incomingSocketFD);
        return;
    } else if (incomingSocketFD == httpSocket.getSocketFD()) {
        std::cout << "Client connected on HTTP port" << std::endl;
        redirectToHTTPS(incomingSocketFD);
        return;
    }

    //Check if event is from signal
    if (epollEvent.data.fd == sigExitFD) {
        std::cout << "SIGINT or SIGTERM received. Shutting down." << std::endl;
        end();
        exit(0);
    }
}

void https::Server::redirectToHTTPS(int fd) {
    //Initialize client address
    struct sockaddr_in clientAddress{};
    socklen_t clientAddressLength = sizeof(clientAddress);

    //Accept client connection
    int connection = accept(fd, (struct sockaddr *) &clientAddress, &clientAddressLength);
    if (connection < 0) {
        std::string error = std::strerror(errno);
        throw std::runtime_error("Accepting Connection Failed: " + error);
    }

    std::cout << "Accepted client connection" << std::endl;

    //Get https port
    int httpsPort = httpsSocket.getPort();
    //Redirects client to https port
    std::string domain = std::getenv("DOMAIN") ? getenv("DOMAIN") : "localhost";
    char buffer[1024];
    std::string response = "HTTP/1.1 301 Moved Permanently\r\nLocation: https://"+ domain + ":" + std::to_string(httpsPort) + "/\r\n\r\n";
    strcpy(buffer, response.c_str());
    send(connection, buffer, strlen(buffer), 0);

    //Close connection
    close(connection);
}

void https::Server::handleHTTPSRequest(int fd) {
    //Initialize client address
    struct sockaddr_in clientAddress{};
    socklen_t clientAddressLength = sizeof(clientAddress);

    //Accept client connection
    int connection = accept(fd, (struct sockaddr *) &clientAddress, &clientAddressLength);
    if (connection < 0) {
        std::string error = std::strerror(errno);
        throw std::runtime_error("Accepting Connection Failed: " + error);
    }

    std::cout << "Accepted client connection" << std::endl;

    //Create new ssl state
    SSL *ssl = SSL_new(sslCtx);
    if (ssl == nullptr) {
        char buffer[256];
        ERR_error_string(ERR_get_error(), buffer);
        std::string error(buffer);
        throw std::runtime_error("Creating SSL State Failed: "+error);
    }

    //Copy client to SSL
    SSL_set_fd(ssl, connection);

    //Handshake
    int handShakeResult = SSL_accept(ssl);
    if (handShakeResult <= 0) { //Unsuccessful handshake
        int sslError = SSL_get_error(ssl, handShakeResult);
        std::cout << "Handshake Failed: " << std::to_string(sslError) << std::endl;
    } else {
        std::cout << "Handshake Successful" << std::endl;
    }

    //Read client request
    char requestBuffer[2048];
    int bytesRead = SSL_read(ssl, requestBuffer, sizeof(requestBuffer));
    if (bytesRead <= 0) {
        int sslError = SSL_get_error(ssl, handShakeResult);
        if (sslError == SSL_ERROR_SYSCALL) {
            std::string error = std::strerror(errno);
            throw std::runtime_error("Reading Client Request Failed: " + error);
        } else if (sslError == SSL_ERROR_ZERO_RETURN) {
            std::cout << "Client disconnected" << std::endl;
        } else {
            throw std::runtime_error("Reading Client Request Failed: " + std::to_string(sslError));
        }
    }

    //Print request
    std::cout << "Request: " << requestBuffer << std::endl;

    //Send response
    SSL_write(ssl, "HTTP/1.1 200 OK\r\n\r\nHello World!", 27);

    //Close connection
    SSL_shutdown(ssl);
    close(connection);
}

