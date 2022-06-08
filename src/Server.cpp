//
// Created by Solace on 6/7/2022.
//

#include <iostream>
#include <unistd.h>
#include <sys/epoll.h>
#include <cstring>
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
        throw std::runtime_error("Failed to create SSL context");
    }

    //Load certificate
    if (SSL_CTX_use_certificate_file(sslCtx, certFile, SSL_FILETYPE_PEM) <= 0) {
        throw std::runtime_error("Failed to load certificate");
    }

    //Load private key
    if (SSL_CTX_use_PrivateKey_file(sslCtx, keyFile, SSL_FILETYPE_PEM) <= 0) {
        throw std::runtime_error("Failed to load private key");
    }

    //Check if private key matches certificate
    if (!SSL_CTX_check_private_key(sslCtx)) {
        throw std::runtime_error("Private key does not match certificate");
    }

    //Setup epoll
    epollFD = epoll_create1(0);
    if (epollFD < 0) {
        throw std::runtime_error("Failed to create epoll");
    }

    //Add sockets to epoll
    struct epoll_event epollEvent{};
    epollEvent.events = EPOLLIN;
    epollEvent.data.fd = httpsSocket.getSocketFD();
    if (epoll_ctl(epollFD, EPOLL_CTL_ADD, httpsSocket.getSocketFD(), &epollEvent) < 0) {
        throw std::runtime_error("Failed to add https socket to epoll");
    }
    epollEvent.data.fd = httpSocket.getSocketFD();
    if (epoll_ctl(epollFD, EPOLL_CTL_ADD, httpSocket.getSocketFD(), &epollEvent) < 0) {
        throw std::runtime_error("Failed to add http socket to epoll");
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
        throw std::runtime_error("Failed to wait on epoll");
    }

    //Check if client is coming from https port
    int incomingSocketFD = epollEvent.data.fd;
    if (incomingSocketFD == httpsSocket.getSocketFD()) {
        std::cout << "Client connected on HTTPS port" << std::endl;
        handleHTTPSRequest(incomingSocketFD);
    } else if (incomingSocketFD == httpSocket.getSocketFD()) {
        std::cout << "Client connected on HTTP port" << std::endl;
        redirectToHTTPS(incomingSocketFD);
    }
}

void https::Server::redirectToHTTPS(int fd) {
    //Initialize client address
    struct sockaddr_in clientAddress{};
    socklen_t clientAddressLength = sizeof(clientAddress);

    //Accept client connection
    int connection = accept(fd, (struct sockaddr *) &clientAddress, &clientAddressLength);
    if (connection < 0) {
        throw std::runtime_error("Failed to accept client connection");
    }

    std::cout << "Accepted client connection" << std::endl;

    //Get https port
    int httpsPort = httpsSocket.getPort();
    //Redirects client to https port
    char buffer[1024];
    std::string response = "HTTP/1.1 301 Moved Permanently\r\nLocation: https://localhost:" + std::to_string(httpsPort) + "/\r\n\r\n";
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
    if (connection <= 0) {
        throw std::runtime_error("Failed to accept client");
    }

    std::cout << "Accepted client connection" << std::endl;

    //Create new ssl state
    SSL *ssl = SSL_new(sslCtx);
    if (ssl == nullptr) {
        throw std::runtime_error("Failed to create SSL state");
    }

    //Copy client to SSL
    SSL_set_fd(ssl, connection);

    //Handshake
    if (SSL_accept(ssl) <= 0) {
        throw std::runtime_error("Failed to complete handshake");
    }

    //Read client request
    char buffer[1024];
    int bytesRead = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytesRead <= 0) {
        throw std::runtime_error("Failed to read client request");
    }

    //Print request
    std::cout << "Request: " << buffer << std::endl;

    //Send response
    SSL_write(ssl, "HTTP/1.1 200 OK\r\n\r\nHello World!", 27);

    //Close connection
    SSL_shutdown(ssl);
    close(connection);}

