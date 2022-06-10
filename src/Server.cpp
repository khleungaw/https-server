//
// Created by Solace on 6/7/2022.
//

#include <iostream>
#include <unistd.h>
#include <cstring>
#include <csignal>
#include <thread>
#include <algorithm>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <fstream>
#include "Server.h"
#include "Socket.h"
#include "utils.h"

https::Server::Server(char *certFile, char *keyFile, Socket httpsSocket, Socket httpSocket, const std::string& htmlFilePath)
        : httpsSocket(httpsSocket), httpSocket(httpSocket) {
    std::cout << "\n-----Server Starting------------------------------" << std::endl;
    //Load HTML
    loadHTML(htmlFilePath);

    //Create SSL context with flexible TLS methods
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    sslCtx = SSL_CTX_new(TLS_server_method());
    if (sslCtx == nullptr) {
        char buffer[bufferSize];
        ERR_error_string(ERR_get_error(), buffer);
        std::string error(buffer);
        throw std::runtime_error("SSL Context Creation Failed: "+error);
    }

    //Load certificate
    if (SSL_CTX_use_certificate_file(sslCtx, certFile, SSL_FILETYPE_PEM) <= 0) {
        char buffer[bufferSize];
        ERR_error_string(ERR_get_error(), buffer);
        std::string error(buffer);
        throw std::runtime_error("Loading Certificate Failed: "+error);

    }

    //Load private key
    if (SSL_CTX_use_PrivateKey_file(sslCtx, keyFile, SSL_FILETYPE_PEM) <= 0) {
        char buffer[bufferSize];
        ERR_error_string(ERR_get_error(), buffer);
        std::string error(buffer);
        throw std::runtime_error("Loading Private Key Failed: "+error);

    }

    //Check if private key matches certificate
    if (SSL_CTX_check_private_key(sslCtx) <= 0) {
        char buffer[bufferSize];
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

    //Add SIGPIPE to epoll
    sigemptyset(&mask);
    sigaddset(&mask, SIGPIPE);
    if (sigprocmask(SIG_BLOCK, &mask, nullptr) < 0) { //Block signals
        std::string error = std::strerror(errno);
        throw std::runtime_error("Changing Signal Mask Failed: " + error);
    }

    sigPipeFD = signalfd(-1, &mask, 0);
    if (sigPipeFD < 0) {
        std::string error = std::strerror(errno);
        throw std::runtime_error("Creating SIGPIPE FD Failed: "+error);
    }

    struct epoll_event signalPipeEvent{};
    signalPipeEvent.events = EPOLLIN;
    signalPipeEvent.data.fd = sigPipeFD;
    if (epoll_ctl(epollFD, EPOLL_CTL_ADD, sigPipeFD, &signalPipeEvent) < 0) {
        std::string error = std::strerror(errno);
        throw std::runtime_error("Adding SIGPIPE to Epoll Failed: " + error);
    }

    //Add sockets to epoll with edge trigger
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
    std::cout << "\nWaiting for Connection...\n" << std::endl;
    struct epoll_event epollEvent{};
    int epollResult = epoll_wait(epollFD, &epollEvent, 100, -1);
    if (epollResult < 0) {
        std::string error = std::strerror(errno);
        throw std::runtime_error("Waiting on Epoll Failed: " + error);
    }
    int incomingFD = epollEvent.data.fd;

    //Handle ports FDs
    if (incomingFD == httpsSocket.getSocketFD() && std::count(connections.begin(), connections.end(), incomingFD) == 0) {
        acceptConnection(incomingFD, true);
        return;
    } else if (incomingFD == httpSocket.getSocketFD() && std::count(connections.begin(), connections.end(), incomingFD) == 0) { //Redirect to HTTPS
        acceptConnection(incomingFD, false);
        return;
    }

    //Handle connections FDs
    if (std::count(connections.begin(), connections.end(), incomingFD) > 0) {
        std::thread workerThread(&https::Server::handleHTTPSRequest, this, incomingFD);
        workerThread.detach();
        return;
    }

    //Handle SIGINT/SIGTERM FDs
    if (epollEvent.data.fd == sigExitFD) {
        std::cout << "SIGINT or SIGTERM received. Shutting down." << std::endl;
        end();
        exit(0);
    }

    //Handle SIGPIPE FDs
    if (epollEvent.data.fd == sigPipeFD) {
        std::cout << "SIGPIPE received. Ignoring." << std::endl;
        return;
    }
}

void https::Server::redirectToHTTPS(int fd) {
    //Get https port
    int httpsPort = httpsSocket.getPort();

    //Read request from fd
    char reqBuffer[bufferSize];
    ssize_t bytesRead = read(fd, reqBuffer, 4096);
    if (bytesRead < 0) {
        std::string error = std::strerror(errno);
        throw std::runtime_error("Reading HTTP Request Failed: " + error);
    }

    //Print request
    std::cout << reqBuffer << std::endl;

    //Redirects client to https port
    std::string domain = std::getenv("DOMAIN") ? getenv("DOMAIN") : "localhost";
    char resBuffer[1024];
    std::string response = "HTTP/1.1 301 Moved Permanently\r\nLocation: https://"+ domain + ":" + std::to_string(httpsPort) + "/\r\n\r\n";
    strcpy(resBuffer, response.c_str());
    send(fd, resBuffer, strlen(resBuffer), 0);

    //Close connection
    close(fd);

    std::cout << "-------------------Closing Connection-------------------" << std::endl;
}

void https::Server::handleHTTPSRequest(int fd) {
    SSL *ssl = makeSSLConnection(fd);
    //Check if SSL connection is valid
    if (ssl == nullptr) {
        std::cout << "-------------------Closing Connection-------------------" << std::endl;
        close(fd);
        return;
    }
    //Read client request until EOF
    std::string req = sslRead(ssl, fd);

    //Print request
    std::cout << req << std::endl;

    //Parse request
    HttpRequest request = parseRequest(req);
    std::string response;

    //Only handle GET requests, reject the rest
    if (request.method != "GET") {
        response = "HTTP/1.1 405 Method Not Allowed\r\n\r\n";
    } else {
        response = https::generateResponse(htmlText);
    }

    //Send response
    char resBuffer[response.length()];
    strcpy(resBuffer, response.c_str());
    SSL_write(ssl, resBuffer, response.length());

    //Close connection
    if (SSL_shutdown(ssl) ==0) {
        SSL_shutdown(ssl);
    }
    SSL_free(ssl);
    close(fd);

    //Remove connection FD from connections
    connections.erase(std::remove(connections.begin(), connections.end(), fd), connections.end());

    std::cout << "-------------------Closing Connection-------------------" << std::endl;
}

void https::Server::acceptConnection(int fd, bool isHTTPS) {
    //Initialize client address
    struct sockaddr_in clientAddress{};
    socklen_t clientAddressLength = sizeof(clientAddress);

    //Accept client connection
    int acceptedFD = accept(fd, (struct sockaddr *) &clientAddress, &clientAddressLength);
    if (acceptedFD < 0) {
        std::string error = std::strerror(errno);
        throw std::runtime_error("Accepting Connection Failed: " + error);
    }

    if (isHTTPS) {
        std::cout << "--------------------HTTPS Connection--------------------" << std::endl;
        //Get client address
        char clientAddressBuffer[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(clientAddress.sin_addr), clientAddressBuffer, INET_ADDRSTRLEN);
        std::cout << "Client: " << clientAddressBuffer << std::endl << std::endl;

        //Add connection to epoll
        struct epoll_event connectionEvent{};
        connectionEvent.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
        connectionEvent.data.fd = acceptedFD;
        if (epoll_ctl(epollFD, EPOLL_CTL_ADD, acceptedFD, &connectionEvent) < 0) {
            std::string error = std::strerror(errno);
            throw std::runtime_error("Adding Connection to Epoll Failed: " + error);
        }

        //Add to connections
        connections.push_back(acceptedFD);
        return;
    } else {
        std::cout << "--------------------HTTP  Connection--------------------" << std::endl;
        //Get client address
        char clientAddressBuffer[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(clientAddress.sin_addr), clientAddressBuffer, INET_ADDRSTRLEN);
        std::cout << "Client: " << clientAddressBuffer << std::endl << std::endl;

        //Redirect to HTTPS
        std::thread workerThread(&https::Server::redirectToHTTPS, this, acceptedFD);
        workerThread.detach();
    }
}

std::string https::Server::sslRead(SSL *ssl, int connectionFD) const {
    char buffer[bufferSize];
    std::string req;
    int contentLengthInt = 0;

    //First Reading
    int firstBytesRead = SSL_read(ssl, buffer, bufferSize);
    if (firstBytesRead < 0) {
        int sslError = SSL_get_error(ssl, firstBytesRead);
        std::cout << "Reading Error: " << sslError << std::endl;
    } else {
        req.append(buffer, firstBytesRead);
        //Get content length
        if (req.find("Content-Length: ") != std::string::npos) {
            std::string contentLength = req.substr(req.find("Content-Length: ") + 16);
            contentLengthInt = std::stoi(contentLength.substr(0, contentLength.find("\r\n")));
        }

        //Return if content length matches req
        if (contentLengthInt == firstBytesRead) {
            return req;
        }
    }

    //Read from SSL until req meets content length
    while (req.size() < contentLengthInt) {
        //Rearm connection epoll
        struct epoll_event connectionEvent{};
        connectionEvent.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
        connectionEvent.data.fd = connectionFD;
        if (epoll_ctl(epollFD, EPOLL_CTL_MOD, connectionFD, &connectionEvent) < 0) {
            std::string error = std::strerror(errno);
            throw std::runtime_error("Modifying Connection to Epoll Failed: " + error);
        }
        //Read from SSL
        int bytesRead = SSL_read(ssl, buffer, bufferSize);
        if (bytesRead < 0) {
            int sslError = SSL_get_error(ssl, bytesRead);
            std::cout << "Reading Error: " << sslError << std::endl;
        } else {
            req.append(buffer, bytesRead);
        }
    }

    return req;
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
    int handShakeResult = SSL_accept(ssl);
    if (handShakeResult <= 0) { //Unsuccessful handshake
        int sslError = SSL_get_error(ssl, handShakeResult);
        std::cout << "Handshake Failed: " << std::to_string(sslError) << std::endl;
        //Free ssl state
        SSL_free(ssl);
        //Return
        return nullptr;
    } else {
        std::cout << "Handshake Successful" << std::endl;
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

