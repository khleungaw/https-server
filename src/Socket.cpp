//
// Created by Solace on 6/7/2022.
//

#include <iostream>
#include <cstring>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "../include/Socket.h"

https::Socket::Socket(int PORT) {
    port = PORT;
    //Prepare the address structure
    address.sin_family = AF_INET;
    address.sin_port = htons(PORT);
    address.sin_addr.s_addr = htonl(INADDR_ANY);

    //Create a socket
    socketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFD <= 0) {
        std::string error = std::strerror(errno);
        throw std::runtime_error("Port Creation Failed: " + error);
    }

    /*//Set socket to non-blocking
    int flags = fcntl(socketFD, F_GETFL, 0);
    if (flags == -1) {
        std::string error = std::strerror(errno);
        throw std::runtime_error("Setting Non-blocking failed: " + error);
    }*/

    //Set to KEEPALIVE
    int keepAlive = 1;
    if (setsockopt(socketFD, SOL_SOCKET, SO_KEEPALIVE, &keepAlive, sizeof(keepAlive)) < 0) {
        std::string error = std::strerror(errno);
        throw std::runtime_error("Setting KeepAlive failed: " + error);
    }

    //Bind socket to port
    binding = bind(socketFD, (struct sockaddr *) &address, sizeof(address));
    if (binding < 0) {
        std::string error = std::strerror(errno);
        throw std::runtime_error("Port Binding Failed: " + error);
    }

    /*//Set to non-blocking
    if (fcntl(socketFD, F_SETFL, flags | O_NONBLOCK) == -1) {
        std::string error = std::strerror(errno);
        throw std::runtime_error("Setting Non-blocking failed: " + error);
    }*/

    //Listen for incoming httpsEpollFDs
    listening = listen(this->socketFD, 32);
    if (listening < 0) {
        std::string error = std::strerror(errno);
        throw std::runtime_error("Port Listening Failed: " + error);
    }

    std::cout << "Socket created on port " << PORT << std::endl;
}

void https::Socket::end() const {
    //Clean up
    close(socketFD);
}

int https::Socket::getSocketFD() const {
    return socketFD;
}

int https::Socket::getPort() const {
    return port;
}
