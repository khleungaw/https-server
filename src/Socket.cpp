//
// Created by Solace on 6/7/2022.
//

#include <iostream>
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
        throw std::runtime_error("Failed to create socket");
    }

    //Bind socket to port
    binding = bind(socketFD, (struct sockaddr *) &address, sizeof(address));
    if (binding < 0) {
        throw std::runtime_error("Failed to bind socket");
    }

    //Listen for incoming connections
    listening = listen(this->socketFD, 32);
    if (listening < 0) {
        throw std::runtime_error("Failed to listen on socket");
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
