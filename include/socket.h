//
// Created by Solace on 6/7/2022.
//

#ifndef HTTPS_SERVER_SOCKET_H
#define HTTPS_SERVER_SOCKET_H

#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>


namespace https {
    constexpr int kMaxConnections = 1000;

    struct Socket {
        struct sockaddr_in address{};
        int fd;
        int port;

        explicit Socket(int PORT) {
            port = PORT;
            //Prepare the address structure
            address.sin_family = AF_INET;
            address.sin_port = htons(PORT);
            address.sin_addr.s_addr = htonl(INADDR_ANY);

            //Create a socket
            fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd <= 0) {
                std::string error = std::strerror(errno);
                throw std::runtime_error("Port Creation Failed: " + error);
            }

            //Set socket to non-blocking
            setNonBlocking(fd);

            //Set to KEEPALIVE
            int keepAlive = 1;
            if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepAlive, sizeof(keepAlive)) < 0) {
                std::string error = std::strerror(errno);
                throw std::runtime_error("Setting KeepAlive failed: " + error);
            }

            //Bind socket to port
            int binding = bind(fd, (struct sockaddr *) &address, sizeof(address));
            if (binding < 0) {
                std::string error = std::strerror(errno);
                throw std::runtime_error("Port Binding Failed: " + error);
            }

            //Listen for incoming messages
            int listening = listen(fd, kMaxConnections);
            if (listening < 0) {
                std::string error = std::strerror(errno);
                throw std::runtime_error("Port Listening Failed: " + error);
            }

            std::cout << "Socket created on port " << PORT << std::endl;
        }

        static void setNonBlocking(int fd) {
            int flags = fcntl(fd, F_GETFL, 0);
            if (flags == -1) {
                std::string error = std::strerror(errno);
                throw std::runtime_error("Socket Flags Failed: " + error);
            }
            flags |= O_NONBLOCK;
            if (fcntl(fd, F_SETFL, flags) == -1) {
                std::string error = std::strerror(errno);
                throw std::runtime_error("Socket Flags Failed: " + error);
            }
        }

        static void end(int fd) {
            shutdown(fd, SHUT_RD);
            close(fd);
        }

    };
}



#endif //HTTPS_SERVER_SOCKET_H
