//
// Created by Solace on 6/7/2022.
//

#ifndef HTTPS_SERVER_SOCKET_H
#define HTTPS_SERVER_SOCKET_H

#include <netinet/in.h>

namespace https {
    class Socket {
    private:
        struct sockaddr_in address{};
        int socketFD;
        int binding;
        int listening;
        int port;
    public:
        explicit Socket(int PORT);
        int getSocketFD() const;
        int getPort() const;
        void end() const;
    };
}



#endif //HTTPS_SERVER_SOCKET_H
