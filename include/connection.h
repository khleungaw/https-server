//
// Created by Solace on 6/13/2022.
//

#ifndef HTTPS_SERVER_CONNECTION_H
#define HTTPS_SERVER_CONNECTION_H

#include <string>
#include <openssl/ssl.h>
#include <sstream>

namespace https {
    struct Request {
        std::string method;
        std::string path;
        std::string version;

        void updateRequest(const std::string& req) {
            //Split the request into lines
            std::stringstream requestStream(req);
            std::string line;
            for (int i = 0; std::getline(requestStream, line); i++) {
                if (i == 0) {
                    //Parse the first line
                    std::stringstream firstLineStream(line);
                    std::string firstLine;
                    std::getline(firstLineStream, firstLine, ' ');
                    method = firstLine;
                    std::getline(firstLineStream, firstLine, ' ');
                    path = firstLine;
                    std::getline(firstLineStream, firstLine, ' ');
                    version = firstLine;
                } else {
                    break;
                }
            }
        }
    };

    //States for the connection:
    //0: TLS not yet established
    //1: Waiting for read
    //2: Waiting for write
    struct Connection {
        int fd;
        int port;
        int state = 0;
        SSL *ssl = nullptr;
        std::string method;
        std::string path;
        std::string version;
        explicit Connection(int fd, int port) : fd(fd), port(port) {};
    };

}


#endif //HTTPS_SERVER_CONNECTION_H
