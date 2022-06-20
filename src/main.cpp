#include <openssl/ssl.h>
#include <iostream>
#include "../include/server.h"
#include "listener_server.h"

int main(int argc, char *argv[]) {
    if (argc < 9) {
        std::cout << "Usage: " << argv[0] << " <httpPort> <httpsPort> <certFile> <keyFile> <publicFolderPath> <threadPoolSize> <useListener> <domain>" << std::endl;
        return 1;
    }
    //Get arguments
    int httpPort = std::stoi(argv[1], nullptr, 10);
    int httpsPort = std::stoi(argv[2], nullptr, 10);
    char *certFile = argv[3];
    char *keyFile = argv[4];
    std::string publicFolderPath = argv[5];
    int threadPoolSize = std::stoi(argv[6], nullptr, 10);
    bool useListener = std::stoi(argv[7], nullptr, 10);
    char *domain = argv[8];

    //Initialize OpenSSL
    SSL_library_init();

    //Initialize server
    if (useListener) {
        https::ListenerServer server(certFile, keyFile, domain, httpsPort, httpPort, publicFolderPath);
        server.startWithListener(threadPoolSize);
    } else {
        https::Server server(certFile, keyFile, domain, httpsPort, httpPort, publicFolderPath);
        server.start(threadPoolSize);
    }
}
