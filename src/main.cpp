#include <openssl/ssl.h>
#include <iostream>
#include "../include/server.h"
#include "listener_server.h"

int main(int argc, char *argv[]) {
    if (argc < 8) {
        std::cout << "Usage: " << argv[0] << " <certFile> <keyFile> <httpsPort> <htmlFilePath> <threadPoolSize> <useListener> <domain>" << std::endl;
        return 1;
    }
    //Get arguments
    int httpPort = std::stoi(argv[1], nullptr, 10);
    int httpsPort = std::stoi(argv[2], nullptr, 10);
    char *certFile = argv[3];
    char *keyFile = argv[4];
    int threadPoolSize = std::stoi(argv[5], nullptr, 10);
    bool useListener = std::stoi(argv[6], nullptr, 10);
    char *domain = argv[7];

    //Initialize variables
    std::string rootPath = std::getenv( "ROOT" ) ? getenv( "ROOT" ) : "../";
    std::string htmlFilePath = rootPath + "public/index.html";

    //Initialize OpenSSL
    SSL_library_init();

    //Initialize server
    if (useListener) {
        https::ListenerServer server(certFile, keyFile, domain, httpsPort, httpPort, htmlFilePath);
        server.startWithListener(threadPoolSize);
    } else {
        https::Server server(certFile, keyFile, domain, httpsPort, httpPort, htmlFilePath);
        server.start(threadPoolSize);
    }
}
