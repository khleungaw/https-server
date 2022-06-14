#include <openssl/ssl.h>
#include <iostream>
#include "../include/server.h"

int main(int argc, char *argv[]) {
    //Get arguments
    int httpPort = std::stoi(argv[1], nullptr, 10);
    int httpsPort = std::stoi(argv[2], nullptr, 10);
    char *certFile = argv[3];
    char *keyFile = argv[4];
    int threadPoolSize = std::stoi(argv[5], nullptr, 10);
    bool useListener = std::stoi(argv[6], nullptr, 10);

    //Initialize variables
    std::string rootPath = std::getenv( "ROOT" ) ? getenv( "ROOT" ) : "../";
    std::string htmlFilePath = rootPath + "public/index.html";

    //Initialize OpenSSL
    SSL_library_init();

    //Create a server
    https::Server server(certFile, keyFile, httpsPort, httpPort, htmlFilePath);

    //Starts server
    if (useListener) {
        server.startWithListener(threadPoolSize);
    } else {
        server.start(threadPoolSize);
    }
}
