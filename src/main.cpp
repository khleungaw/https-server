#include <openssl/ssl.h>
#include <iostream>
#include "../include/server.h"

int main() {
    //Initialize variables
    int httpPort = std::getenv("HTTP_PORT") ? std::stoi(getenv("HTTP_PORT")) : 8080;
    int httpsPort = std::getenv("HTTPS_PORT") ? std::stoi(getenv("HTTPS_PORT")) : 4430;
    std::string rootPath = std::getenv( "ROOT" ) ? getenv( "ROOT" ) : "../";
    std::string certFilePath = rootPath + "key/cert.crt";
    std::string keyFilePath = rootPath + "key/key.pem";
    std::string htmlFilePath = rootPath + "public/index.html";
    char *certFile = const_cast<char *>(certFilePath.c_str());
    char *keyFile = const_cast<char *>(keyFilePath.c_str());

    //Initialize OpenSSL
    SSL_library_init();

    //Create a server
    https::Server server(certFile, keyFile, httpsPort, httpPort, htmlFilePath);



    //Starts server
    server.start(4);
}
