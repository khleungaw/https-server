//  m
// Created by Solace on 6/10/2022.
//

#include <cstring>
#include "message.h"

std::string https::generateResponse(const std::string &html) {
    std::string httpResponse = "HTTP/1.1 200 OK\r\n";
    httpResponse += "Content-Type: text/html\r\n";
    httpResponse += "Content-Length: " + std::to_string(html.length()) + "\r\n";
    httpResponse += "\r\n";
    httpResponse += html;

    return httpResponse;
}

char* https::generateRedirect() {
    auto buffer = new char[128];
    strcat(buffer, "HTTP/1.1 301 Moved Permanently\r\n");
    strcat(buffer, "Location: https://");
    strcat(buffer, std::getenv("DOMAIN") ? getenv("DOMAIN") : "localhost");
    strcat(buffer, ":");
    strcat(buffer, std::getenv("HTTPS_PORT") ? getenv("HTTPS_PORT") : "4430");
    strcat(buffer, "\r\n");
    strcat(buffer, "\r\n");

    return buffer;
}