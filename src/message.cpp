//  m
// Created by Solace on 6/10/2022.
//

#include "message.h"

std::string https::generateResponse(const std::string &html) {
    std::string httpResponse = "HTTP/1.1 200 OK\r\n";
    httpResponse += "Content-Type: text/html\r\n";
    httpResponse += "Content-Length: " + std::to_string(html.length()) + "\r\n";
    httpResponse += "\r\n";
    httpResponse += html;

    return httpResponse;
}

std::string https::generateRedirect() {
    std::string domain = (std::getenv("DOMAIN") ? getenv("DOMAIN") : "172.18.200.13");
    std::string port = (std::getenv("HTTPS_PORT") ? getenv("HTTPS_PORT") : "4430");
    std::string res =
            "HTTP/1.1 301 Moved Permanently\r\n"
            "Location: https://"
            + domain + ":" + port + "/\r\n"
            "\r\n"
            "\r\n";

    return res;
}