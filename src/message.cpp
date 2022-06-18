//  m
// Created by Solace on 6/10/2022.
//

#include <stdexcept>
#include "message.h"

std::string https::generateResponse(const std::string &html) {
    std::string httpResponse = "HTTP/1.1 200 OK\r\n";
    httpResponse += "Content-Type: text/html\r\n";
    httpResponse += "Content-Length: " + std::to_string(html.length()) + "\r\n";
    httpResponse += "\r\n";
    httpResponse += html;

    return httpResponse;
}

std::string https::generateRedirect(const std::string& domain, int httpsPort) {
    std::string res =
            "HTTP/1.1 301 Moved Permanently\r\n"
            "Location: https://"
            + domain + ":" + std::to_string(httpsPort) + "/\r\n"
            "\r\n"
            "\r\n";

    return res;
}

int https::unsignedLongToInt(size_t strLength) {
    if (strLength > INTMAX_MAX) {
        throw std::runtime_error("String length is too long");
    } else {
        return static_cast<int>(strLength);
    }
}