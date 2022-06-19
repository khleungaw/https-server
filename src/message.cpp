//  m
// Created by Solace on 6/10/2022.
//

#include <stdexcept>
#include <climits>
#include <memory>
#include <cstring>
#include "message.h"

char* https::generateHeader(const std::shared_ptr<File> &file) {
    //Size = 53 + extension length + file size length
    int headerSize = 53 + unsignedLongToInt(file->extension.length()) + unsignedLongToInt(std::to_string(file->size).length());
    auto *header = new char[headerSize];

    strcpy(header, "HTTP/1.1 200 OK\r\n");
    strcat(header, "Content-Type: ");
    strcat(header, file->extension.c_str());
    strcat(header, "\r\n");
    strcat(header, "Content-Length: ");
    strcat(header, std::to_string(file->size).c_str());
    strcat(header, "\r\n\r\n");

    return header;
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

int https::unsignedLongToInt(size_t num) {
    if (num > INTMAX_MAX) {
        throw std::runtime_error("Unsigned long too large for int");
    } else {
        return static_cast<int>(num);
    }
}

long https::unsignedLongToLong(size_t num) {
    if (num > LLONG_MAX) {
        throw std::runtime_error("Unsigned long too large for long");
    } else {
        return static_cast<long>(num);
    }
}
