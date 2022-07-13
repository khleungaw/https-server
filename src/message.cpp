//  m
// Created by Solace on 6/10/2022.
//

#include <stdexcept>
#include <climits>
#include <memory>
#include <cstring>
#include "message.h"

std::unique_ptr<char[]> https::generateHeader(const std::shared_ptr<File> &file) {
    //Size = 53 + extension length + file size length
    int headerSize = 53 + unsignedLongToInt(file->extension.length()) + unsignedLongToInt(std::to_string(file->size).length());
    std::unique_ptr header = std::make_unique<char[]>(headerSize);

    strcpy(header.get(), "HTTP/1.1 200 OK\r\n");
    strcat(header.get(), "Content-Type: ");
    strcat(header.get(), file->extension.c_str());
    strcat(header.get(), "\r\n");
    strcat(header.get(), "Content-Length: ");
    strcat(header.get(), std::to_string(file->size).c_str());
    strcat(header.get(), "\r\n\r\n");

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

[[maybe_unused]] long https::unsignedLongToLong(size_t num) {
    if (num > LLONG_MAX) {
        throw std::runtime_error("Unsigned long too large for long");
    } else {
        return static_cast<long>(num);
    }
}
