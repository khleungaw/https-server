//
// Created by Solace on 6/10/2022.
//

#ifndef HTTPS_SERVER_MESSAGE_H
#define HTTPS_SERVER_MESSAGE_H

#include <string>


namespace https {
    struct File {
        char *data = nullptr;
        size_t size = 0;
        std::string extension;
        File() = default;
    };

    char* generateHeader(const std::shared_ptr<File> &file);
    std::string generateRedirect(const std::string& domain, int httpsPort);
    int unsignedLongToInt(size_t num);
    long unsignedLongToLong(size_t num);
}

#endif //HTTPS_SERVER_MESSAGE_H
