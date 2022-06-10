//
// Created by Solace on 6/10/2022.
//

#ifndef HTTPS_SERVER_UTILS_H
#define HTTPS_SERVER_UTILS_H

#include <string>


namespace https {
    struct HttpRequest {
        std::string method;
        std::string path;
        std::string version;
    };

    HttpRequest parseRequest(const std::string &request);
    std::string generateResponse(const std::string &html);
}

#endif //HTTPS_SERVER_UTILS_H
