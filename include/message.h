//
// Created by Solace on 6/10/2022.
//

#ifndef HTTPS_SERVER_MESSAGE_H
#define HTTPS_SERVER_MESSAGE_H

#include <string>


namespace https {
    std::string generateResponse(const std::string &html);
    std::string generateRedirect(const std::string& domain, int httpsPort);
    int strIntLength(size_t strLength);
}

#endif //HTTPS_SERVER_MESSAGE_H
