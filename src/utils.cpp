//  m
// Created by Solace on 6/10/2022.
//

#include <sstream>
#include <cstring>
#include "utils.h"

https::HttpRequest https::parseRequest(const std::string &request) {
    struct HttpRequest httpRequest;

    //Split the request into lines
    std::stringstream requestStream(request);
    std::string line;
    for (int i = 0; std::getline(requestStream, line); i++) {
        if (i == 0) {
            //Parse the first line
            std::stringstream firstLineStream(line);
            std::string firstLine;
            std::getline(firstLineStream, firstLine, ' ');
            httpRequest.method = firstLine;
            std::getline(firstLineStream, firstLine, ' ');
            httpRequest.path = firstLine;
            std::getline(firstLineStream, firstLine, ' ');
            httpRequest.version = firstLine;
        } else {
            break;
        }
    }

    //Return
    return httpRequest;
}

std::string https::generateResponse(const std::string &html) {
    std::string httpResponse = "HTTP/1.1 200 OK\r\n";
    httpResponse += "Content-Type: text/html\r\n";
    httpResponse += "Content-Length: " + std::to_string(html.length()) + "\r\n";
    httpResponse += "\r\n";
    httpResponse += html;

    return httpResponse;
}

