//
// Created by Solace on 6/10/2022.
//

#ifndef HTTPS_SERVER_MESSAGE_H
#define HTTPS_SERVER_MESSAGE_H

#include <string>


namespace https {
    template <typename Key, typename Value, std::size_t Size>
    struct Dict {
        std::array<std::pair<Key, Value>, Size> data;

        [[nodiscard]] constexpr Value get(const Key &key) const {
            const auto iterator =
                std::find_if(std::begin(data), std::end(data), [&key](const auto &pair) {
                    return std::strcmp(pair.first, key);
                });

            if (iterator != std::end(data)) {
                return iterator->second;
            } else {
                throw std::out_of_range("Key not found");
            }
        }

    };


    static constexpr std::array<std::pair<const char*, const char*>, 6> contentTypes {{
            {".html", "text/html"},
            {".css", "text/css"},
            {".js", "application/javascript"},
            {".png", "image/png"},
            {".jpg", "image/jpeg"},
            {".ico", "image/x-icon"}
    }};
    static constexpr Dict<const char*, const char*, 6> contentTypeDict = {contentTypes};


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
