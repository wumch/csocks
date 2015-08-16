
#pragma once

#include "predef.hpp"
#include <string>
#include <boost/filesystem/path.hpp>
#include <boost/asio/ip/tcp.hpp>

namespace csocks
{

class Config
{
private:
    Config():
        ioServiceNum(2),
        host(boost::asio::ip::address::from_string("0.0.0.0")),
        port(10022)
    {}

    void load(boost::filesystem::path file);

public:
    static const Config* instance()
    {
        Config* config = new Config;
        config->load("./csocks.ini");
        return config;
    }

public:
    std::size_t ioServiceNum;
    boost::asio::ip::address host;
    std::uint16_t port;

    std::time_t dsRecvTimeout, dsSendTimeout,
        usRecvTimeout, usSendTimeout;
};

}
