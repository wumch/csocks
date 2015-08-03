
#pragma once

#include "predef.hpp"
#include <boost/system/error_code.hpp>
#include <boost/asio.hpp>
#include "Config.hpp"
#include "Channel.hpp"

using boost::asio::ip::tcp;

namespace csocks
{

class Portal
{
private:
    const Config& config;

    boost::asio::io_service ioService;
    tcp::acceptor acceptor;
    tcp::resolver resolver;

public:
    Portal(const Config& _config):
        config(_config),
        ioService(config.ioServiceNum),
        acceptor(ioService, tcp::endpoint(config.host, config.port)),
        resolver(ioService)
    {}

    void run()
    {
        accept();
    }

private:
    void accept();

    void handle_accept(Channel* chan, const boost::system::error_code& err);
};

}