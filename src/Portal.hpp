
#pragma once

#include "predef.hpp"
#include <boost/system/error_code.hpp>
#include <boost/asio.hpp>
#include "Config.hpp"
#include "Bus.hpp"

using boost::asio::ip::tcp;

namespace csocks
{

class Portal
{
private:
    const Config* const config;
    Bus bus;

public:
    Portal(const Config* _config):
        config(_config), bus(config)
    {}

    void run()
    {
        bus.start();
    }
};

}
