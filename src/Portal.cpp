
#include "Portal.hpp"
#include "Channel.hpp"

#include <iostream>
#include <exception>
#include <boost/bind.hpp>

namespace csocks
{

void Portal::accept()
{
    Channel* chan = new Channel(ioService);
    acceptor.async_accept(chan->downstream(),
        boost::bind(&Portal::handle_accept, this, chan, boost::asio::placeholders::error));
    try
    {
        ioService.run();
    }
    catch (std::exception& e)
    {
        std::cerr << "error:" << e.what() << std::endl;
    }
}

void Portal::handle_accept(Channel* chan, const boost::system::error_code& err)
{
    if (!err)
    {
        chan->start();
    }
    else
    {
        delete chan;
    }
    accept();
}

}
