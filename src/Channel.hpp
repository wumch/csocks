
#pragma once

#include "predef.hpp"
#include <vector>
#include <boost/enable_shared_from_this.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/bind.hpp>
#include "Config.hpp"
#include "Authenticater.hpp"

namespace asio = boost::asio;
using asio::ip::tcp;

namespace csocks
{

class Channel:
    public boost::enable_shared_from_this<Channel>
{
private:
    enum CMD {
        CMD_CONNECT = 1,
        CMD_BIND = 2,
        CMD_UDP_ASSOCIATE = 3,
    };
    enum STAGE {
        STAGE_INIT = 0,
        STAGE_ADDR = 1,
        STAGE_UDP_ASSOC = 2,
        STAGE_DNS = 3,
        STAGE_CONNECTING = 4,
        STAGE_STREAM = 5,
        STATE_AUTH = 6,
        STAGE_DESTROYED = -1,
    };

    static const Config* const config;

    asio::io_service& ioService;
    tcp::socket ds;
    tcp::socket us;
    Buffer bufdr, bufdw, bufur, bufuw;

    Authenticater authenticater;
    Authority authority;

    STAGE stage;

public:
    Channel(asio::io_service& _ioService):
        ioService(_ioService),
        ds(ioService), us(ioService),
        stage(STAGE_INIT)
    {
        setsockopt(ds.native(), SOL_SOCKET, SO_RCVTIMEO, &config->ds_recv_timeout, sizeof(config->ds_recv_timeout));
        setsockopt(ds.native(), SOL_SOCKET, SO_RCVTIMEO, &config->ds_recv_timeout, sizeof(config->ds_recv_timeout));
        setsockopt(us.native(), SOL_SOCKET, SO_RCVTIMEO, &config->us_recv_timeout, sizeof(config->us_recv_timeout));
        setsockopt(us.native(), SOL_SOCKET, SO_RCVTIMEO, &config->us_recv_timeout, sizeof(config->us_recv_timeout));
        asio::ssl::context c(asio::ssl::context::sslv23);
        asio::ssl::context_base::options  o;

        c.set_options();
    }

    tcp::socket& downstream()
    {
        return ds;
    }

    void start()
    {
        readDs(2);
    }

private:

    // read
    //  +----+----------+----------+
    //  |VER | NMETHODS | METHODS  |
    //  +----+----------+----------+
    //  | 1  |    1     | 1 to 255 |
    //  +----+----------+----------+
    //  [               ]
    // or
    //  +----+----+----+----+----+----+----+----+----+----+....+----+
    //  | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
    //  +----+----+----+----+----+----+----+----+----+----+....+----+
    //    1    1      2        4                  variable       1
    //  [         ]
    // 读取[]里的部分.
    void readDs(std::size_t exact_bytes)
    {
        asio::async_read(ds, asio::buffer(bufdr.data + bufdr.filled, bufdr.size - bufdr.filled),
            asio::transfer_at_least(exact_bytes),
            boost::bind(&Channel::handleReadDs, shared_from_this(), asio::placeholders::error,
                asio::placeholders::bytes_transferred));
    }

    void readDs()
    {
        ds.async_read_some(asio::buffer(bufdr.data + bufdr.filled, bufdr.size - bufdr.filled),
            boost::bind(&Channel::handleReadDs, shared_from_this(), asio::placeholders::error,
                asio::placeholders::bytes_transferred));
    }

    void handleReadDs(const boost::system::error_code &err, std::size_t bytes_read)
    {
        if (CS_BUNLIKELY(err))
        {
            delete this;
        }

    }

    ~Channel()
    {
        boost::system::error_code ignored_err;
        if (ds.is_open())
        {
            ds.shutdown(tcp::socket::shutdown_both, ignored_err);
            ds.close(ignored_err);
        }
        if (us.is_open())
        {
            us.shutdown(tcp::socket::shutdown_both, ignored_err);
            us.close(ignored_err);
        }
        authenticater.restore(authority);
    }

private:
    void _handleGreet()
    {
        bufdr.filled = 0;
        bufdw.data[0] = 0x5;
        ds.async_send(asio::buffer(bufdw.data, 1),
            boost::bind(&Channel::readDs, shared_from_this()));
    }

    void _handleDr(std::size_t bytes_read)
    {
        if (CS_BLIKELY(authority.traf(bytes_read)))
        {
            switch (bufdr.data[0])
            {
                case CMD_CONNECT:
                    CS_SAY("cmd:connect");
                    break;
                case CMD_BIND:
                    CS_SAY("cmd:bind");
                    break;
                case CMD_UDP_ASSOCIATE:
                    CS_SAY("cmd:udp_assoc");
                    break;
                default:    // 无效命令
                    delete this;
                    break;
            }
        }
        else
        {
            delete this;
        }
    }

    void _handle_dw(const boost::system::error_code& err, std::size_t bytes_written)
    {
        bufdw.filled -= bytes_written;  // TODO: 方向...
    }

    std::size_t getBufferSize() const
    {
        return authority.bandwidth >> 3;
    }

};

}