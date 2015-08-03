
#pragma once

#include "predef.hpp"
#include <vector>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include "Authenticater.hpp"

namespace asio = boost::asio;
using asio::ip::tcp;

namespace csocks
{

class Channel
{
private:
    enum PROGRESS {
        PROGRESS_INIT,  // 初始化

        PROGRESS_GREET_WAITING,
        PROGRESS_GREET_SENT,

        PROGRESS_AUTH_WAITING,  // 等候认证包
        PROGRESS_AUTH_CONTINUE, // 认证接收不完整
        PROGRESS_AUTHING,       // 认证中（认证包接收完毕，等待认证）
        PROGRESS_AUTHED,        // 认证完毕
    };
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

    tcp::socket downstream;
    tcp::socket upstream;
    Buffer bufdr, bufdw, bufur, bufuw;

    Authenticater authenticater;
    Authority authority;

    PROGRESS progress;
    STAGE stage;

public:
    Channel(asio::io_service& ioService):
        downstream(ioService), upstream(ioService),
        progress(PROGRESS_INIT), stage(STAGE_INIT)
    {}

    tcp::socket& socket()
    {
        return downstream;
    }

    void start()
    {
        readdr();
    }

    void readdr()
    {
        downstream.async_read_some(asio::buffer(bufdr.data + bufdr.filled, bufdr.size - bufdr.filled),
            boost::bind(&Channel::handle_readdr, this, asio::placeholders::error,
                asio::placeholders::bytes_transferred));
    }

    void handle_readdr(const boost::system::error_code& err, std::size_t bytes_read)
    {
        if (CS_BUNLIKELY(err))
        {
            delete this;
        }

        if (CS_BLIKELY(progress == PROGRESS_AUTHED))
        {
            _handle_dr(bytes_read);
        }
        else
        {
            switch (progress)
            {
                case PROGRESS_INIT:
                    progress = PROGRESS_GREET_WAITING;

                case PROGRESS_GREET_WAITING:
                    _handle_greet();
                    break;
                case PROGRESS_GREET_SENT:
                    progress = PROGRESS_AUTH_WAITING;

                case PROGRESS_AUTH_CONTINUE:
                    switch (authenticater.auth(bufdr))
                    {
                        case Authenticater::STATUS_HUNGRY:
                            readdr();
                            break;
                        case Authenticater::STATUS_WAITING:
                            bufdr.filled = 0;
                            authenticater.packAuth(bufdw);
                            downstream.async_send(asio::buffer(bufdw.data, bufdw.filled),
                                boost::bind(&Channel::readdr, this));
                            break;
                    }
                    break;
                case PROGRESS_AUTHING:
                    // TODO:
                    break;

                default:
                    delete this;
                    break;
            }
        }
    }

    ~Channel()
    {
        authenticater.restore(authority);
    }

private:
    void _handle_greet()
    {
        bufdr.filled = 0;
        bufdw.data[0] = 0x5;
        downstream.async_send(asio::buffer(bufdw.data, 1),
            boost::bind(&Channel::readdr, this));
    }

    void _handle_dr(std::size_t bytes_read)
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