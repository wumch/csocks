
#pragma once

#include "predef.hpp"
#include <netinet/in.h>
#include <vector>
#include <boost/enable_shared_from_this.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/bind.hpp>
#include <crypto++/modes.h>
#include <crypto++/aes.h>
#include <crypto++/filters.h>
#include "Config.hpp"
#include "Crypto.hpp"
#include "Authenticater.hpp"

namespace asio = boost::asio;
using asio::ip::tcp;

#define KICK_IF(err) if (CS_UNLIKELY(err)) { delete this; return; }

namespace csocks
{

class Channel:
    public boost::enable_shared_from_this<Channel>
{
private:
    enum CMD {
        CMD_CONNECT = 0x01,
        CMD_BIND = 0x02,
        CMD_UDP_ASSOC = 0x03,
    };
    // 认证方法
    enum {
        AUTH_NONE = 0x00,			// 不认证
        AUTH_USERPASS = 0x02,		// 用户名+密码
        AUTH_UNACCEPTABLE = 0xff,	// 无可接受方法
    };
    // 认证结果
    enum {
    	AUTH_RES_SUCCESS = 0x00,		// 成功
		AUTH_RES_FAILED = 0x01,			// 失败
    };
    // addr type
    enum {
        ADDR_IPV4 = 0x01,
        ADDR_DOMAIN = 0x03,
        ADDR_IPV6 = 0x04
    };

    static const int maxNumMethods = 8;
    static const char connectSuccessResponse[10] = {PROTOCOL_VERSION, 0x00, 0x00, 0x01};
    static const Config* const config;

    asio::io_service& ioService;
    tcp::resolver resolver;

    tcp::socket ds, us;
    Buffer bufdr, bufdw, bufur, bufuw;

    Crypto crypto;
    Authenticater& authenticater;
    Authority authority;

public:
    Channel(asio::io_service& _ioService, Authenticater& _authenticater):
        ioService(_ioService), resolver(ioService),
        ds(ioService), us(ioService),
        authenticater(_authenticater)
    {
        setsockopt(ds.native(), SOL_SOCKET, SO_RCVTIMEO, &config->ds_recv_timeout, sizeof(config->ds_recv_timeout));
        setsockopt(ds.native(), SOL_SOCKET, SO_SNDTIMEO, &config->ds_send_timeout, sizeof(config->ds_send_timeout));
        setsockopt(us.native(), SOL_SOCKET, SO_RCVTIMEO, &config->us_recv_timeout, sizeof(config->us_recv_timeout));
        setsockopt(us.native(), SOL_SOCKET, SO_SNDTIMEO, &config->us_send_timeout, sizeof(config->us_send_timeout));
    }

    tcp::socket& downstream()
    {
        CryptoPP::AES::Encryption aesEnc();
        CryptoPP::StreamTransformationFilter streamEncor();
        return ds;
    }

    void start()
    {
        readNumMethods();
    }

private:
    void readNumMethods()
    {
        // read
        //  +----+----------+----------+
        //  |VER | NMETHODS | METHODS  |
        //  +----+----------+----------+
        //  | 1  |    1     | 1 to 255 |
        //  +----+----------+----------+
        //  [               ]
        // 读取[]里的部分.
        asio::async_read(ds, asio::buffer(bufdr.data, bufdr.capacity),
            asio::transfer_exactly(2),
            boost::bind(&Channel::handleGreet, shared_from_this(), asio::placeholders::error,
                asio::placeholders::bytes_transferred));
    }

    void handleGreet(const boost::system::error_code& err, int byteRead)
    {
    	KICK_IF(err)
    	KICK_IF(byteRead != 2)

    	char header[2];
    	crypto.decrypt(bufdr.data, 2, header);
    	KICK_IF(header[0] != PROTOCOL_VERSION || header[1] < 1 || maxNumMethods < header[1]);

    	// read
        //  +----+----------+----------+
        //  |VER | NMETHODS | METHODS  |
        //  +----+----------+----------+
        //  | 1  |    1     | 1 to 255 |
        //  +----+----------+----------+
        //                  [          ]
    	asio::async_read(ds, asio::buffer(bufdr.data, bufdr.capacity), asio::transfer_exactly(header[1]),
			boost::bind(&Channel::handleMethods, shared_from_this(), header[1],
				asio::placeholders::error, asio::placeholders::bytes_transferred));
    }

    void handleMethods(int numMethods, const boost::system::error_code& err, int bytesRead)
    {
    	KICK_IF(err)
		KICK_IF(bytesRead != numMethods)

		char methods[maxNumMethods];
    	crypto.decrypt(bufdr.data, numMethods, methods);

    	char method = AUTH_UNACCEPTABLE;
		for (int i = 0; i < numMethods; ++i)
		{
			if (methods[i] == AUTH_USERPASS)
			{
				method = methods[i];
			}
		}

		// write
        //  +----+--------+
        //  |VER | METHOD |
        //  +----+--------+
        //  | 1  |   1    |
        //  +----+--------+
        //  [             ]
		char data[2] = {PROTOCOL_VERSION, method};
		crypto.encrypt(data, 2, bufdw.data);

		if (CS_BUNLIKELY(method == AUTH_UNACCEPTABLE))
		{
			asio::async_write(ds, asio::buffer(bufdw.data, bufdw.capacity), asio::transfer_exactly(2),
				boost::bind(&Channel::shutdown, shared_from_this(),
					asio::placeholders::error, asio::placeholders::bytes_transferred));
		}
		else
		{
			asio::async_write(ds, asio::buffer(bufdw.data, bufdw.capacity), asio::transfer_exactly(2),
				boost::bind(&Channel::handleAuthSent, shared_from_this(),
					asio::placeholders::error, asio::placeholders::bytes_transferred));
		}
    }

    void handleAuthSent(boost::system::error_code err, int bytesSent)
    {
    	KICK_IF(err)

		// read
        //  +----+------+----------+------+----------+
        //  |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
        //  +----+------+----------+------+----------+
        //  | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
        //  +----+------+----------+------+----------+
        //  [           ]
		asio::async_read(ds, asio::buffer(bufdr.data, bufdr.capacity), asio::transfer_exactly(2),
			boost::bind(&Channel::handleUserLen, shared_from_this(),
				asio::placeholders::error, asio::placeholders::bytes_transferred));
    }

    void handleUserLen(const boost::system::error_code& err, int bytesRead)
    {
    	KICK_IF(err)

		char header[2];
    	crypto.decrypt(bufdr.data, 2, header);
    	KICK_IF(header[1] < 1)

		// read
        //  +----+------+----------+------+----------+
        //  |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
        //  +----+------+----------+------+----------+
        //  | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
        //  +----+------+----------+------+----------+
        //              [                 ]
		asio::async_read(ds, asio::buffer(bufdr.data, bufdr.capacity), asio::transfer_exactly(header[1] + 1),
			boost::bind(&Channel::handleUserPassLen, shared_from_this(),
				asio::placeholders::error, asio::placeholders::bytes_transferred));
    }

    void handleUserPassLen(const boost::system::error_code& err, int bytesRead)
    {
    	KICK_IF(err)

		char* userPassLen = new char[bytesRead];
    	crypto.decrypt(bufdr.data, bytesRead, userPassLen);
    	int passLen = userPassLen[bytesRead - 1];
    	KICK_IF(passLen < 1)
    	userPassLen[bytesRead - 1] = 0x00;

		// read
        //  +----+------+----------+------+----------+
        //  |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
        //  +----+------+----------+------+----------+
        //  | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
        //  +----+------+----------+------+----------+
        //              				  [          ]
		asio::async_read(ds, asio::buffer(bufdr.data, bufdr.capacity), asio::transfer_exactly(passLen),
			boost::bind(&Channel::handleUserPassLen, shared_from_this(), userPassLen,
				asio::placeholders::error, asio::placeholders::bytes_transferred));
    }

    void handleUserPass(const char* username, const boost::system::error_code& err, int bytesRead)
    {
    	if (err)
    	{
    		delete username;
    		delete this;
    		return;
    	}

    	char* password = new char[bytesRead + 1];
    	crypto.decrypt(bufdr.data, bytesRead, password);
    	password[bytesRead] = 0x00;

    	authenticater.auth(username, password, boost::bind(&Channel::handleAuthed, username, password));
    }

    void handleAuthed(const char* username, const char* password,
    		Authenticater::AuthCode code, const Authority& _authority)
    {
    	CS_DUMP(username);
    	CS_DUMP(password);
    	delete username;
    	delete password;

    	if (CS_BUNLIKELY(code != Authenticater::CODE_OK))
    	{
    		char data[2] = {PROTOCOL_VERSION, AUTH_RES_FAILED};
    		crypto.encrypt(data, 2, bufdw.data);
    		asio::async_write(ds, asio::buffer(bufdw.data, bufdw.capacity), asio::transfer_exactly(2),
				boost::bind(&Channel::shutdown, shared_from_this(),
					asio::placeholders::error, asio::placeholders::bytes_transferred));
    		return;
    	}

		authority = _authority;
		crypto.setDecKeyWithIv(authority.key, sizeof(authority.key),
				authority.iv, sizeof(authority.iv));

		char data[2 + sizeof(authority.key) + sizeof(authority.iv)] = {PROTOCOL_VERSION, AUTH_RES_SUCCESS};
		std::memcpy(data + 2, authority.key, sizeof(authority.key));
		std::memcpy(data + (2 + sizeof(authority.key)), authority.iv, sizeof(authority.iv));
		crypto.encrypt(data, sizeof(data), bufdw.data);
		// write
        //  +----+--------+-----+----+
        //  |VER | STATUS | KEY | IV |
        //  +----+--------+----------+
        //  | 1  |    1   | 16  | 16 |
        //  +----+--------+-----+----+
        //  [                        ]
		asio::async_write(ds, asio::buffer(bufdw.data, bufdw.capacity), asio::transfer_exactly(sizeof(data)),
			boost::bind(&Channel::handleAuthedSent, shared_from_this(),
				asio::placeholders::error, asio::placeholders::bytes_transferred));
    }

    void handleAuthedSent(const boost::system::error_code& err, int bytesRead)
    {
    	KICK_IF(err)
    	// read
        //  +----+-----+-------+------+----------+----------+
        //  |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        //  +----+-----+-------+------+----------+----------+
        //  | 1  |  1  | X'00' |  1   | Variable |    2     |
        //  +----+-----+-------+------+----------+----------+
        //  [                          +1]
    	asio::async_read(ds, asio::buffer(bufdr.data, bufdr.capacity), asio::transfer_exactly(5),
			boost::bind(&Channel::handleCmd, shared_from_this(),
				asio::placeholders::error, asio::placeholders::bytes_transferred));
    }

    void handleCmd(const boost::system::error_code &err, std::size_t bytesRead)
    {
    	KICK_IF(err);

    	char header[5];
    	crypto.decrypt(bufdr.data, bytesRead, header);

    	if (CS_BLIKELY(header[1] == CMD_CONNECT))
    	{
    		if (CS_BLIKELY(header[3] == ADDR_DOMAIN))
    		{
    			asio::async_read(ds, asio::buffer(bufdr.data, bufdr.capacity),
					asio::transfer_exactly(header[4] + 2),
					boost::bind(&Channel::handleDomainRequest, shared_from_this(),
						asio::placeholders::error, asio::placeholders::bytes_transferred));
    		}
    		else if (header[3] == ADDR_IPV4)
    		{
    			asio::async_read(ds, asio::buffer(bufdr.data, bufdr.capacity),
					asio::transfer_exactly(3 + 2),
					boost::bind(&Channel::handleDomainRequest, shared_from_this(), header[4],
						asio::placeholders::error, asio::placeholders::bytes_transferred));
    		}
    		else
    		{
    			// TODO: IPv6 support
    			delete this;
    			return;
//    			asio::async_read(ds, asio::buffer(bufdr.data, bufdr.capacity),
//					asio::transfer_exactly(5 + 2),
//					boost::bind(&Channel::handleDomainRequest, shared_from_this(), header[4],
//						asio::placeholders::error, asio::placeholders::bytes_transferred));
    		}
    	}
    	else
    	{
        	switch (header[1])
        	{
        	case CMD_BIND:
        		break;

        	case CMD_UDP_ASSOC:
        		break;

        	default:
        		delete this;
        		break;
        	}
    	}
    }

    void handleDomainRequest(const boost::system::error_code &err, std::size_t bytesRead)
    {
    	KICK_IF(err)

		char* host = new char[bytesRead];
    	crypto.decrypt(bufdr.data, bytesRead, host);

    	uint16_t port = (static_cast<uint16_t>(host[bytesRead - 2]) << 8) + host[bytesRead - 1];
    	port = ntohs(port);
    	KICK_IF(port == 0)

    	host[bytesRead - 2] = 0x00;
    	tcp::resolver::query query(host, "http");
    	resolver.async_resolve(query, boost::bind(&Channel::handleDomainResolved, shared_from_this(),
			asio::placeholders::error, asio::placeholders::iterator));
    }

    void handleDomainResolved(const boost::system::error_code &err, tcp::resolver::iterator it)
    {
    	KICK_IF(err)	// TODO: 域名解析出错 不应该踢下线

		asio::async_connect(us, it, boost::bind(&Channel::handleConnected,
				shared_from_this(), asio::placeholders::error));
    }

    void handleIpv4Request(char firstByte, const boost::system::error_code &err, std::size_t bytesRead)
    {
    	KICK_IF(err)

		char ipPort[8];		// to align with 4 bytes.
    	crypto.decrypt(bufdr.data, 5, ipPort + 1);
    	ipPort[0] = firstByte;
    	uint32_t ip = ntohl(*reinterpret_cast<uint32_t*>(ipPort));
    	uint16_t port = ntohs(reinterpret_cast<uint16_t*>(ipPort)[2]);
    	KICK_IF(ip == 0 || port == 0);

		asio::async_connect(us, tcp::endpoint(asio::ip::address_v4(ip), port),
				boost::bind(&Channel::handleConnected, shared_from_this(), asio::placeholders::error));
    }

    void handleConnected(const boost::system::error_code &err, std::size_t bytesRead)
    {
    	KICK_IF(err)	// TODO: 远程服务器连接出错 不应该踢下线。

		asio::async_write(ds, asio::buffer(connectSuccessResponse, sizeof(connectSuccessResponse)),
			asio::transfer_exactly(sizeof(connectSuccessResponse)),
			boost::bind(&Channel::handleConnectSuccessResponseSent, shared_from_this(),
				asio::placeholders::error, asio::placeholders::bytes_transferred));
    }

    void handleConnectSuccessResponseSent(const boost::system::error_code &err, std::size_t bytesSent)
    {
    	KICK_IF(err)

		bufdr.filled = 0;
		ds.async_read_some(asio::buffer(bufdr.data, bufdr.capacity),
			boost::bind(&Channel::handleReadBody, shared_from_this(),
				asio::placeholders::error, asio::placeholders::bytes_transferred));
    }

    void handleReadBody(const boost::system::error_code &err, std::size_t bytesRead)
    {
    	KICK_IF(err)

		bufdr.filled += bytesRead;
		crypto.decrypt(bufdr, bufuw);

		// ds.read() => us.write()
		// NOTE: 考虑 https 的情况：连接建立后，服务器端可能先发送数据。
//		asio::async_write()
    }


    ~Channel()
    {
    	shutdown();
    }

private:
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

    void shutdown(const boost::system::error_code& err, std::size_t bytesSent)
    {
    	shutdown();
    }

    void shutdown()
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
};

}
