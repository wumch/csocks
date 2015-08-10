
#include "Channel.hpp"

namespace csocks
{

// 连接成功.
//  +----+-----+-------+------+----------+----------+
//  |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
//  +----+-----+-------+------+----------+----------+
//  | 1  |  1  | X'00' |  1   | Variable |    2     |
//  +----+-----+-------+------+----------+----------+
//  [                                               ]
const char Channel::ConnectResponse::succeed5[10] = { PROTOCOL_V5,
    Channel::SOCKS5_CONNECT_SUCCEED, 0x00, ADDR_IPV4 };

const char Channel::ConnectResponse::succeed4[10] = { PROTOCOL_V4,
    Channel::SOCKS4_CONNECT_SUCCEED, 0x00, ADDR_IPV4 };

// socks5 连接失败
//  +----+-----+-------+------+----------+----------+
//  |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
//  +----+-----+-------+------+----------+----------+
//  | 1  |  1  | X'00' |  1   | Variable |    2     |
//  +----+-----+-------+------+----------+----------+
//  [                                               ]
const char Channel::ConnectResponse::failed5[10] = { PROTOCOL_V5,
    Channel::SOCKS5_CONNECT_FAILED, 0x00, ADDR_IPV4 };

// socks4 连接失败
//  +----+----+----+----+----+----+----+----+
//  | VN | CD | DSTPORT |      DSTIP        |
//  +----+----+----+----+----+----+----+----+
//  | 1  | 1  |    2    |         4         |
//  +----+----+----+----+----+----+----+----+
//  [                                       ]
const char Channel::ConnectResponse::failed4[8] = { PROTOCOL_V4,
    Channel::SOCKS4_CONNECT_FAILED };

}
