#pragma once

#include "predef.hpp"
#include <ctime>
#include "Buffer.hpp"

namespace csocks
{

class Authenticater
{
private:
    Status status;

    enum Method {
        METHOD_USERNAME_PASSWORD = 2,
    };

public:
    enum Status {
        STATUS_WAITING, //  数据已准备好，等候验证
        STATUS_HUNGRY,  // 需要更多数据
        STATUS_EXPIRED, // 会员过期
        STATUS_TRAFFIC_EXHAUST, // 阶段流量耗尽
    };

    void restore(const Authority& authority)
    {
        // 持久化保存
    }

    Status auth(const Buffer& buf)
    {
        if (buf.filled < 2)
        {
            return STATUS_HUNGRY;
        }
        int end = buf.data[1] + 2;
        if (buf.filled < end)
        {
            return STATUS_HUNGRY;
        }
        for (int i = 2; i < end; ++i)
        {
            if (buf.data[i] == METHOD_USERNAME_PASSWORD)
            {
                // TODO: 开始验证
                return STATUS_WAITING;
            }
        }
        return STATUS_HUNGRY;
    }

    void packAuth(Buffer& buf)
    {
        buf.data[0] = PROTOCOL_VERSION;
        buf.data[1] = METHOD_USERNAME_PASSWORD;
        buf.filled = 2;
    }
};

class Authority
{
public:
    typedef uint64_t traf_t;

    std::time_t expires;         // 会员过期时间 unix_timestamp
    uint32_t bandwidth;          // 带宽 byte
    traf_t traffic;              // 剩余流量 byte

    std::time_t traffic_expires; // 流量过期时间
    traf_t traffic_future;       // 下一阶段的剩余流量
    std::time_t traffic_expires_future; // 下一阶段流量过期时间

    bool authed;

    Authority():
        authed(false)
    {}

    bool traffic_expired(std::time_t point) const
    {
        return traffic_expires <= point;
    }

    bool traffic_expired() const
    {
        return traffic_expired(std::time(NULL));
    }

    bool expired(std::time_t point) const
    {
        return expires <= point;
    }

    bool expired() const
    {
        return expired(std::time(NULL));
    }

    void traffic_forward()
    {
        traffic_expires = traffic_expires_future;
        traffic = traffic_future;
        traffic_future = 0;
    }

    bool allow(traf_t traf)
    {
        if (CS_UNLIKELY(traffic_expired()))
        {
            if (expired())
            {
                return false;
            }
            traffic_forward();
        }
        return traf <= traffic;
    }

    bool traf(traf_t traf)
    {
        if (CS_LIKELY(allow(traf)))
        {
            traffic -= traf;
            return true;
        }
        else
        {
            return false;
        }
    }
};

}
