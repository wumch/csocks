
#pragma once

#include "predef.hpp"

namespace csocks
{

class Buffer
{
public:
    char* data;
    const std::size_t size;
    std::size_t filled;

    Buffer():
        size(0), filled(0)
    {}

    Buffer(std::size_t _size):
        size(_size), filled(0)
    {
        data = new char[size];
    }

    ~Buffer()
    {
        delete data;
    }
};

}