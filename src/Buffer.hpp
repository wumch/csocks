
#pragma once

#include "predef.hpp"
#include <memory>

namespace csocks
{

class Buffer
{
public:
    char* data;
    std::size_t size;
    std::size_t filled;

    Buffer():
        data(NULL), size(0), filled(0)
    {}

    Buffer(std::size_t _size):
        data(NULL), size(_size), filled(0)
    {
        setSize(size);
    }

    void setSize(std::size_t _size)
    {
        if (data != NULL)
        {
            throw std::bad_alloc();
        }
        size = _size;
        data = new char[size];
    }

    ~Buffer()
    {
        delete data;
    }
};

}