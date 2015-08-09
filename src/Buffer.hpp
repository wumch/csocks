
#pragma once

#include "predef.hpp"
#include <memory>

namespace csocks
{

class Buffer
{
public:
    char* data;
    std::size_t capacity;
    std::size_t filled;

    Buffer():
        data(NULL), capacity(0), filled(0)
    {}

    Buffer(std::size_t _size):
        data(NULL), capacity(_size), filled(0)
    {
        setCapacity(capacity);
    }

    void setCapacity(std::size_t _capacity)
    {
        if (data != NULL)
        {
            throw std::bad_alloc();
        }
        capacity = _capacity;
        data = new char[capacity];
    }

    ~Buffer()
    {
        delete data;
    }
};

}
