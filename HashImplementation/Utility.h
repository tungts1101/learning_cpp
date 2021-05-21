#ifndef __UTILITY_H__
#define __UTILITY_H__

#include <stdint.h>
#include <assert.h>

#define INT_BITS 32

static inline uint32_t rotl32(uint32_t n, unsigned int c)
{
    return (n << c) | (n >> (INT_BITS - c));
}

static inline uint32_t rotr32(uint32_t n, unsigned int c)
{
    return (n >> c) | (n << (INT_BITS - c));
}

#endif
