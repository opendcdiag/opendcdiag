/*
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_SANDSTONE_SPAN_H
#define INC_SANDSTONE_SPAN_H

#include <iterator>
#include <stddef.h>

// A simple replacement implementation of std::span
// https://en.cppreference.com/w/cpp/container/span
template <typename T, size_t Extent = ~size_t(0)>
class span
{
    static_assert(Extent == -1, "Only dynamic extents supported");
    T *_begin = nullptr;
    T *_end = nullptr;
public:
    using element_type = T;
    using size_type = size_t;
    using difference_type = ptrdiff_t;
    using pointer = T *;
    using const_pointer = const T *;
    using reference = T &;
    using const_reference = const T &;

    using iterator = pointer;
    using const_iterator = const_pointer;
    using reverse_iterator = std::reverse_iterator<iterator>;
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;

    static constexpr size_t extent = Extent;

    constexpr span() noexcept = default;
    constexpr span(T *first, size_type count) : _begin(first), _end(first + count) {}
    constexpr span(T *first, T *last) : _begin(first), _end(last) {}
    template <size_t N> constexpr span(element_type (&arr)[N]) : span(arr, N) {}
    // other constructors not needed

    constexpr pointer data() const { return _begin; }
    constexpr iterator begin() const { return _begin; }
    constexpr iterator end() const { return _end; }

    constexpr reference front() const { return *_begin; }
    constexpr reference back() const { return _end[-1]; }

    constexpr reference operator[](size_t idx) const  { return _begin[idx]; }

    constexpr size_t size() const { return _end - _begin; }
    constexpr size_t size_bytes() const { return size() * sizeof(T); }
    constexpr bool empty() const { return size() == 0; }
};

#endif
