#include <iostream>
#include <vector>
#include <unordered_map>


template <typename T, T Begin = T::Begin, T End = T::End>
class Enum {
public:
    Enum() {}
    ~Enum() {}

    Enum(const Enum&) = delete;
    Enum(Enum&&) = delete;
    Enum& operator=(const Enum&) = delete;
    Enum& operator=(Enum&&) = delete;

    class Iterator {
    public:
        Iterator(int value)
          : value_(value)
        {}

        T operator*() const
        {
            return static_cast<T>(value_);
        }

        void operator++()
        {
            ++value_;
        }

        bool operator!=(const Iterator &rhs)
        {
            return value_ != rhs.value_;
        }

    private:
        int value_;
    };

    Iterator begin()
    {
        return Iterator(static_cast<int>(Begin));
    }

    Iterator end()
    {
        return Iterator(static_cast<int>(End) + 1);
    }
};

namespace a {
namespace b {

enum class Color {
    No = -1,
    Red = 0,
    Green,
    Blue,
    Yellow,
    Purple,
    Begin = Red,
    End = Purple
};

}
}

void changeEnum(a::b::Color &en)
{
    en = a::b::Color::Purple;
}


int main()
{
    using Color = a::b::Color;
    for (auto iter : Enum<Color>()) {
        std::cout << static_cast<int>(iter) << std::endl;
    }

    auto en = a::b::Color::Red;
    std::cout << "before " << static_cast<int>(en) << std::endl;

    changeEnum(en);
    std::cout << "after  " << static_cast<int>(en) << std::endl;

    return 0;
}