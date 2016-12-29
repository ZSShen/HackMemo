#include <chrono>
#include <iostream>


// The utility functions to calculate wall clock time.
auto makeStamp()
{
    return std::chrono::steady_clock::now();
}

template<typename T = std::chrono::milliseconds>
auto makeDuration(decltype(makeStamp()) time)
{
    return std::chrono::duration_cast<T>(
        std::chrono::steady_clock::now() - time).count();
}


int main()
{
    auto start = makeStamp();

    // Run the task.

    auto cost = makeDuration<std::chrono::milliseconds>(start);
    std::cout << "Wall clock time: " << cost << " milliseconds" << std::endl;

    return 0;
}
