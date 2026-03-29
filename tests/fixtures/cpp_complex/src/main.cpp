#include "fixture.hpp"

int main() {
    return fixture::run_demo() & 0xff;
}
