#include "test.h"
#include "varint_test.c"
#include "header_test.c"

int main(void)
{
    test_varint();
    test_header();
    return TEST_REPORT();
}
