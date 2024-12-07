#include <stdlib.h>
#include <stdio.h>

void print_hex(unsigned char* printme, size_t length) {
    for (size_t i = 0; i < length; i++) {
        char space = i % 16 == 15 ? '\n' : ' ';
        printf("%.2X%c", printme[i], space);
    }
    printf("\n");
}
