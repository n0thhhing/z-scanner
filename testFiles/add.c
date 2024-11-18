#include <stdio.h>

int add(int a, int b) {
    return a+b;
}

int main() {
    int a = 1;
    int b = 2;
    int result = a+b;
    printf("%d + %d = %d\n", a, b, result);
};