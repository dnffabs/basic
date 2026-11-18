#include <stdio.h>
#include <stdlib.h>

typedef int (*Operation)(int, int);

int initialized_value = 7;
unsigned char zero_buffer[256];
const char message[] = "bpa-test";

int add(int left, int right)
{
    return left + right;
}

int subtract(int left, int right)
{
    return left - right;
}

Operation operations[] = {add, subtract};

struct Pair {
    Operation operation;
    int value;
};

int apply(Operation operation, int left, int right)
{
    return operation(left, right);
}

int invoke(struct Pair *pair)
{
    return pair->operation(pair->value, 1);
}

int main(void)
{
    struct Pair local = {add, initialized_value};
    struct Pair *heap = malloc(sizeof(*heap));
    if (heap == NULL)
        return 1;
    heap->operation = subtract;
    heap->value = 10;
    zero_buffer[3] = 5;

    int sum = apply(operations[0], 9, 4);
    int difference = apply(operations[1], 9, 4);
    int stack_result = invoke(&local);
    int heap_result = invoke(heap);
    free(heap);

    printf("%s: %d %d %d %d\n", message, sum, difference, stack_result, heap_result);
    return !(sum == 13 && difference == 5 && stack_result == 8 && heap_result == 9
             && zero_buffer[0] == 0 && zero_buffer[3] == 5);
}
