typedef int (*Operation)(int);

int source = 3;
int result;

int add_one(int value)
{
    return value + 1;
}

int invoke(Operation operation, int value)
{
    return operation(value);
}

int main(void)
{
    result = invoke(add_one, source);
    return result != 4;
}
