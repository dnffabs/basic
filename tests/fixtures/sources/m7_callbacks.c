typedef int (*callback)(void);
typedef callback (*factory)(void);

static factory volatile create;
static callback volatile selected;

int result(void) { return 7; }
int left(void) { return 11; }
int right(void) { return 13; }
callback make_callback(void) { return result; }

int cascade(void) {
    create = make_callback;
    return create()();
}

int dispatch(int choose) {
    if (choose)
        selected = left;
    else
        selected = right;
    return selected();
}

int main(int argc, char **argv) {
    (void)argv;
    return cascade() + dispatch(argc > 1);
}
