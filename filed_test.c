#include <assert.h>
#include <stdio.h>
#include "filed.c"

// Make sure this behaves according to the Linux manpage spec: 
// http://man7.org/linux/man-pages/man2/sendfile.2.html
void test_filed_sendfile_badfds() {
    ssize_t ret = filed_sendfile(-1, -1, NULL, 0);

    assert(ret == -1);
    perror("sendfile");
}

void all_tests() {
    test_filed_sendfile_badfds();
}

int main() {
    all_tests();
}