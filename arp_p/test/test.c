#include <stdio.h>
#include <string.h>

int main()
{
    char str1[] = "geeks";
    char str2[] = "quiz";

    puts("str1 before memcpy");
    puts(str1);

    memcpy(str1, str2, sizeof(str2));

    puts("\n str1 after memcpy");
    puts(str1);
    return 0;
}