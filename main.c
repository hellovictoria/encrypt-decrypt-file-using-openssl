#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include "safeopts1.h"

int main()
{
        FILE * encry_fp;
        FILE * decry_fp;
        char * ecypted_code;
        char * dcypted_code;

        encry_fp=ecyfopen("a","r");
        ecypted_code=(char *)malloc(encrylen * sizeof(char));
        fread(ecypted_code,encrylen,1,encry_fp);
        printf("output encrypted code:\n%s\n",ecypted_code);

        dcyprint("a","r");
        return 1;
}

