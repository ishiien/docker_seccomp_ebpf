#include<stdio.h>

typedef unsigned int kernerer;
typedef kernerer uid_t;


typedef struct {
	uid_t val;
} kuid_t;

struct cred{
    kuid_t uid;
} test_struct;


int main(void){


    return 0;
}

