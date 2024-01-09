#include <stdio.h>
#include <stdlib.h>
#include "xhook.h"
void foo(int n){
	printf("foo:output %d\n",n);
}
void add50(int n){
	long lv;
	xhook_uncurse(foo,add50,LONG_MIN);
	lv=xhook_getlevel();
	foo(n+50);
	xhook_curse(foo,add50,lv);
}
void mul2(int n){
	long lv;
	xhook_uncurse(foo,mul2,LONG_MIN);
	lv=xhook_getlevel();
	foo(n*2);
	xhook_curse(foo,mul2,lv);
}
void deny(int n){
	puts("deny:foo is denied");
}
int main(void){
	foo(5);
	puts("Note:60=(5*2)+50 110=(5+50)*2\n");
	xhook_curse(foo,deny,0);
	puts("main:foo to deny (level 0)");
	foo(5);
	xhook_uncurse(foo,deny,0);
	puts("main:foo is uncursed\n");
	foo(5);
	xhook_curse(foo,add50,0);
	puts("main:foo to add50 (level 0)");
	foo(5);
	xhook_curse(foo,mul2,0);
	puts("main:foo to mul2 (level 0)");
	foo(5);
	xhook_wipe();
	puts("main:foo is uncursed\n");
	foo(5);
	xhook_curse(foo,mul2,0);
	puts("main:foo to mul2 (level 0)");
	foo(5);
	xhook_curse(foo,add50,0);
	puts("main:foo to add50 (level 0)");
	foo(5);
	xhook_wipe();
	puts("main:foo is uncursed\n");
	foo(5);
	xhook_curse(foo,mul2,1);
	puts("main:foo to mul2 (level 1)");
	foo(5);
	xhook_curse(foo,add50,0);
	puts("main:foo to add50 (level 0)");
	foo(5);
	xhook_wipe();
	puts("main:foo is uncursed\n");
	return EXIT_SUCCESS;
}
