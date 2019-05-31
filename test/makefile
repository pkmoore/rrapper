all: callread calltime gtodtest renametest

smallprog: smallprog.c
	gcc -ggdb -o smallprog smallprog.c

callread: callread.c
	gcc -ggdb -o callread callread.c

calltime: calltime.c
	gcc -ggdb -o calltime calltime.c

gtodtest: gtodtest.c
	gcc -ggdb -o gtodtest gtodtest.c

renametest: renametest.c
	gcc -ggdb -o renametest renametest.c

clean:
	- rm smallprog
	- rm callread
	- rm calltime
	- rm gtodteset
	- rm renametest
