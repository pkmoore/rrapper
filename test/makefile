all: callread gtodtest renametest callwrite


smallprog: smallprog.c
	gcc -ggdb -o smallprog smallprog.c

callread: callread.c
	gcc -ggdb -o callread callread.c
	
callwrite: callwrite.c
	gcc -ggdb -o callwrite callwrite.c

gtodtest: gtodtest.c
	gcc -ggdb -o gtodtest gtodtest.c

renametest: renametest.c
	gcc -ggdb -o renametest renametest.c

clean:
	- rm smallprog
	- rm callread
	- rm gtodteset
	- rm renametest
