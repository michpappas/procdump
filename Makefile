procdump: procdump.c
	gcc -o procdump procdump.c
	chmod +x procdump

clean:
	rm procdump
