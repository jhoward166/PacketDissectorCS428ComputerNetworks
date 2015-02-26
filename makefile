all: dissector 

dissector: dissector.c
	gcc -g -Wall -o dissector dissector.c -lpcap


