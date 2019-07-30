all: doorbird

doorbird: doorbird.c
	gcc doorbird.c -o doorbird -lsodium

debug:
	gcc doorbird.c -o doorbird -lsodium -DDEBUG

clean:
	rm doorbird
