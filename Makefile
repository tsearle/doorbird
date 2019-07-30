all: doorbird

doorbird: doorbird.c
	gcc doorbird.c -o doorbird -lsodium -lcurl

debug: doorbird.c
	gcc doorbird.c -o doorbird -lsodium -lcurl -DDEBUG

clean:
	rm doorbird
