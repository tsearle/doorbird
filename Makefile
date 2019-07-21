doorbird:
	gcc doorbird.c -o doorbird -lsodium

debug:
	gcc doorbird.c -o doorbird -lsodium -DDEBUG
