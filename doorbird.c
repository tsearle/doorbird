#include <sodium.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>


typedef struct {
	unsigned char id[3];
	unsigned char version;
	uint32_t opslimit;
	uint32_t memlimit;
	unsigned char salt[16];
	unsigned char nonce[8];
	unsigned char ciphertext[34];
} doorbird_pkt;

typedef struct {
	char intercom_id[6];
	char event [8];
	unsigned timestamp;
} doorbird_cipher_text;

#define LOGGING(format, ...) printf(format, ##__VA_ARGS__)

#ifdef DEBUG
#define LOG_DEBUG(format, ...) printf(format, ##__VA_ARGS__)
#else
#define LOG_DEBUG(format, ...) do {} while (0)
#endif
#define CRYPTO_SALT_BYTES 16
#define CRYPTO_ARGON_OUT_SIZE 32

#define MAX(x,y) (x>y?x:y)

void hexdump(unsigned char * data, int len) {
	for(int i=0; i<len;i++) {
		printf("0x%02X ", data[i]);
	}
}

unsigned char* stretchPasswordArgon(const char *password, unsigned char *salt, unsigned* oplimit, unsigned* memlimit) {
	if (sodium_is_zero(salt, CRYPTO_SALT_BYTES) ) {
		randombytes_buf(salt, CRYPTO_SALT_BYTES);
		return NULL;
	}
	unsigned char* key = malloc(CRYPTO_ARGON_OUT_SIZE);
	if (!*oplimit) {
		*oplimit = crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE;
	}
	if (!*memlimit) {
		*memlimit = crypto_pwhash_MEMLIMIT_MIN;
	}
	if (crypto_pwhash(key, CRYPTO_ARGON_OUT_SIZE, password, strlen(password), salt, *oplimit, *memlimit, crypto_pwhash_ALG_ARGON2I13)) {
		LOGGING("Argon2 Failed\n");
		*oplimit = 0;
		*memlimit = 0;
		free(key);
		return NULL;
	}
	return key;
}

doorbird_cipher_text decrypt_broadcast_notification(const doorbird_pkt * notification, const unsigned char* password) {
	doorbird_cipher_text decrypted = {{0},{0},0};
	int res = 0;
	if(res = crypto_aead_chacha20poly1305_decrypt((unsigned char*)&decrypted, NULL, NULL, notification->ciphertext, sizeof(notification->ciphertext), NULL, 0, notification->nonce, password)){
		LOGGING("crypto_aead_chacha20poly1305_decrypt() failed %d\n", res);
		perror(NULL);
	}
	return decrypted;
}

doorbird_cipher_text decode_packet(unsigned char * packet, int size, char * password) {
	char pass5[6];
	doorbird_pkt * pkt = (doorbird_pkt*)packet;
	doorbird_cipher_text decrypted = {{0},{0},0};

	if (size != 70) {
		LOG_DEBUG("Packet wrong size, ignoring!\n");
		return decrypted;
	}	       

	if (pkt->id[0] != 0xDE || pkt->id[1] != 0xAD || pkt->id[2] != 0xBE) {
		LOG_DEBUG("Wrong ident!, ignoring\n");
		return decrypted;
	}

	LOG_DEBUG("Version %d detected\n", packet[3]);
	strncpy(pass5, password, 5);
	unsigned opslimit = ntohl(pkt->opslimit);
	unsigned memlimit = ntohl(pkt->memlimit);

	LOG_DEBUG("Opslimit %u, memlimit %u\n", opslimit, memlimit);

#ifdef DEBUG
	LOG_DEBUG("salt: ");
	hexdump(pkt->salt, sizeof(pkt->salt));
	LOG_DEBUG("\n");
#endif

	unsigned char* stretchPass = stretchPasswordArgon(pass5, pkt->salt, &opslimit, &memlimit); 
	if (stretchPass == NULL) {
		LOGGING("Error making stretchpass!\n");
	}


#ifdef DEBUG
	LOG_DEBUG("pass5: %s\n", pass5);
	LOG_DEBUG("Stretch Pass: ");
	hexdump(stretchPass, CRYPTO_ARGON_OUT_SIZE);
	LOG_DEBUG("\n");

	LOG_DEBUG("nonce text: ");
	hexdump(pkt->nonce, sizeof(pkt->nonce));
	LOG_DEBUG("\n");

	LOG_DEBUG("cipher text: ");
	hexdump(pkt->ciphertext, sizeof(pkt->ciphertext));
	LOG_DEBUG("\n");
#endif


	decrypted = decrypt_broadcast_notification(pkt, stretchPass);
	
	decrypted.timestamp = ntohl(decrypted.timestamp);

	return decrypted;


}

void handle_event(char * event_str) {
	LOGGING("Got an event: '%s'\n", event_str);

	/**
	 * Add your logic for doorbell events here
	 */
}


int main(int argc, char *argv[]) {
	struct sockaddr_in si_me, si_other;
	int s1=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	int s2=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	int port1=6524;
	int port2=35344;
	int broadcast=1;
	unsigned int timestamp;
	fd_set readfds;
	char *user,*password; 

	if(argc < 2) {
		printf("Usage:\n./doorbird user password\n");
		return -1;
	}

	user = argv[1];
	password = argv[2];

	setsockopt(s1, SOL_SOCKET, SO_BROADCAST,
		    &broadcast, sizeof broadcast);
	setsockopt(s2, SOL_SOCKET, SO_BROADCAST,
		    &broadcast, sizeof broadcast);

	memset(&si_me, 0, sizeof(si_me));
	si_me.sin_family = AF_INET;
	si_me.sin_port = htons(port1);
	si_me.sin_addr.s_addr = INADDR_ANY;

	bind(s1, (struct sockaddr *)&si_me, sizeof(struct sockaddr));

	si_me.sin_port = htons(port2);
	bind(s2, (struct sockaddr *)&si_me, sizeof(struct sockaddr));

	while(1)
	{
		FD_ZERO(&readfds);
		FD_SET(s1, &readfds);
		FD_SET(s2, &readfds);
		char buf[10000];
		int len = 0;
		unsigned slen=sizeof(struct sockaddr);

		int activity = select(MAX(s1,s2)+1, &readfds, NULL, NULL, NULL);
		if (activity > 0) {
			if(FD_ISSET(s1, &readfds)) {
				len = recvfrom(s1, buf, sizeof(buf)-1, 0, (struct sockaddr *)&si_other, &slen);
			} else {
				len = recvfrom(s2, buf, sizeof(buf)-1, 0, (struct sockaddr *)&si_other, &slen);
			}
		}

		LOG_DEBUG("Got packet of size %d\n", len);

		doorbird_cipher_text event = decode_packet(buf, len, password);
		if(event.timestamp == 0) {
			continue;
		}

		char intercom_id[10];
		char event_str[10];
		
		strncpy(intercom_id, event.intercom_id, 6);
		intercom_id[6] = 0;
		strncpy(event_str, event.event, 8);
		event_str[8] = 0;

		if(strncmp(user,intercom_id,6) != 0) {
			LOGGING("Not the expected doorbel %s, ignoring\n", intercom_id);
			continue;
		}

		if(timestamp == event.timestamp) {
			LOGGING("Retransmitted event, ignorning\n");
			continue;
		}
		
		timestamp = event.timestamp;

		handle_event(event_str);

	}

	return 0;

}
