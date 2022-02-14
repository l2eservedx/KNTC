#ifndef _COMMON_H_
#define _COMMON_H_

#ifndef NULL
#define NULL ((void *) 0)
#endif

typedef struct {
	char ID;
	unsigned short len;
	char* data;
} Packet;

Packet* unpackPacket(const char* data, int len, int& next);

enum class e_PacketType {
	RECEIVED = 1,
	SENDED = 2
};

// readSocket() error codes
#define SF_NODATA 0
#define SF_CLOSED -1

SOCKET createSocket(int port);
bool isConnected(SOCKET s);
bool dataWaiting(SOCKET s);
int readSocket(SOCKET s, char* buf, int len);

/* Alloc Console to Show DEBUG messages */
void debugInit();
void debug(const char* message);

class Packetx {
    //std::string name;
    int ID;
    int length;
    char* content;
    e_PacketType packetType;

public:
    //string getName();
    Packetx(int cID, int clength, char* ccontent, e_PacketType cpacketType);
    int getID();
    int getLength();
    char* getContent();
    e_PacketType getPacketType();
    void printPacket(bool debug);
};

#endif /* _COMMON_H_ */
