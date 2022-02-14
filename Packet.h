#pragma once

// packets types
enum class e_PacketType {
    RECEIVED = 1,
    SENDED = 2
};

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