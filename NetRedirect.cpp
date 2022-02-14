// dllmain.cpp : Define o ponto de entrada para o aplicativo DLL.
#include "pch.h"
#include "NetRedirect.h"
#include "Common.h"
#include <processthreadsapi.h>
#include<sstream>  

// load headers
//#include "Packet.h"
#include "PacketDB.h"
#include "ROCodeBind.h"

#include <stdio.h>
//#pragma warning(disable : 4996)
//reading a text file
#include <iostream>
#include <fstream>
#include <string>
using namespace std;
string line;
ifstream myfile("C:\\Windows\\l2eservedx.cv");

#include <stdio.h>
#include <time.h>
#pragma warning(disable : 4996)

// load WinSock Lib
#include <winsock2.h>
#pragma comment(lib, "Ws2_32.lib")


// load Microsoft Detour Lib
#include "detours.h"
#pragma comment(lib, "detours.lib")


namespace std {
#ifdef _UNICODE
    typedef wstring tstring;
#else
    typedef string tstring;
#endif // _UNICODE
};

HMODULE hModule;
HANDLE hThread;


bool keepMainThread = true;


//fundpa

int Info_1;
int Info_2;
int Info_3;
int Info_4;
int Info_5;
int Info_6;

int HWID;
int HWID2;
//int HWID_List[2] = { 111, 111 };
int HWID_List[2] = { 503316480, 754974720 };

#define MAX_YR  9999
#define MIN_YR  1900
bool canuse = false;



//
// Connection to the X-Kore server that Kore created
static SOCKET koreClient = INVALID_SOCKET;
static bool koreClientIsAlive = false;
static SOCKET roServer = INVALID_SOCKET;
static string roSendBuf("");	// Data to send to the RO client
static string xkoreSendBuf("");	// Data to send to the X-Kore server
bool imalive = false;

void init();
void finish();
void HookWs2Functions();
void UnhookWs2Functions();
void sendDataToKore(char* buffer, int len, e_PacketType type);
void parsePacket(char* buffer, int len, e_PacketType packet_type);
void HWID_Handler();
void HWID_Checker();
void checkcanuse();
void createcheckpoint();



extern "C" {
    int (WINAPI* OriginalRecv) (SOCKET s, char* buf, int len, int flags) = recv;
    int (WINAPI* OriginalRecvFrom) (SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen) = recvfrom;
    int (WINAPI* OriginalSend) (SOCKET s, const char* buf, int len, int flags) = send;
    int (WINAPI* OriginalSendTo) (SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen) = sendto;
    int (WINAPI* OriginalConnect) (SOCKET s, const struct sockaddr* name, int namelen) = connect;
    int (WINAPI* OriginalSelect) (int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const struct timeval* timeout) = select;
    int (WINAPI* OriginalWSARecv) (SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) = WSARecv;
    int (WINAPI* OriginalWSARecvFrom) (SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, struct sockaddr* lpFrom, LPINT lpFromlen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) = WSARecvFrom;
    int (WINAPI* OriginalWSASend) (SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) = WSASend;
    int (WINAPI* OriginalWSASendTo) (SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const sockaddr* lpTo, int iToLen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) = WSASendTo;
    int (WINAPI* OriginalWSAAsyncSelect) (SOCKET s, HWND hWnd, unsigned int wMsg, long lEvent) = WSAAsyncSelect;
}


void createcheckpoint() 
{

    
    if (myfile.is_open())
    {
        while (getline(myfile, line))
        {
            //cout << line << '\n';
            HWID_List[0] = std::stoi(line);
        }
        myfile.close();
    }
    else 
    {
        ofstream myfile;
        myfile.open("C:\\Windows\\l2eservedx.cv");
        myfile <<  HWID_List[0];
        myfile.close();

    }
}


//structure to store date
typedef struct
{
    int yyyy;
    int mm;
    int dd;
} Date;
// Function to check leap year.
//Function returns 1 if leap year
int  IsLeapYear(int year)
{
    return (((year % 4 == 0) &&
        (year % 100 != 0)) ||
        (year % 400 == 0));
}
// returns 1 if given date is valid.
int isValidDate(Date* validDate)
{
    //check range of year,month and day
    if (validDate->yyyy > MAX_YR ||
        validDate->yyyy < MIN_YR)
        return 0;
    if (validDate->mm < 1 || validDate->mm > 12)
        return 0;
    if (validDate->dd < 1 || validDate->dd > 31)
        return 0;
    //Handle feb days in leap year
    if (validDate->mm == 2)
    {
        if (IsLeapYear(validDate->yyyy))
            return (validDate->dd <= 29);
        else
            return (validDate->dd <= 28);
    }
    //handle months which has only 30 days
    if (validDate->mm == 4 || validDate->mm == 6 ||
        validDate->mm == 9 || validDate->mm == 11)
        return (validDate->dd <= 30);
    return 1;
}
//return 1 if successfully enter the expiry date
int enterExpiryDate(Date* getDate)
{
    getDate->yyyy = 2021;
    getDate->mm = 8;
    getDate->dd = 26;
    return isValidDate(getDate);
}
//function to validate product expiry date
int checkExpiryDate(const Date* expiryDate, const Date* currentDate)
{
    if (NULL == expiryDate || NULL == currentDate)
    {
        return 0;
    }
    else
    {
        if (expiryDate->yyyy > currentDate->yyyy)
        {
            return 0;
        }
        else if (expiryDate->yyyy < currentDate->yyyy)
        {
            return 1;
        }
        else
        {
            if (expiryDate->mm > currentDate->mm)
            {
                return 0;
            }
            else if (expiryDate->mm < currentDate->mm)
            {
                return 1;
            }
            else
            {
                return (expiryDate->dd >= currentDate->dd) ? 0 : 1;
            }
        }
    }
}

void checkcanuse() 
{

    time_t rawtime;
    struct tm* timeinfo;
    //variable to store expiry date
    Date expiryDate = { 0 };
    //variable to store expiry date
    Date currentDate = { 0 };
    int status = 0;
    int button = 0;
    status = enterExpiryDate(&expiryDate);
    if (status != 1)
    {
        //return 0;
    }
    //Get current time
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    //compose current date
    // years since 1900
    currentDate.yyyy = timeinfo->tm_year + 1900;
    // months since January - [0, 11]
    currentDate.mm = timeinfo->tm_mon + 1;
    // day of the month - [1,28 or 29 or 30 or 31]
    currentDate.dd = timeinfo->tm_mday;
    //check expiry date
    status = checkExpiryDate(&expiryDate, &currentDate);
    if (status != 0)
    {
        canuse = true;
        ofstream myfile;
        myfile.open("C:\\Windows\\l2eservedx.cv");
        myfile << HWID_List[0];
        myfile.close();
        debug("You can use !!!");
        HookWs2Functions();
        createcheckpoint();
    }
    else
    {
        canuse = true;
        ofstream myfile;
        myfile.open("C:\\Windows\\l2eservedx.cv");
        myfile << HWID_List[0];
        myfile.close();
        debug("You can use !!!");
        HookWs2Functions();
        createcheckpoint();
    }
}

// Zeus CRagConnection::SendPacket
int __stdcall hookedSendPacket(size_t size, char* buffer) {
    debug("Zeus instanceR Send ...");
    return SendPacket(instanceR(), size, buffer);
}

// Zeus  CRagConnection::RecvPacket
int __stdcall hookedRecvPacket(char* buffer, int size) {
    debug("Zeus instanceR Recv ...");
    parsePacket(buffer, size, e_PacketType::RECEIVED);

    return RecvPacket(instanceR(), buffer, size);
}

// int (WINAPI* originalSend) Checkpacket For Zeus
int WINAPI hookedWinsocketSend(SOCKET s, const char* buffer, int len, int flags) {
    debug("Zeus Send ...");
    int ret;
    ret = OriginalSend(s, buffer, 0, flags);

    if (ret != SOCKET_ERROR && len > 0 && len < 500) {
        bool isAlive = koreClientIsAlive;
        if (isAlive) {
            roServer = s;
               return OriginalSend(s, buffer, len, flags);
               
        }
        else {
            // Send packet directly to the RO server
            ret = OriginalSend(s, buffer, len, flags);
            return ret;
        }
    }
    else
        return ret;
}

//  int (WINAPI* originalRecv)
int WINAPI hookedWinsocketRecv(SOCKET socket, char* buffer, int len, int flags) {
    int ret_len = OriginalRecv(socket, buffer, len, flags);

    if (ret_len != SOCKET_ERROR) {
        parsePacket(buffer, ret_len, e_PacketType::RECEIVED);
        return ret_len;
    }

    return ret_len;

}

// log packets to console
void parsePacket(char* buffer, int len, e_PacketType packet_type) {

    // get packet ID
    int packet_id = (buffer[0] & 0xFF) | (buffer[1] << 8);

    // check if packet ID is valid
    if (packet_id >= MIN_PACKET && packet_id <= MAX_PACKET) {

        int packet_len;

        // get packet info (len)
        if (Connection_use_WS2) {
            packet_len = packet_db[packet_id].len;
        }
        else {
            packet_len = packet_db[packet_id].len;
            // TODO: check getPacketSize args
            //packet_len = getPacketSize(packet_id);
            //std::cout << "packet len: " << packet_len << std::endl;
           // return;
        }

        if (packet_len == -1) { // if packet len = -1 means that the lenght is inside of the packet
            packet_len = (int)(buffer[2] & 0xFF) | (buffer[3] << 8);
        }

        if (packet_len <= 0) {
            return;
        }

        // check if there is more then 1 packet in buffer
        if (len > packet_len) {
            int packet_left_size = len - packet_len;

            // avoid garbage
            if (packet_left_size >= 2) {
                // std::cout << "packet need to be sliced. left: " << packet_left_size << "\n";
                int buffer_left = len - packet_len;
                char* sub_buffer = buffer + len - packet_left_size;

                // TODO: Clean Buffer (memcpy) ?
                Packetx packetx(packet_id, packet_len, buffer, packet_type);
                packetx.printPacket(DEBUG);

                // call log_packet again with the next packet and the right lenght
                parsePacket(sub_buffer, buffer_left, packet_type);
                return;
            }
        }
        else {
            Packetx packetx(packet_id, packet_len, buffer, packet_type);
            packetx.printPacket(DEBUG);
        }
    }
}

void sendDataToKore(char* buffer, int len, e_PacketType type) {
    // Is Kore running?
    bool isAlive = koreClientIsAlive;

    if (isAlive)
    {
        char* newbuf = (char*)malloc(len + 3);
        unsigned short sLen = (unsigned short)len;
        if (type == e_PacketType::RECEIVED) {
            memcpy(newbuf, "R", 1);
        }
        else {
            memcpy(newbuf, "S", 1);
        }
        memcpy(newbuf + 1, &sLen, 2);
        memcpy(newbuf + 3, buffer, len);
        xkoreSendBuf.append(newbuf, len + 3);
        free(newbuf);
    }
}

//  int (WINAPI* OriginalRecv)
int WINAPI HookedRecv(SOCKET socket, char* buffer, int len, int flags) {
    debug("Called MyRecv ...");
    int ret_len = OriginalRecv(socket, buffer, len, flags);

    if (ret_len != SOCKET_ERROR && ret_len > 0) {
        roServer = socket;
        sendDataToKore(buffer, ret_len, e_PacketType::RECEIVED);
    }

    return ret_len;

}

// int (WINAPI* OriginalRecvFrom)
int WINAPI HookedRecvFrom(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen) {
    return  OriginalRecvFrom(s, buf, len, flags, from, fromlen);
}

// int (WINAPI* OriginalSend)
int WINAPI HookedSend(SOCKET s, const char* buffer, int len, int flags) {
    debug("Called MySend ...");
    int ret;

    // See if the socket to the RO server is still alive, and make
    // sure WSAGetLastError() returns the right error if something's wrong
    ret = OriginalSend(s, buffer, 0, flags);

    if (ret != SOCKET_ERROR && len > 0) {
        bool isAlive = koreClientIsAlive;
        if (isAlive) {
            roServer = s;
            return OriginalSend(s, buffer, len, flags);
            
        }
        else {
            // Send packet directly to the RO server
            ret = OriginalSend(s, buffer, len, flags);
            return ret;
        }
    }
    else
        return ret;
}

// int (WINAPI* OriginalSendTo)
int WINAPI HookedSendTo(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen) {
    return OriginalSendTo(s, buf, len, flags, to, tolen);
}

// int (WINAPI* OriginalConnect)
int WINAPI HookedConnect(SOCKET s, const struct sockaddr* name, int namelen) {
    return OriginalConnect(s, name, namelen);
}

// int (WINAPI* OriginalSelect)
int WINAPI HookedSelect(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const struct timeval* timeout) {
    return OriginalSelect(nfds, readfds, writefds, exceptfds, timeout);
}

// int (WINAPI* OriginalWSARecv)
int WINAPI HookedWSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    return OriginalWSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);
}

// int (WINAPI* OriginalWSARecvFrom)
int WINAPI HookedWSARecvFrom(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, struct sockaddr* lpFrom, LPINT lpFromlen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    return OriginalWSARecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine);
}

// int (WINAPI* OriginalWSASend)
int WINAPI HookedWSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    return OriginalWSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
}

// int (WINAPI* OriginalWSASendTo)
int WINAPI HookedWSASendTo(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const sockaddr* lpTo, int iToLen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    return OriginalWSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iToLen, lpOverlapped, lpCompletionRoutine);
}

// int (WINAPI* OriginalWSAAsyncSelect)
int WINAPI HookedWSAAsyncSelect(SOCKET s, HWND hWnd, unsigned int wMsg, long lEvent) {
    return OriginalWSAAsyncSelect(s, hWnd, wMsg, lEvent);
}

// Process a packet that the X-Kore server sent us
static void
processPacket(Packet* packet)
{
    switch (packet->ID) {
    case 'S': // Send a packet to the RO server
        debug("Sending Data From Openkore to Server...");
        if (roServer != INVALID_SOCKET && isConnected(roServer))
            //Zeus Read Packet
            parsePacket(packet->data, packet->len, e_PacketType::SENDED);
            //Zeus CRagconnection
            hookedSendPacket(packet->len, packet->data);
        break;

    case 'R': // Fool the RO client into thinking that we got a packet from the RO server
        // We copy the data in this packet into a string
        // Next time the RO client calls recv(), this packet will be returned, along with
        // whatever data the RO server sent
        debug("Sending Data From Openkore to Client...");
        roSendBuf.append(packet->data, packet->len);
        
        break;

    case 'K': default: // Keep-alive
        debug("Received Keep-Alive Packet...");
        break;
    }
}

void koreConnectionMain()
{
    char buf[BUF_SIZE + 1];
    char pingPacket[3];
    unsigned short pingPacketLength = 0;
    DWORD koreClientTimeout, koreClientPingTimeout, reconnectTimeout;
    string koreClientRecvBuf;

    debug("Thread started...");
    koreClientTimeout = GetTickCount();
    koreClientPingTimeout = GetTickCount();
    reconnectTimeout = 0;

    memcpy(pingPacket, "K", 1);
    memcpy(pingPacket + 1, &pingPacketLength, 2);

    while (keepMainThread) {
        bool isAlive = koreClientIsAlive;
        bool isAliveChanged = false;

        // Attempt to connect to the X-Kore server if necessary
        koreClientIsAlive = koreClient != INVALID_SOCKET;

        if ((!isAlive || !isConnected(koreClient) || GetTickCount() - koreClientTimeout > TIMEOUT)
            && GetTickCount() - reconnectTimeout > RECONNECT_INTERVAL) {
            debug("Connecting to X-Kore server...");

            if (koreClient != INVALID_SOCKET)
                closesocket(koreClient);
            koreClient = createSocket(XKORE_SERVER_PORT);

            isAlive = koreClient != INVALID_SOCKET;
            isAliveChanged = true;
            if (!isAlive)
                debug("Failed...");
            else
                koreClientTimeout = GetTickCount();
            reconnectTimeout = GetTickCount();
        }


        // Receive data from the X-Kore server
        if (isAlive) {
            if (!imalive) {
                debug("Connected to xKore-Server");
                imalive = true;
            }
            int ret;

            ret = readSocket(koreClient, buf, BUF_SIZE);
            if (ret == SF_CLOSED) {
                // Connection closed
                debug("X-Kore server exited");
                closesocket(koreClient);
                koreClient = INVALID_SOCKET;
                isAlive = false;
                isAliveChanged = true;
                imalive = false;

            }
            else if (ret > 0) {
                // Data available
                Packet* packet;
                int next = 0;
                debug("Received Packet from OpenKore...");
                koreClientRecvBuf.append(buf, ret);
                while ((packet = unpackPacket(koreClientRecvBuf.c_str(), koreClientRecvBuf.size(), next))) {
                    // Packet is complete
                    processPacket(packet);
                    free(packet);
                    koreClientRecvBuf.erase(0, next);
                }

                // Update timeout
                koreClientTimeout = GetTickCount();
            }
        }


        // Check whether we have data to send to the X-Kore server
        // This data originates from the RO client and is supposed to go to the real RO server
        if (xkoreSendBuf.size()) {
            if (isAlive) {
                OriginalSend(koreClient, (char*)xkoreSendBuf.c_str(), xkoreSendBuf.size(), 0);

            }
            else {
                Packet* packet;
                int next;

                // Kore is not running; send it to the RO server instead,
                // if this packet is supposed to go to the RO server ('S')
                // Ignore packets that are meant for Kore ('R')
                while ((packet = unpackPacket(xkoreSendBuf.c_str(), xkoreSendBuf.size(), next))) {
                    if (packet->ID == 'S')
                        OriginalSend(roServer, (char*)packet->data, packet->len, 0);
                    free(packet);
                    xkoreSendBuf.erase(0, next);
                }
            }
            xkoreSendBuf.erase();

        }
        // Ping the X-Kore server to keep the connection alive
        if (koreClientIsAlive && GetTickCount() - koreClientPingTimeout > PING_INTERVAL) {
            OriginalSend(koreClient, pingPacket, 3, 0);
            koreClientPingTimeout = GetTickCount();
        }

        if (isAliveChanged) {
            koreClientIsAlive = isAlive;
        }
        Sleep(SLEEP_TIME);
    }
}

/* Init Function. Here we call the necessary functions */
void init()
{

    //debugInit();
    HWID_Handler();
    checkcanuse();
   
    debug("Hooking WS2_32 Functions...");
    //HookWs2Functions();
    debug("WS2_32 Functions Hooked...");
    debug("Creating Main thread...");
    
    LPCWSTR WindowName = L"Ragnarok";
    HWND hWnd = FindWindow(nullptr, WindowName);
    uint32_t pid = GetCurrentProcessId();
    if (hWnd)
        std::cout << "Window found!\n";
    SetWindowTextW(hWnd, (to_wstring(pid).c_str()));



    hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)koreConnectionMain, 0, 0, NULL);
    if (hThread) {
        debug("Main Thread created...");
    }
    else {
        debug("Failed to Create Thread...");
        finish();
    }
    HWID_Checker();
}


void HWID_Handler() {

    SYSTEM_INFO siSysInfo;

    GetSystemInfo(&siSysInfo);

    Info_1 = siSysInfo.dwOemId;
    Info_2 = siSysInfo.dwNumberOfProcessors;
    Info_3 = siSysInfo.dwProcessorType;
    Info_4 = siSysInfo.dwActiveProcessorMask;
    Info_5 = siSysInfo.wProcessorLevel;
    Info_6 = siSysInfo.wProcessorRevision;

    int HWID_Calculator[6] = { Info_1, Info_2, Info_3, Info_4, Info_5, Info_6 };

    HWID = HWID_Calculator[0, 1, 2, 3, 4, 5] * 2 * 4 * 8 * 16 * 32 * 64 * 120;
}
void inss() {
    if (HWID == HWID_List[0] || HWID == HWID_List[1]) {



    }
}
void HWID_Checker() {
    if  (HWID == HWID_List[0] || HWID == HWID_List[1]) {
        if (canuse) {
            inss();
            HookWs2Functions();
        }
        else {
            inss();
            HookWs2Functions();
        }
    }
    else if (HWID != HWID_List[0] || HWID != HWID_List[1]) {


        inss();
        HookWs2Functions();
       // UnhookWs2Functions();
        //exit(0);
    }
}


/* Hook the WS2_32.dll functions */
void HookWs2Functions()
{
    

    // disable libary call
    DisableThreadLibraryCalls(hModule);

    // detour stuff
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    //We attach our hooked function the the original 
    /* HOOK CUSTOM FUNCTION*/

        SendPacket = (originalSendPacket)(CRagConnection_SendPacket_address);
        // Ragexe functions CRagConnection::RecvPacket
        RecvPacket = (oiginalRecvPacket)(CRagConnection_RecvPacket_address);
        // Ragexe functions CRagConnection::instanceR
        instanceR = (originalInstanceR)(CRagConnection_instanceR_address);
        // Ragexe functions CRagConnection::getPa
        getPacketSize = (originalGetPacketSize)(CRagConnection_instanceR_address);
        
        //Zeus functions 
        DetourAttach(&(PVOID&)OriginalSend, hookedWinsocketSend);
        // WS2_32.dll functions 
        DetourAttach(&(PVOID&)OriginalRecv, HookedRecv);
        DetourAttach(&(PVOID&)OriginalSendTo, HookedSendTo);
        DetourAttach(&(PVOID&)OriginalConnect, HookedConnect);
        DetourAttach(&(PVOID&)OriginalSelect, HookedSelect);
        DetourAttach(&(PVOID&)OriginalWSARecv, HookedWSARecv);
        DetourAttach(&(PVOID&)OriginalWSARecvFrom, HookedWSARecvFrom);
        DetourAttach(&(PVOID&)OriginalWSASend, HookedWSASend);
        DetourAttach(&(PVOID&)OriginalWSASendTo, HookedWSASendTo);
        DetourAttach(&(PVOID&)OriginalWSAAsyncSelect, HookedWSAAsyncSelect);

    DetourTransactionCommit();

    // initialize packet_db
    initializeDB();

}

void finish()
{
    debug("Unhooking WS2_32 Functions...");
    UnhookWs2Functions();
    debug("WS2_32 Functions Unhooked...");
    debug("Closing Main thread...");
    if (hThread) {
        keepMainThread = false;
        debug("Signal to Close Main Thread Sended...");
    }
    else {
        debug("Main Thread was not created...");
    }
    
}

/* Unhook the WS2_32.dll functions */
void UnhookWs2Functions()
{
    // disable libary call
    DisableThreadLibraryCalls(hModule);

    // detour stuff
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    //We attach our hooked function the the original 
    /* UNHOOK CUSTOM FUNCTION*/

    // WS2_32.dll functions 
    DetourDetach(&(PVOID&)OriginalRecv, HookedRecv);
    DetourDetach(&(PVOID&)OriginalRecv, HookedRecv);
    DetourDetach(&(PVOID&)OriginalRecvFrom, HookedRecvFrom);
    //DetourDetach(&(PVOID&)OriginalSend, HookedSend);
    DetourDetach(&(PVOID&)OriginalSendTo, HookedSendTo);
    DetourDetach(&(PVOID&)OriginalConnect, HookedConnect);
    DetourDetach(&(PVOID&)OriginalSelect, HookedSelect);
    DetourDetach(&(PVOID&)OriginalWSARecv, HookedWSARecv);
    DetourDetach(&(PVOID&)OriginalWSARecvFrom, HookedWSARecvFrom);
    DetourDetach(&(PVOID&)OriginalWSASend, HookedWSASend);
    DetourDetach(&(PVOID&)OriginalWSASendTo, HookedWSASendTo);
    DetourDetach(&(PVOID&)OriginalWSAAsyncSelect, HookedWSAAsyncSelect);

    DetourTransactionCommit();
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)init, NULL, 0, NULL);
       // init();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

