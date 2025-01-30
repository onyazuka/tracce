#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <memory.h>
#include <unistd.h>
#include <cassert>
#include <format>
#include <thread>
#include <chrono>
#include <regex>

using namespace std;

void makeIpHeader() {
    struct iphdr headerIp;
    int id = 0;
    memset(&headerIp, 0, sizeof(headerIp));
    headerIp.version = 4;
    headerIp.ihl = 5;
    headerIp.tos = 0;
    // total length filled manually
    headerIp.id = id++;
    headerIp.ttl = 20;
    headerIp.protocol = IPPROTO_ICMP;
}

uint16_t checksumInet(uint8_t* data, size_t sz) {
    assert(sz % 2 == 0);
    uint32_t sum = 0;
    for (size_t i = 0; i < sz; i += 2) {
        sum += *(uint16_t*)(data + i);
    }
    uint8_t carry  = (sum & 0xff0000) >> 16;
    uint16_t res = ~((sum & 0xffff) + carry);
    return res;
}

void testChecksumInet() {
    uint16_t data[] = {0x4500, 0x0073, 0x0000, 0x4000, 0x4011, 0xc0a8, 0x0001, 0xc0a8, 0x00c7};
    uint16_t checksum = checksumInet((uint8_t*)&data, sizeof(data));
    assert(checksum == 0xb861);
}

void tests(){
    testChecksumInet();
}

std::string ipHexToStr(uint32_t ip) {
    return std::format("{}.{}.{}.{}", (ip & 0xff000000) >> 24, (ip & 0x00ff0000) >> 16, (ip & 0x0000ff00) >> 8, (ip & 0x000000ff) >> 0);
}

bool isIp(std::string_view s) {
    static regex ipv4("(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])");
    return regex_match(s.data(), ipv4);
}

auto getTsMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count();
}

int main(int argc, char* argv[])
{
    tests();
    if (argc != 2) {
        cout << "Usage: tracce [ip|hostname]\n";
        exit(EXIT_SUCCESS);
    }

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    int sockRecv = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockRecv < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    int opt = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) == -1) {
        perror("setsockopt");
        close(sock);
        close(sockRecv);
        exit(EXIT_FAILURE);
    }
    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;

    if (setsockopt (sockRecv, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) < 0) {
        perror("setsockopt timeout");
        close(sock);
        close(sockRecv);
        exit(EXIT_FAILURE);
    }
    iphdr* headerIp = 0;
    icmphdr* headerIcmp = 0;
    sockaddr_in dest;
    //string srcIp = "192.168.100.5";
    //string dstIp = "74.125.146.96";
    string dstIp = argv[1];
    // hostname case
    if (!isIp(dstIp)) {
        struct addrinfo* res = NULL;
        if (getaddrinfo(dstIp.c_str(), "443", 0, &res) < 0) {
            perror("couldn't get hostname");
            close(sock);
            close(sockRecv);
            exit(EXIT_FAILURE);
        }
        while(!(res->ai_addr->sa_family == AF_INET) && res->ai_next) {
            res = res->ai_next;
        }
        struct sockaddr_in *p = (struct sockaddr_in *)res->ai_addr;
        dstIp = inet_ntoa(p->sin_addr);
    }
    char outputBuf[1024];
    int id = 0;
    int ttl = 1;
    while (true) {
        headerIp = (iphdr*)(outputBuf);
        headerIcmp = (icmphdr*)(outputBuf + sizeof(iphdr));
        memset((void*)headerIp, 0, sizeof(iphdr));
        headerIp->version = 4;
        headerIp->ihl = 5;
        headerIp->tos = 0;
        // total length filled manually
        headerIp->tot_len = sizeof(iphdr) + sizeof(icmphdr);
        headerIp->id = id++;
        headerIp->ttl = ttl++;
        headerIp->protocol = IPPROTO_ICMP;
        //headerIp->saddr = inet_addr(srcIp.c_str());
        headerIp->daddr = inet_addr(dstIp.c_str());
        memset((void*)headerIcmp, 0, sizeof(headerIcmp));
        headerIcmp->type = ICMP_ECHO;
        headerIcmp->un.echo.sequence = id++;
        headerIcmp->checksum = checksumInet((uint8_t*)headerIcmp, sizeof(icmphdr));
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = inet_addr(dstIp.c_str());
        socklen_t sz = sizeof(dest);

        int nbytes = 0;
        auto before = getTsMs();
        if (nbytes = sendto(sock, outputBuf, headerIp->tot_len, 0, (sockaddr*)&dest, sizeof(dest)); nbytes < 0) {
            perror("icmp send failed");
            close(sock);
            close(sockRecv);
            exit(EXIT_FAILURE);
        }

        uint8_t inputBuf[1024];
        memset(inputBuf, 0, sizeof(inputBuf));
        if (nbytes = recvfrom(sockRecv, inputBuf, sizeof(inputBuf), 0, (sockaddr*)&dest, &sz); nbytes < 0) {
            if (errno == EAGAIN) {
                cout << format("No response (TTL = {})\n", ttl - 1);
                cout.flush();
                continue;
            }
            perror("icmp recv failed");
            close(sock);
            close(sockRecv);
            exit(EXIT_FAILURE);
        }
        auto after = getTsMs();

        size_t ipsz = sizeof(iphdr);
        size_t icmpsz = sizeof(icmphdr);
        iphdr headerIpO = *(iphdr*)(inputBuf);
        icmphdr headerIcmpO = *(icmphdr*)(&inputBuf[0] + sizeof(iphdr));

        if (headerIcmpO.type == ICMP_TIMXCEED) {
            cout << format("TTL exceeded from {0} (TTL = {1}) (time = {2}ms)\n", ipHexToStr(ntohl(headerIpO.saddr)), ttl - 1, after - before);
        }
        if (headerIcmpO.type == ICMP_ECHOREPLY) {
            cout << format("Reply from {0} (TTL = {1})) (time = {2}ms)\n", ipHexToStr(ntohl(headerIpO.saddr)), ttl - 1, after - before);
            break;
        }
        cout.flush();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    close(sock);
    close(sockRecv);

    return 0;
}
