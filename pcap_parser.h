#ifndef __PARSE_PCAP_H__
#define __PARSE_PCAP_H__

#include <stdint.h>

#include <fstream>
#include <iostream>
#include <memory>
#include <vector>

#define RET_OK 0
#define RET_ERR (-1)
#define TS_PKT_SIZE 188

struct PcapFileHeader
{
    uint32_t magic;
    uint16_t versionMajor;
    uint16_t versionMinor;
    uint32_t timeZone;
    uint32_t timeStamp;
    uint32_t pktMaxLen;
    uint32_t linkLayerType;
};

struct PcapPktHeader
{
    uint32_t secTime;
    uint32_t microTime;
    uint32_t capLen; /** 抓包获取到的长度,如果抓包时限制了单个包的大小会小于actualLen */
    uint32_t actualLen;
};

/** 使用source IP PORT和dest IP PORT区分抓包中不同的流 */
class StreamId
{
public:
    bool operator==(StreamId &id)
    {
        if ((mSrcIp == id.getSrcIp()) && (mDestIp == id.getDestIp()) && (mSrcPort == id.getSrcPort()) &&
            (mDestPort == id.getDestPort()))
        {
            return true;
        }
        return false;
    }

    bool operator!=(StreamId &id)
    {
        if ((mSrcIp == id.getSrcIp()) && (mDestIp == id.getDestIp()) && (mSrcPort == id.getSrcPort()) &&
            (mDestPort == id.getDestPort()))
        {
            return false;
        }
        return true;
    }

    void setSrcIp(uint32_t ip) { mSrcIp = ip; }

    void setDestIp(uint32_t ip) { mDestIp = ip; }

    void setSrcPort(uint16_t port) { mSrcPort = port; }

    void setDestPort(uint16_t port) { mDestPort = port; }

    uint32_t getSrcIp() { return mSrcIp; }

    uint32_t getDestIp() { return mDestIp; }

    uint16_t getSrcPort() { return mSrcPort; }

    uint16_t getDestPort() { return mDestPort; }

    std::string getStrId();

private:
    uint32_t mSrcIp = 0;
    uint32_t mDestIp = 0;
    uint16_t mSrcPort = 0;
    uint16_t mDestPort = 0;
};

class FramePkt
{
public:
    FramePkt(const char *data, uint32_t len, uint32_t index, uint32_t linkType);

    bool isRtpTsPkt() { return mRtpTsFlag; }

    uint16_t getRtpSeq() { return mRtpSeq; }

    uint32_t getFrameIndex() { return mFrameIndex; }

    StreamId getStreamId() { return mId; }

    int writeToFile(std::ofstream &of);

private:
    int parseEthPktHeader(const char *pBuf, uint32_t bufLen, uint32_t &headerLen, uint32_t linkType);
    int parsePPPoEPktHeader(const char *pBuf, uint32_t bufLen, uint32_t &headerLen);
    int parseIpPktHeader(const char *pBuf, uint32_t bufLen, uint32_t &headerLen);
    int parseUdpPktHeader(const char *pBuf, uint32_t bufLen, uint32_t &headerLen);
    int parseRtpPktHeader(const char *pBuf, uint32_t bufLen, uint32_t &headerLen);

    int parseTsData(const char *pBuf, uint32_t bufLen);

    uint32_t mFrameIndex = 0;
    uint16_t mFrameType = 0; /** ip or other */
    uint16_t mP2pProtocol = 0;
    uint8_t mIpProtocol = 0; /** udp or tcp */
    StreamId mId;
    uint16_t mRtpSeq = 0;
    bool mRtpTsFlag = false;
    std::vector<char> mTsData;
};

class RtpPktManager
{
public:
    class RtpPktStream
    {
    public:
        int addRtpPkt(std::shared_ptr<FramePkt> pkt);
        void sort_pkt();
        void printfStreamInfo();

    private:
        StreamId mId;
        std::vector<std::shared_ptr<FramePkt>> pktVector;
    };

    void addRtpPkt(std::shared_ptr<FramePkt> pkt);
    void printInfo();

private:
    std::vector<std::shared_ptr<RtpPktStream>> streamVector;
};

#endif
