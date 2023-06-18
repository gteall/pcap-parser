#ifndef __PARSE_PCAP_H__
#define __PARSE_PCAP_H__

#include <string.h>

#include <fstream>
#include <iostream>
#include <vector>

#define RET_OK 0
#define RET_ERR (-1)
#define TS_PKT_SIZE 188

typedef unsigned int UInt;
typedef unsigned short UShort;
typedef unsigned char UChar;

struct PcapFileHeader
{
    UInt magic;
    UShort versionMajor;
    UShort versionMinor;
    UInt timeZone;
    UInt timeStamp;
    UInt pktMaxLen;
    UInt linkLayerType;
};

struct PcapPktHeader
{
    UInt secTime;
    UInt microTime;
    UInt
        capLen; /** 抓包获取到的长度,如果抓包时限制了单个包的大小会小于actualLen
                 */
    UInt actualLen;
};

/** 使用source IP PORT和dest IP PORT区分抓包中不同的流 */
class StreamId
{
public:
    bool operator==(StreamId &id)
    {
        if ((mSrcIp == id.getSrcIp()) && (mDestIp == id.getDestIp()) &&
            (mSrcPort == id.getSrcPort()) && (mDestPort == id.getDestPort()))
        {
            return true;
        }
        return false;
    }

    bool operator!=(StreamId &id)
    {
        if ((mSrcIp == id.getSrcIp()) && (mDestIp == id.getDestIp()) &&
            (mSrcPort == id.getSrcPort()) && (mDestPort == id.getDestPort()))
        {
            return false;
        }
        return true;
    }

    void setSrcIp(UInt ip) { mSrcIp = ip; }

    void setDestIp(UInt ip) { mDestIp = ip; }

    void setSrcPort(UShort port) { mSrcPort = port; }

    void setDestPort(UShort port) { mDestPort = port; }

    UInt getSrcIp() { return mSrcIp; }

    UInt getDestIp() { return mDestIp; }

    UShort getSrcPort() { return mSrcPort; }

    UShort getDestPort() { return mDestPort; }

    std::string getStrId();

private:
    UInt mSrcIp = 0;
    UInt mDestIp = 0;
    UShort mSrcPort = 0;
    UShort mDestPort = 0;
};

class FramePkt
{
public:
    FramePkt(const char *data, UInt len, UInt index, UInt linkType);

    bool isRtpTsPkt() { return mRtpTsFlag; }

    UShort getRtpSeq() { return mRtpSeq; }

    UInt getFrameIndex() { return mFrameIndex; }

    StreamId getStreamId() { return mId; }

    int writeToFile(std::ofstream &of);

private:
    int parseEthPktHeader(const char *pBuf, UInt bufLen, UInt &headerLen,
                          UInt linkType);
    int parsePPPoEPktHeader(const char *pBuf, UInt bufLen, UInt &headerLen);
    int parseIpPktHeader(const char *pBuf, UInt bufLen, UInt &headerLen);
    int parseUdpPktHeader(const char *pBuf, UInt bufLen, UInt &headerLen);
    int parseRtpPktHeader(const char *pBuf, UInt bufLen, UInt &headerLen);

    int parseTsData(const char *pBuf, UInt bufLen);

    UInt mFrameIndex = 0;
    UShort mFrameType = 0; /** ip or other */
    UShort mP2pProtocol = 0;
    UChar mIpProtocol = 0; /** udp or tcp */
    StreamId mId;
    UShort mRtpSeq = 0;
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
