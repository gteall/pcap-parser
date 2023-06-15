#if 0
#include <winsock.h>
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#include <memory>
#include "pcap_parser.h"

#define DEBUG  0

using namespace std;

string StreamId::getStrId()
{
    string strId;
    struct in_addr addr;
    char tmpSrc[8] = {0};
    char tmpDest[8] = {0};
    UInt tmpIp = 0;
    
    snprintf(tmpSrc, sizeof(tmpSrc), "%d", mSrcPort);
    snprintf(tmpDest, sizeof(tmpDest), "%d", mDestPort);
    
    tmpIp = htonl(mSrcIp);
    memcpy(&addr, &tmpIp, sizeof(tmpIp));
    strId.append(inet_ntoa(addr)).append("-").append(tmpSrc).append("_to_");
    
    tmpIp = htonl(mDestIp);
    memcpy(&addr, &tmpIp, sizeof(tmpIp));
    strId.append(inet_ntoa(addr)).append("-").append(tmpDest);
    return strId;
}

FramePkt::FramePkt(const char *data, UInt len, UInt index, UInt linkType) : mFrameIndex(index)
{
    int  ret = 0;
    UInt headerLen = 0;
    
    ret = parseEthPktHeader(data, len, headerLen, linkType);
    /*
    *   mFrameType   0x0800    ip
    *                0x8864    pppoe session
    *                0x0806    ARP
    *                0x86dd    ipv6
					 0x8100    802.1q
    *                0xfffa    unknown (broadcast ?)
    */
    if(ret != RET_OK || (mFrameType != 0x800 && mFrameType != 0x8864 && mFrameType != 0x8100))
    {
        if(0x0806 == mFrameType || 0xfffa == mFrameType || 0x86dd == mFrameType)
        {
            return;
        }

        cout << "not ip pkt, type = " << hex << mFrameType << dec << ", index = " << index << endl;
        return;
    }

    data += headerLen;
    len  -= headerLen;

    if(mFrameType == 0x8864)
    {
        ret = parsePPPoEPktHeader(data, len, headerLen);
        if(RET_OK == ret)
        {
            if(0x21 == mP2pProtocol)
            {

            }
            else if(0xc021 == mP2pProtocol)
            {
                return;
            }
            else
            {
                cout << "unknown pppoe type = " << hex << mP2pProtocol << dec << endl;
                return;
            }
            
        }
        else
        {
            return;
        }
        
        data += headerLen;
        len  -= headerLen;
    }
	else if(mFrameType == 0x8100)
	{
		/** 跳过802.1q的4个字节包头 */
		data += 4;
        len  -= 4;
	}

    ret = parseIpPktHeader(data, len, headerLen);
    /*
    *   mIpProtocol 17  udp
    *               2   igmp 
    *               6   tcp
    */
    if(ret != RET_OK || mIpProtocol != 17) //not udp
    {
        if(2 == mIpProtocol || 6 == mIpProtocol)
        {
            return;
        }
        else
        {
            cout << "parse ip header failed, index = " << index << endl;
        }
        return;
    }

    data += headerLen;
    len  -= headerLen;
    ret = parseUdpPktHeader(data, len, headerLen);
    if(ret != RET_OK)
    {
        #if DEBUG
        cout << "parse udp header failed" << endl;
        #endif
        return;
    }
    
    data += headerLen;
    len  -= headerLen;
    ret = parseRtpPktHeader(data, len, headerLen);
    if(ret != RET_OK)
    {
        #if DEBUG
        cout << "parse rtp header failed" << endl;
        #endif
        return;
    }

    data += headerLen;
    len  -= headerLen;
    ret = parseTsData(data, len);
    if(ret == RET_OK && len > 0)
    {
        mTsData.clear();
        mTsData.reserve(2048);
        for (size_t i = 0; i < len; i++)
        {
            mTsData.push_back(data[i]);
        }
        
        mRtpTsFlag = true;
    }
}


int FramePkt::writeToFile(ofstream &of)
{
    if(of)
    {
        of.write(&mTsData[0], mTsData.size());
    }
    return 0;
}

int FramePkt::parseEthPktHeader(const char *pBuf, UInt bufLen, UInt &headerLen, UInt linkType)
{
    UInt EthPktHeaderLen = 0;
    UShort usFrameType = 0;

    if(linkType == 113)
    {
        EthPktHeaderLen = 16;
    }
    else
    {
        EthPktHeaderLen = 14;
    }
    
    if(NULL == pBuf || bufLen < EthPktHeaderLen)
    {
        //cout << "parse EthPkt Header error" << endl;
        headerLen = 0;
        return RET_ERR;
    }
    headerLen = EthPktHeaderLen;
    
    /** skip dest and src mac, not parse */
    pBuf += (EthPktHeaderLen - 2);

    memcpy((void *)&usFrameType, pBuf, 2);
    mFrameType = ntohs(usFrameType);
    return RET_OK;
}

int FramePkt::parsePPPoEPktHeader(const char *pBuf, UInt bufLen, UInt &headerLen)
{
    const UInt PPPoEPktHeaderLen = 8;
    UShort usPPPoEType = 0;

    if(nullptr == pBuf || bufLen <= PPPoEPktHeaderLen)
    {
        return RET_ERR;
    }

    pBuf += (PPPoEPktHeaderLen - 2);
    memcpy((void *)&usPPPoEType, pBuf, 2);
    mP2pProtocol = ntohs(usPPPoEType);
    headerLen = PPPoEPktHeaderLen;
    return RET_OK;
}

int FramePkt::parseIpPktHeader(const char *pBuf, UInt bufLen, UInt &headerLen)
{
    const char *tmpBuf = pBuf;
    
    if(nullptr == tmpBuf)
    {
        cout << "parseIpPkt pBuf is null" << endl;
        return RET_ERR;
    }
    
    headerLen = (tmpBuf[0] & 0xf) * 4;
    if(bufLen < headerLen)
    {
        cout << "ip pkt header len error" << endl;
        headerLen = 0;
        return RET_ERR;
    }

    mIpProtocol = tmpBuf[9];
    
    UInt srcIp  = 0;
    UInt destIp = 0;
    
    tmpBuf += 12;
    memcpy(&srcIp, tmpBuf, 4);
    mId.setSrcIp(ntohl(srcIp));

    tmpBuf += 4;
    memcpy(&destIp, tmpBuf, 4);
    mId.setDestIp(ntohl(destIp));
    
    //cout << hex << "src ip:0x" << srcIp << endl;
    //cout << "dest ip:0x" << destIp << dec << endl;
    return RET_OK;
}

int FramePkt::parseUdpPktHeader(const char *pBuf, UInt bufLen, UInt &headerLen)
{
    UInt UdpPktHeaderLen = 8;
    const char *tmpBuf = pBuf;
    
    if(NULL == tmpBuf || bufLen < UdpPktHeaderLen)
    {
        cout << "parseUdpPkt pBuf error" << endl;
        return RET_ERR;
    }
    headerLen = UdpPktHeaderLen;
    
    UShort srcPort = 0;
    UShort destPort = 0;
    
    memcpy(&srcPort, tmpBuf, 2);
    mId.setSrcPort(ntohs(srcPort));

    tmpBuf += 2;
    memcpy(&destPort, tmpBuf, 2);
    mId.setDestPort(ntohs(destPort));
    
    //cout << "src port:" << srcPort << endl;
    //cout << "dest port:" << destPort << endl;
    return RET_OK;
}

int FramePkt::parseRtpPktHeader(const char *pBuf, UInt bufLen, UInt &headerLen)
{
    UInt rtpHeaderLen = 0;
    const char *tmpBuf = pBuf;

    if(NULL == tmpBuf || 0 == bufLen)
    {
        return RET_ERR;
    }
    
    UInt rtpVer = (tmpBuf[0] >> 6) & 0x3;
    if(rtpVer != 2)
    {
        //cout << "rtp ver err : " << rtpVer << endl;
        return RET_ERR;
    }
    
    bool rtpExtensionFlag = tmpBuf[0] & 0x10 ? true : false;
    UInt csrc = tmpBuf[0] & 0xf;
    
    
    /** 固定头 */
    rtpHeaderLen = 12 + csrc * 4;
    if(bufLen <= rtpHeaderLen)
    {
        //cout << "parseRtpTs failed " << bufLen << " headLen " << headLen << endl;
        return RET_ERR;
    }
    
    UShort seq = 0;
    memcpy((void *)&seq, &tmpBuf[2], 2);
    mRtpSeq = ntohs(seq);
    tmpBuf += rtpHeaderLen;
    
    /** 扩展头 */
    if(rtpExtensionFlag)
    {
        UShort extensionCnt = 0;
        memcpy((void *)&extensionCnt, &tmpBuf[2], 2);
        extensionCnt = ntohs(extensionCnt);
        //cout << "extensionCnt = " << extensionCnt << endl;
        rtpHeaderLen += 4;
        rtpHeaderLen += extensionCnt * 4;

        if(bufLen <= rtpHeaderLen)
        {
            return RET_ERR;
        }
    }
    
    headerLen = rtpHeaderLen;
    return RET_OK;
}

int FramePkt::parseTsData(const char *pBuf, UInt bufLen)
{
    const char *tmpBuf = pBuf;

    if(NULL == tmpBuf || bufLen < TS_PKT_SIZE)
    {
        return RET_ERR;
    }

    for(;bufLen >= 188; bufLen -= 188, tmpBuf += 188)
    {
        if(tmpBuf[0] != 0x47)
        {
            //cout << "0x47 error" << endl;
            return RET_ERR;
        }
        //tsCnt++;
    }
    return RET_OK;
}

int RtpPktManager::RtpPktStream::addRtpPkt(shared_ptr<FramePkt> pkt)
{
    if(pktVector.size() == 0)
    {
        mId = pkt->getStreamId();
    }
    else
    {
        if(pkt->getStreamId() != mId)
        {
            return RET_ERR;
        }
    }
    
    pktVector.push_back(pkt);
    return RET_OK;
}

void RtpPktManager::RtpPktStream::printfStreamInfo()
{
    vector<FramePkt *> tmpVector;
    UShort expectedSeq = 0;
    UShort curSeq = 0;
    UShort lastSeq = 0;
    UInt pktLossCnt  = 0;
    UInt pktErrorCnt = 0;
    
    ofstream tsfile(mId.getStrId().append(".ts").c_str(), ofstream::binary);
    ofstream infofile(mId.getStrId().append(".txt").c_str());

    if(tsfile)
    {
        cout << mId.getStrId().append(".ts") << " create success" << endl;
    }
    else 
    {
        cout << mId.getStrId().append(".ts") << " create failed" << endl;
    }

    if(infofile)
    {
        cout << mId.getStrId().append(".txt") << " create success" << endl;
    }
    else 
    {
        cout << mId.getStrId().append(".txt") << " create failed" << endl;
    }
    
    
    shared_ptr<FramePkt> lastPkt = NULL;

    for (auto pkt : pktVector)
    {
        if(nullptr != lastPkt)
        {
            lastSeq = lastPkt->getRtpSeq();
            curSeq  = pkt->getRtpSeq();
            expectedSeq = lastSeq < 0xffff ? lastSeq + 1 : 0;
            
            if(curSeq != expectedSeq)
            {
                UInt curLoss = 0;
                if(curSeq > expectedSeq)
                {
                    curLoss = curSeq - expectedSeq;
                }
                else
                {
                    curLoss = 0xffff - (expectedSeq - curSeq);
                }

                /** 200个以内的包认为是重复包 */
                if(curLoss > (0xffff - 200))
                {
                    continue;
                }

                pktLossCnt += curLoss;
                pktErrorCnt++;
                infofile << "pkt loss : " << "cur seq " << curSeq << ", index " <<  pkt->getFrameIndex() << " --"
                                          << "last seq "<< lastSeq << ", index " << lastPkt->getFrameIndex() << " -- "
                                          << "loss pkt cnt " << curLoss << endl;
            }
        }
        pkt->writeToFile(tsfile);
        lastPkt = pkt;
    }

    cout << "stream " << mId.getStrId() << " info:" << endl;
    cout << "pkt total = " << pktVector.size() << " loss = " << pktLossCnt
         << " err = " << pktErrorCnt << " packet loss probability " 
         << ((double)pktLossCnt/(double)pktVector.size()) * 100 << "%" << '\n' << endl;
         
    infofile << "pkt total = " << pktVector.size() << " loss = " << pktLossCnt
             << " err = " << pktErrorCnt << " packet loss probability "
             << ((double)pktLossCnt/(double)pktVector.size()) * 100 << "%" << endl;
    
    tsfile.close();
    infofile.close();
}

void RtpPktManager::addRtpPkt(shared_ptr<FramePkt> pkt)
{
    int ret = RET_ERR;

    if(nullptr == pkt)
    {
        return;
    }

    if(!pkt->isRtpTsPkt())
    {
        return;
    }

    /** 遍历已有的stream并add pkt */
    for(auto stream : streamVector)
    {
        ret = stream->addRtpPkt(pkt);
        if(RET_OK == ret)
        {
            break;
        }
    }

    /** pkt不属于已有的stream,创建stream并add pkt */
    if(RET_ERR == ret)
    {
        shared_ptr<RtpPktStream> spRtpPktStream(new RtpPktStream());
        ret = spRtpPktStream->addRtpPkt(pkt);
        if(RET_OK == ret)
        {
            streamVector.push_back(spRtpPktStream);
        }
    }
}

void RtpPktManager::printInfo()
{
    for (auto stream : streamVector)
    {
        stream->printfStreamInfo();
    }
}

int main(int argc, char *argv[])
{
    RtpPktManager   rtpPktManager;
    PcapFileHeader  fileHeader;
    PcapPktHeader   pktHeader;
    UInt            pcapSeq = 1;

    //shared_ptr<char> spcBuf(new char[65535], [](char *p){delete[] p; cout << "free sp" << endl;});

    if(argc != 2)
    {
        cerr << "usage: ./xxx  xxx.pcap" << endl;
        return RET_ERR;
    }
    
    string filename(argv[1]);
    #if 0
    if(filename.find_last_not_of(".pcap"))
    {
        cerr << "input file must pcap format, err:" << filename << endl;
        return RET_ERR;
    }
    #endif
    
    ifstream inStream(filename.c_str(), ifstream::binary);
    if(!inStream)
    {
        std::cerr << "open file failed " << argv[1] << endl;
        return -1;
    }
    
    memset(&fileHeader, 0, sizeof(fileHeader));
    inStream.read((char *)&fileHeader, sizeof(fileHeader));
    if(!inStream)
    {
        std::cerr << "read failed" << endl;
        return RET_ERR;
    }

    std::cout << "Read file header successfully." << endl;
    std::cout << hex << "0x" << fileHeader.magic << dec << '\n'
                //<< fileHeader.versionMajor << '\n'
                //<< fileHeader.versionMinor << '\n'
                //<< fileHeader.timeZone << '\n'
                //<< fileHeader.timeStamp << '\n'
                << fileHeader.pktMaxLen << '\n'
                << "linkLayerType " << fileHeader.linkLayerType << '\n' << endl;
    
    if(fileHeader.magic != 0xa1b2c3d4)
    {
        cerr << "file format error" << endl;
        return RET_ERR;
    }

    shared_ptr<char> spcBuf(new char[65535], [](char *p){delete[] p; cout << "free sp" << endl;});

    while(inStream)
    {
        inStream.read((char *)&pktHeader, sizeof(pktHeader));
        if(inStream)
        {
        #if DEBUG
            std::cout << "pkt header" << endl;
            std::cout << pktHeader.secTime << '\n'
                        << pktHeader.microTime << '\n'
                        << pktHeader.capLen << '\n'
                        << pktHeader.actualLen << endl;
        #endif
        }
        else
        {
            break;
        }
        
        inStream.read(spcBuf.get(), pktHeader.capLen);
        if(inStream)
        {
            shared_ptr<FramePkt> spPkt(new FramePkt(spcBuf.get(), pktHeader.capLen, pcapSeq++, fileHeader.linkLayerType));
            #if DEBUG
            cout << "rtp seq : " << spPkt->getRtpSeq() << endl;
            #endif
            rtpPktManager.addRtpPkt(spPkt);
        }
        
    }

    rtpPktManager.printInfo();
    return 0;
}
