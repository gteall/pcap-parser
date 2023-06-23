#include <_types/_uint32_t.h>
#if 0
#include <winsock.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif
#include <string.h>

#include "pcap_parser.h"

using namespace std;

string StreamId::getStrId()
{
    string strId;
    struct in_addr addr;
    char tmpSrc[8] = {0};
    char tmpDest[8] = {0};
    uint32_t tmpIp = 0;

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

FramePkt::FramePkt(const char *data, uint32_t len, uint32_t index, uint32_t linkType) : mFrameIndex(index)
{
    int ret = 0;
    uint32_t headerLen = 0;

    ret = parseEthPktHeader(data, len, headerLen, linkType);
    /*
    *   mFrameType   0x0800    ip
    *                0x8864    pppoe session
    *                0x0806    ARP
    *                0x86dd    ipv6
                                         0x8100    802.1q
    *                0xfffa    unknown (broadcast ?)
    */
    if (ret != RET_OK || (mFrameType != 0x800 && mFrameType != 0x8864 && mFrameType != 0x8100))
    {
        if (0x0806 == mFrameType || 0xfffa == mFrameType || 0x86dd == mFrameType)
        {
            return;
        }

        cout << "not ip pkt, type = " << hex << mFrameType << dec << ", index = " << index << endl;
        return;
    }

    data += headerLen;
    len -= headerLen;

    if (mFrameType == 0x8864)
    {
        ret = parsePPPoEPktHeader(data, len, headerLen);
        if (RET_OK == ret)
        {
            if (0x21 == mP2pProtocol)
            {
            }
            else if (0xc021 == mP2pProtocol)
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
        len -= headerLen;
    }
    else if (mFrameType == 0x8100)
    {
        /** 跳过802.1q的4个字节包头 */
        data += 4;
        len -= 4;
    }

    ret = parseIpPktHeader(data, len, headerLen);
    /*
     *   mIpProtocol 17  udp
     *               2   igmp
     *               6   tcp
     */
    if (ret != RET_OK || mIpProtocol != 17)  // not udp
    {
        if (2 == mIpProtocol || 6 == mIpProtocol)
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
    len -= headerLen;
    ret = parseUdpPktHeader(data, len, headerLen);
    if (ret != RET_OK)
    {
#if DEBUG
        cout << "parse udp header failed" << endl;
#endif
        return;
    }

    data += headerLen;
    len -= headerLen;
    ret = parseRtpPktHeader(data, len, headerLen);
    if (ret != RET_OK)
    {
#if DEBUG
        cout << "parse rtp header failed" << endl;
#endif
        return;
    }

    data += headerLen;
    len -= headerLen;
    ret = parseTsData(data, len);
    if (ret == RET_OK && len > 0)
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
    if (of)
    {
        of.write(&mTsData[0], mTsData.size());
    }
    return 0;
}

int FramePkt::parseEthPktHeader(const char *pBuf, uint32_t bufLen, uint32_t &headerLen, uint32_t linkType)
{
    uint32_t EthPktHeaderLen = 0;
    uint16_t usFrameType = 0;

    if (linkType == 113)
    {
        EthPktHeaderLen = 16;
    }
    else
    {
        EthPktHeaderLen = 14;
    }

    if (NULL == pBuf || bufLen < EthPktHeaderLen)
    {
        // cout << "parse EthPkt Header error" << endl;
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

int FramePkt::parsePPPoEPktHeader(const char *pBuf, uint32_t bufLen, uint32_t &headerLen)
{
    const uint32_t PPPoEPktHeaderLen = 8;
    uint16_t usPPPoEType = 0;

    if (nullptr == pBuf || bufLen <= PPPoEPktHeaderLen)
    {
        return RET_ERR;
    }

    pBuf += (PPPoEPktHeaderLen - 2);
    memcpy((void *)&usPPPoEType, pBuf, 2);
    mP2pProtocol = ntohs(usPPPoEType);
    headerLen = PPPoEPktHeaderLen;
    return RET_OK;
}

int FramePkt::parseIpPktHeader(const char *pBuf, uint32_t bufLen, uint32_t &headerLen)
{
    const char *tmpBuf = pBuf;

    if (nullptr == tmpBuf)
    {
        cout << "parseIpPkt pBuf is null" << endl;
        return RET_ERR;
    }

    headerLen = (tmpBuf[0] & 0xf) * 4;
    if (bufLen < headerLen)
    {
        cout << "ip pkt header len error" << endl;
        headerLen = 0;
        return RET_ERR;
    }

    mIpProtocol = tmpBuf[9];

    uint32_t srcIp = 0;
    uint32_t destIp = 0;

    tmpBuf += 12;
    memcpy(&srcIp, tmpBuf, 4);
    mId.setSrcIp(ntohl(srcIp));

    tmpBuf += 4;
    memcpy(&destIp, tmpBuf, 4);
    mId.setDestIp(ntohl(destIp));

    // cout << hex << "src ip:0x" << srcIp << endl;
    // cout << "dest ip:0x" << destIp << dec << endl;
    return RET_OK;
}

int FramePkt::parseUdpPktHeader(const char *pBuf, uint32_t bufLen, uint32_t &headerLen)
{
    uint32_t UdpPktHeaderLen = 8;
    const char *tmpBuf = pBuf;

    if (NULL == tmpBuf || bufLen < UdpPktHeaderLen)
    {
        cout << "parseUdpPkt pBuf error" << endl;
        return RET_ERR;
    }
    headerLen = UdpPktHeaderLen;

    uint16_t srcPort = 0;
    uint16_t destPort = 0;

    memcpy(&srcPort, tmpBuf, 2);
    mId.setSrcPort(ntohs(srcPort));

    tmpBuf += 2;
    memcpy(&destPort, tmpBuf, 2);
    mId.setDestPort(ntohs(destPort));

    // cout << "src port:" << srcPort << endl;
    // cout << "dest port:" << destPort << endl;
    return RET_OK;
}

int FramePkt::parseRtpPktHeader(const char *pBuf, uint32_t bufLen, uint32_t &headerLen)
{
    uint32_t rtpHeaderLen = 0;
    const char *tmpBuf = pBuf;

    if (NULL == tmpBuf || 0 == bufLen)
    {
        return RET_ERR;
    }

    uint32_t rtpVer = (tmpBuf[0] >> 6) & 0x3;
    if (rtpVer != 2)
    {
        // cout << "rtp ver err : " << rtpVer << endl;
        return RET_ERR;
    }

    bool rtpExtensionFlag = tmpBuf[0] & 0x10 ? true : false;
    uint32_t csrc = tmpBuf[0] & 0xf;

    /** 固定头 */
    rtpHeaderLen = 12 + csrc * 4;
    if (bufLen <= rtpHeaderLen)
    {
        // cout << "parseRtpTs failed " << bufLen << " headLen " << headLen <<
        // endl;
        return RET_ERR;
    }

    uint16_t seq = 0;
    memcpy((void *)&seq, &tmpBuf[2], 2);
    mRtpSeq = ntohs(seq);
    tmpBuf += rtpHeaderLen;

    /** 扩展头 */
    if (rtpExtensionFlag)
    {
        uint16_t extensionCnt = 0;
        memcpy((void *)&extensionCnt, &tmpBuf[2], 2);
        extensionCnt = ntohs(extensionCnt);
        // cout << "extensionCnt = " << extensionCnt << endl;
        rtpHeaderLen += 4;
        rtpHeaderLen += extensionCnt * 4;

        if (bufLen <= rtpHeaderLen)
        {
            return RET_ERR;
        }
    }

    headerLen = rtpHeaderLen;
    return RET_OK;
}

int FramePkt::parseTsData(const char *pBuf, uint32_t bufLen)
{
    const char *tmpBuf = pBuf;

    if (NULL == tmpBuf || bufLen < TS_PKT_SIZE)
    {
        return RET_ERR;
    }

    for (; bufLen >= 188; bufLen -= 188, tmpBuf += 188)
    {
        if (tmpBuf[0] != 0x47)
        {
            // cout << "0x47 error" << endl;
            return RET_ERR;
        }
        // tsCnt++;
    }
    return RET_OK;
}

int RtpPktManager::RtpPktStream::addRtpPkt(shared_ptr<FramePkt> pkt)
{
    if (pktVector.size() == 0)
    {
        mId = pkt->getStreamId();
    }
    else
    {
        if (pkt->getStreamId() != mId)
        {
            return RET_ERR;
        }
    }

    pktVector.push_back(pkt);
    return RET_OK;
}

void RtpPktManager::RtpPktStream::sort_pkt()
{
    int sort_len = 2000;
    int sort_step = 1000;
    int total_len = pktVector.size();

    for (int i = 0; i < total_len; i += sort_step)
    {
        vector<shared_ptr<FramePkt>>::iterator it_start = pktVector.begin() + i;
        vector<shared_ptr<FramePkt>>::iterator it_end = pktVector.end();
        if (i + sort_len < total_len)
        {
            it_end = it_start + sort_len;
        }
        std::sort(it_start, it_end,
                  [](std::shared_ptr<FramePkt> &v1, std::shared_ptr<FramePkt> &v2)
                  {
                      int overturn = 20000;
                      int v1_seq = v1->getRtpSeq();
                      int v2_seq = v2->getRtpSeq();
                      if (v1_seq < v2_seq)
                      {
                          if (v2_seq - v1_seq < overturn)
                          {
                              return true;
                          }
                          else
                          {
                              return false;
                          }
                      }
                      else
                      {
                          if (v1_seq - v2_seq > overturn)
                          {
                              return true;
                          }
                          else
                          {
                              return false;
                          }
                      }
                  });
    }
}

void RtpPktManager::RtpPktStream::printfStreamInfo()
{
    vector<FramePkt *> tmpVector;
    uint16_t expectedSeq = 0;
    uint16_t curSeq = 0;
    uint16_t lastSeq = 0;
    uint32_t pktLossCnt = 0;
    uint32_t pktErrorCnt = 0;
    uint32_t pktTotalCnt = 0;

    ofstream tsfile(mId.getStrId().append(".ts").c_str(), ofstream::binary);
    ofstream infofile(mId.getStrId().append(".txt").c_str());

    if (tsfile)
    {
        cout << mId.getStrId().append(".ts") << " create success" << endl;
    }
    else
    {
        cout << mId.getStrId().append(".ts") << " create failed" << endl;
    }

    if (infofile)
    {
        cout << mId.getStrId().append(".txt") << " create success" << endl;
    }
    else
    {
        cout << mId.getStrId().append(".txt") << " create failed" << endl;
    }

    sort_pkt();  // 排序, 处理乱序包

    shared_ptr<FramePkt> lastPkt = NULL;

    for (auto pkt : pktVector)
    {
        if (nullptr != lastPkt)
        {
            lastSeq = lastPkt->getRtpSeq();
            curSeq = pkt->getRtpSeq();
            expectedSeq = lastSeq < 0xffff ? lastSeq + 1 : 0;

            if (curSeq != expectedSeq)
            {
                uint32_t curLoss = 0;
                if (curSeq > expectedSeq)
                {
                    curLoss = curSeq - expectedSeq;
                }
                else
                {
                    curLoss = 0xffff - (expectedSeq - curSeq);
                }

                /** 200个以内的包认为是重复包 */
                if (curLoss > (0xffff - 200))
                {
                    infofile << "pkt error : "
                             << "cur seq " << curSeq << ", index " << pkt->getFrameIndex() << " --"
                             << "last seq " << lastSeq << ", index " << lastPkt->getFrameIndex() << endl;
                    continue;
                }

                pktLossCnt += curLoss;
                pktTotalCnt += curLoss;
                pktErrorCnt++;
                infofile << "pkt loss : "
                         << "cur seq " << curSeq << ", index " << pkt->getFrameIndex() << " --"
                         << "last seq " << lastSeq << ", index " << lastPkt->getFrameIndex() << " -- "
                         << "loss pkt cnt " << curLoss << endl;
            }
        }

        pktTotalCnt += 1;
        pkt->writeToFile(tsfile);
        lastPkt = pkt;
    }

    cout << "stream " << mId.getStrId() << " info:" << endl;
    cout << "pkt total = " << pktTotalCnt << " loss = " << pktLossCnt << " err = " << pktErrorCnt
         << " packet loss probability " << ((double)pktLossCnt / (double)pktTotalCnt) * 100 << "%" << '\n'
         << endl;

    infofile << "pkt total = " << pktTotalCnt << " loss = " << pktLossCnt << " err = " << pktErrorCnt
             << " packet loss probability " << ((double)pktLossCnt / (double)pktTotalCnt) * 100 << "%" << endl;

    tsfile.close();
    infofile.close();
}

void RtpPktManager::addRtpPkt(shared_ptr<FramePkt> pkt)
{
    int ret = RET_ERR;

    if (nullptr == pkt)
    {
        return;
    }

    if (!pkt->isRtpTsPkt())
    {
        return;
    }

    /** 遍历已有的stream并add pkt */
    for (auto stream : streamVector)
    {
        ret = stream->addRtpPkt(pkt);
        if (RET_OK == ret)
        {
            break;
        }
    }

    /** pkt不属于已有的stream,创建stream并add pkt */
    if (RET_ERR == ret)
    {
        shared_ptr<RtpPktStream> spRtpPktStream(new RtpPktStream());
        ret = spRtpPktStream->addRtpPkt(pkt);
        if (RET_OK == ret)
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
    RtpPktManager rtpPktManager;
    PcapFileHeader fileHeader;
    PcapPktHeader pktHeader;
    uint32_t pcapSeq = 1;

    // shared_ptr<char> spcBuf(new char[65535], [](char *p){delete[] p; cout <<
    // "free sp" << endl;});

    if (argc != 2)
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
    if (!inStream)
    {
        std::cerr << "open file failed " << argv[1] << endl;
        return -1;
    }

    memset(&fileHeader, 0, sizeof(fileHeader));
    inStream.read((char *)&fileHeader, sizeof(fileHeader));
    if (!inStream)
    {
        std::cerr << "read failed" << endl;
        return RET_ERR;
    }

    std::cout << "Read file header successfully." << endl;
    std::cout << hex << "0x" << fileHeader.magic << dec
              << '\n'
              //<< fileHeader.versionMajor << '\n'
              //<< fileHeader.versionMinor << '\n'
              //<< fileHeader.timeZone << '\n'
              //<< fileHeader.timeStamp << '\n'
              << fileHeader.pktMaxLen << '\n'
              << "linkLayerType " << fileHeader.linkLayerType << '\n'
              << endl;

    if (fileHeader.magic != 0xa1b2c3d4)
    {
        cerr << "file format error" << endl;
        return RET_ERR;
    }

    shared_ptr<char> spcBuf(new char[65535],
                            [](char *p)
                            {
                                delete[] p;
                                cout << "free sp" << endl;
                            });

    while (inStream)
    {
        inStream.read((char *)&pktHeader, sizeof(pktHeader));
        if (inStream)
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
        if (inStream)
        {
            shared_ptr<FramePkt> spPkt(
                new FramePkt(spcBuf.get(), pktHeader.capLen, pcapSeq++, fileHeader.linkLayerType));
#if DEBUG
            cout << "rtp seq : " << spPkt->getRtpSeq() << endl;
#endif
            rtpPktManager.addRtpPkt(spPkt);
        }
    }

    rtpPktManager.printInfo();
    return 0;
}
