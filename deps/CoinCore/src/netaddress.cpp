// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "netaddress.h"
#include "utilstrencodings.h"
#include "tinyformat.h"

#include <cstring>
#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <boost/algorithm/string/predicate.hpp> // for startswith() and endswith()

using namespace std;

namespace net {
    static const unsigned char pchIPv4[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
    static const unsigned char pchOnionCat[] = { 0xFD,0x87,0xD8,0x7E,0xEB,0x43 };
    // 0xFD + sha256("bitcoin")[0:5]
    static const unsigned char g_internal_prefix[] = { 0xFD, 0x6B, 0x88, 0xC0, 0x87, 0x24 };

    void CNetAddr::Init()
    {
        memset(ip, 0, sizeof(ip));
        scopeId = 0;
    }

    void CNetAddr::SetIP(const CNetAddr& ipIn)
    {
        memcpy(ip, ipIn.ip, sizeof(ip));
    }

    void CNetAddr::SetRaw(Network network, const uint8_t *ip_in)
    {
        switch (network)
        {
        case NET_IPV4:
            memcpy(ip, pchIPv4, 12);
            memcpy(ip + 12, ip_in, 4);
            break;
        case NET_IPV6:
            memcpy(ip, ip_in, 16);
            break;
        default:
            assert(!"invalid network");
        }
    }

    bool CNetAddr::SetInternal(const std::string &name)
    {
        if (name.empty()) {
            return false;
        }
        unsigned char hash[32] = {};
        //     CSHA256().Write((const unsigned char*)name.data(), name.size()).Finalize(hash);
        //     memcpy(ip, g_internal_prefix, sizeof(g_internal_prefix));
        //     memcpy(ip + sizeof(g_internal_prefix), hash, sizeof(ip) - sizeof(g_internal_prefix));
        return true;
    }

    bool CNetAddr::SetSpecial(const std::string &strName)
    {
        if (strName.size() > 6 && strName.substr(strName.size() - 6, 6) == ".onion") {
            std::vector<unsigned char> vchAddr = DecodeBase32(strName.substr(0, strName.size() - 6).c_str());
            if (vchAddr.size() != 16 - sizeof(pchOnionCat))
                return false;
            memcpy(ip, pchOnionCat, sizeof(pchOnionCat));
            for (unsigned int i = 0; i < 16 - sizeof(pchOnionCat); i++)
                ip[i + sizeof(pchOnionCat)] = vchAddr[i];
            return true;
        }
        return false;
    }

    CNetAddr::CNetAddr()
    {
        Init();
    }

    CNetAddr::CNetAddr(const struct in_addr& ipv4Addr)
    {
        SetRaw(NET_IPV4, (const uint8_t*)&ipv4Addr);
    }

    CNetAddr::CNetAddr(const struct in6_addr& ipv6Addr, const uint32_t scope)
    {
        SetRaw(NET_IPV6, (const uint8_t*)&ipv6Addr);
        scopeId = scope;
    }

    unsigned int CNetAddr::GetByte(int n) const
    {
        return ip[15 - n];
    }

    bool CNetAddr::IsIPv4() const
    {
        return (memcmp(ip, pchIPv4, sizeof(pchIPv4)) == 0);
    }

    bool CNetAddr::IsIPv6() const
    {
        return (!IsIPv4() && !IsTor() && !IsInternal());
    }

    bool CNetAddr::IsRFC1918() const
    {
        return IsIPv4() && (
            GetByte(3) == 10 ||
            (GetByte(3) == 192 && GetByte(2) == 168) ||
            (GetByte(3) == 172 && (GetByte(2) >= 16 && GetByte(2) <= 31)));
    }

    bool CNetAddr::IsRFC2544() const
    {
        return IsIPv4() && GetByte(3) == 198 && (GetByte(2) == 18 || GetByte(2) == 19);
    }

    bool CNetAddr::IsRFC3927() const
    {
        return IsIPv4() && (GetByte(3) == 169 && GetByte(2) == 254);
    }

    bool CNetAddr::IsRFC6598() const
    {
        return IsIPv4() && GetByte(3) == 100 && GetByte(2) >= 64 && GetByte(2) <= 127;
    }

    bool CNetAddr::IsRFC5737() const
    {
        return IsIPv4() && ((GetByte(3) == 192 && GetByte(2) == 0 && GetByte(1) == 2) ||
            (GetByte(3) == 198 && GetByte(2) == 51 && GetByte(1) == 100) ||
            (GetByte(3) == 203 && GetByte(2) == 0 && GetByte(1) == 113));
    }

    bool CNetAddr::IsRFC3849() const
    {
        return GetByte(15) == 0x20 && GetByte(14) == 0x01 && GetByte(13) == 0x0D && GetByte(12) == 0xB8;
    }

    bool CNetAddr::IsRFC3964() const
    {
        return (GetByte(15) == 0x20 && GetByte(14) == 0x02);
    }

    bool CNetAddr::IsRFC6052() const
    {
        static const unsigned char pchRFC6052[] = { 0,0x64,0xFF,0x9B,0,0,0,0,0,0,0,0 };
        return (memcmp(ip, pchRFC6052, sizeof(pchRFC6052)) == 0);
    }

    bool CNetAddr::IsRFC4380() const
    {
        return (GetByte(15) == 0x20 && GetByte(14) == 0x01 && GetByte(13) == 0 && GetByte(12) == 0);
    }

    bool CNetAddr::IsRFC4862() const
    {
        static const unsigned char pchRFC4862[] = { 0xFE,0x80,0,0,0,0,0,0 };
        return (memcmp(ip, pchRFC4862, sizeof(pchRFC4862)) == 0);
    }

    bool CNetAddr::IsRFC4193() const
    {
        return ((GetByte(15) & 0xFE) == 0xFC);
    }

    bool CNetAddr::IsRFC6145() const
    {
        static const unsigned char pchRFC6145[] = { 0,0,0,0,0,0,0,0,0xFF,0xFF,0,0 };
        return (memcmp(ip, pchRFC6145, sizeof(pchRFC6145)) == 0);
    }

    bool CNetAddr::IsRFC4843() const
    {
        return (GetByte(15) == 0x20 && GetByte(14) == 0x01 && GetByte(13) == 0x00 && (GetByte(12) & 0xF0) == 0x10);
    }

    bool CNetAddr::IsTor() const
    {
        return (memcmp(ip, pchOnionCat, sizeof(pchOnionCat)) == 0);
    }

    bool CNetAddr::IsLocal() const
    {
        // IPv4 loopback
        if (IsIPv4() && (GetByte(3) == 127 || GetByte(3) == 0))
            return true;

        // IPv6 loopback (::1/128)
        static const unsigned char pchLocal[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 };
        if (memcmp(ip, pchLocal, 16) == 0)
            return true;

        return false;
    }

    bool CNetAddr::IsValid() const
    {
        // Cleanup 3-byte shifted addresses caused by garbage in size field
        // of addr messages from versions before 0.2.9 checksum.
        // Two consecutive addr messages look like this:
        // header20 vectorlen3 addr26 addr26 addr26 header20 vectorlen3 addr26 addr26 addr26...
        // so if the first length field is garbled, it reads the second batch
        // of addr misaligned by 3 bytes.
        if (memcmp(ip, pchIPv4 + 3, sizeof(pchIPv4) - 3) == 0)
            return false;

        // unspecified IPv6 address (::/128)
        unsigned char ipNone6[16] = {};
        if (memcmp(ip, ipNone6, 16) == 0)
            return false;

        // documentation IPv6 address
        if (IsRFC3849())
            return false;

        if (IsInternal())
            return false;

        if (IsIPv4())
        {
            // INADDR_NONE
            uint32_t ipNone = INADDR_NONE;
            if (memcmp(ip + 12, &ipNone, 4) == 0)
                return false;

            // 0
            ipNone = 0;
            if (memcmp(ip + 12, &ipNone, 4) == 0)
                return false;
        }

        return true;
    }

    bool CNetAddr::IsRoutable() const
    {
        return IsValid() && !(IsRFC1918() || IsRFC2544() || IsRFC3927() || IsRFC4862() || IsRFC6598() || IsRFC5737() || (IsRFC4193() && !IsTor()) || IsRFC4843() || IsLocal() || IsInternal());
    }

    bool CNetAddr::IsInternal() const
    {
        return memcmp(ip, g_internal_prefix, sizeof(g_internal_prefix)) == 0;
    }

    enum Network CNetAddr::GetNetwork() const
    {
        if (IsInternal())
            return NET_INTERNAL;

        if (!IsRoutable())
            return NET_UNROUTABLE;

        if (IsIPv4())
            return NET_IPV4;

        if (IsTor())
            return NET_TOR;

        return NET_IPV6;
    }

    std::string CNetAddr::ToString() const
    {
        return ToStringIP();
    }

    std::string CNetAddr::ToStringIP() const
    {
//         if (IsTor())
//             return EncodeBase32(&ip[6], 10) + ".onion";
//         if (IsInternal())
//             return EncodeBase32(ip + sizeof(g_internal_prefix), sizeof(ip) - sizeof(g_internal_prefix)) + ".internal";
//         CService serv(*this, 0);
//         struct sockaddr_storage sockaddr;
//         socklen_t socklen = sizeof(sockaddr);
//         if (serv.GetSockAddr((struct sockaddr*)&sockaddr, &socklen)) {
//             char name[1025] = "";
//             if (!getnameinfo((const struct sockaddr*)&sockaddr, socklen, name, sizeof(name), nullptr, 0, NI_NUMERICHOST))
//                 return std::string(name);
//         }
        if (IsIPv4())
            return strprintf("%u.%u.%u.%u", GetByte(3), GetByte(2), GetByte(1), GetByte(0));
        else
            return strprintf("%x:%x:%x:%x:%x:%x:%x:%x",
                GetByte(15) << 8 | GetByte(14), GetByte(13) << 8 | GetByte(12),
                GetByte(11) << 8 | GetByte(10), GetByte(9) << 8 | GetByte(8),
                GetByte(7) << 8 | GetByte(6), GetByte(5) << 8 | GetByte(4),
                GetByte(3) << 8 | GetByte(2), GetByte(1) << 8 | GetByte(0));
    }

    bool operator==(const CNetAddr& a, const CNetAddr& b)
    {
        return (memcmp(a.ip, b.ip, 16) == 0);
    }

    bool operator!=(const CNetAddr& a, const CNetAddr& b)
    {
        return (memcmp(a.ip, b.ip, 16) != 0);
    }

    bool operator<(const CNetAddr& a, const CNetAddr& b)
    {
        return (memcmp(a.ip, b.ip, 16) < 0);
    }

    bool CNetAddr::GetInAddr(struct in_addr* pipv4Addr) const
    {
        if (!IsIPv4())
            return false;
        memcpy(pipv4Addr, ip + 12, 4);
        return true;
    }

    bool CNetAddr::GetIn6Addr(struct in6_addr* pipv6Addr) const
    {
        memcpy(pipv6Addr, ip, 16);
        return true;
    }

    // get canonical identifier of an address' group
    // no two connections will be attempted to addresses with the same group
    std::vector<unsigned char> CNetAddr::GetGroup() const
    {
        std::vector<unsigned char> vchRet;
        int nClass = NET_IPV6;
        int nStartByte = 0;
        int nBits = 16;

        // all local addresses belong to the same group
        if (IsLocal())
        {
            nClass = 255;
            nBits = 0;
        }
        // all internal-usage addresses get their own group
        if (IsInternal())
        {
            nClass = NET_INTERNAL;
            nStartByte = sizeof(g_internal_prefix);
            nBits = (sizeof(ip) - sizeof(g_internal_prefix)) * 8;
        }
        // all other unroutable addresses belong to the same group
        else if (!IsRoutable())
        {
            nClass = NET_UNROUTABLE;
            nBits = 0;
        }
        // for IPv4 addresses, '1' + the 16 higher-order bits of the IP
        // includes mapped IPv4, SIIT translated IPv4, and the well-known prefix
        else if (IsIPv4() || IsRFC6145() || IsRFC6052())
        {
            nClass = NET_IPV4;
            nStartByte = 12;
        }
        // for 6to4 tunnelled addresses, use the encapsulated IPv4 address
        else if (IsRFC3964())
        {
            nClass = NET_IPV4;
            nStartByte = 2;
        }
        // for Teredo-tunnelled IPv6 addresses, use the encapsulated IPv4 address
        else if (IsRFC4380())
        {
            vchRet.push_back(NET_IPV4);
            vchRet.push_back(GetByte(3) ^ 0xFF);
            vchRet.push_back(GetByte(2) ^ 0xFF);
            return vchRet;
        }
        else if (IsTor())
        {
            nClass = NET_TOR;
            nStartByte = 6;
            nBits = 4;
        }
        // for he.net, use /36 groups
        else if (GetByte(15) == 0x20 && GetByte(14) == 0x01 && GetByte(13) == 0x04 && GetByte(12) == 0x70)
            nBits = 36;
        // for the rest of the IPv6 network, use /32 groups
        else
            nBits = 32;

        vchRet.push_back(nClass);
        while (nBits >= 8)
        {
            vchRet.push_back(GetByte(15 - nStartByte));
            nStartByte++;
            nBits -= 8;
        }
        if (nBits > 0)
            vchRet.push_back(GetByte(15 - nStartByte) | ((1 << (8 - nBits)) - 1));

        return vchRet;
    }

    uint64_t CNetAddr::GetHash() const
    {
        //     btc_uint256 hash = Hash(&ip[0], &ip[16]);
        //     uint64_t nRet=0;
        //     memcpy(&nRet, &hash, sizeof(nRet));
        //     return nRet;
        throw runtime_error("CNetAddr::GetHash not support");
    }

    // private extensions to enum Network, only returned by GetExtNetwork,
    // and only used in GetReachabilityFrom
    static const int NET_UNKNOWN = NET_MAX + 0;
    static const int NET_TEREDO = NET_MAX + 1;
    int static GetExtNetwork(const CNetAddr *addr)
    {
        if (addr == nullptr)
            return NET_UNKNOWN;
        if (addr->IsRFC4380())
            return NET_TEREDO;
        return addr->GetNetwork();
    }

    /** Calculates a metric for how reachable (*this) is from a given partner */
    int CNetAddr::GetReachabilityFrom(const CNetAddr *paddrPartner) const
    {
        enum Reachability {
            REACH_UNREACHABLE,
            REACH_DEFAULT,
            REACH_TEREDO,
            REACH_IPV6_WEAK,
            REACH_IPV4,
            REACH_IPV6_STRONG,
            REACH_PRIVATE
        };

        if (!IsRoutable() || IsInternal())
            return REACH_UNREACHABLE;

        int ourNet = GetExtNetwork(this);
        int theirNet = GetExtNetwork(paddrPartner);
        bool fTunnel = IsRFC3964() || IsRFC6052() || IsRFC6145();

        switch (theirNet) {
        case NET_IPV4:
            switch (ourNet) {
            default:       return REACH_DEFAULT;
            case NET_IPV4: return REACH_IPV4;
            }
        case NET_IPV6:
            switch (ourNet) {
            default:         return REACH_DEFAULT;
            case NET_TEREDO: return REACH_TEREDO;
            case NET_IPV4:   return REACH_IPV4;
            case NET_IPV6:   return fTunnel ? REACH_IPV6_WEAK : REACH_IPV6_STRONG; // only prefer giving our IPv6 address if it's not tunnelled
            }
        case NET_TOR:
            switch (ourNet) {
            default:         return REACH_DEFAULT;
            case NET_IPV4:   return REACH_IPV4; // Tor users can connect to IPv4 as well
            case NET_TOR:    return REACH_PRIVATE;
            }
        case NET_TEREDO:
            switch (ourNet) {
            default:          return REACH_DEFAULT;
            case NET_TEREDO:  return REACH_TEREDO;
            case NET_IPV6:    return REACH_IPV6_WEAK;
            case NET_IPV4:    return REACH_IPV4;
            }
        case NET_UNKNOWN:
        case NET_UNROUTABLE:
        default:
            switch (ourNet) {
            default:          return REACH_DEFAULT;
            case NET_TEREDO:  return REACH_TEREDO;
            case NET_IPV6:    return REACH_IPV6_WEAK;
            case NET_IPV4:    return REACH_IPV4;
            case NET_TOR:     return REACH_PRIVATE; // either from Tor, or don't care about our address
            }
        }
    }

    bool static LookupIntern(const char *pszName, std::vector<CNetAddr>& vIP, unsigned int nMaxSolutions, bool fAllowLookup)
    {
        //vIP.clear();

        {
            CNetAddr addr;
            if (addr.SetSpecial(std::string(pszName))) {
                vIP.push_back(addr);
                return true;
            }
        }

        struct addrinfo aiHint;
        memset(&aiHint, 0, sizeof(struct addrinfo));

        aiHint.ai_socktype = SOCK_STREAM;
        aiHint.ai_protocol = IPPROTO_TCP;
        aiHint.ai_family = AF_UNSPEC;
#ifdef WIN32
        aiHint.ai_flags = fAllowLookup ? 0 : AI_NUMERICHOST;
#else
        aiHint.ai_flags = fAllowLookup ? AI_ADDRCONFIG : AI_NUMERICHOST;
#endif
        struct addrinfo *aiRes = nullptr;
        int nErr = getaddrinfo(pszName, nullptr, &aiHint, &aiRes);
        if (nErr)
            return false;

        struct addrinfo *aiTrav = aiRes;
        while (aiTrav != nullptr && (nMaxSolutions == 0 || vIP.size() < nMaxSolutions))
        {
            CNetAddr resolved;
            if (aiTrav->ai_family == AF_INET)
            {
                assert(aiTrav->ai_addrlen >= sizeof(sockaddr_in));
                resolved = CNetAddr(((struct sockaddr_in*)(aiTrav->ai_addr))->sin_addr);
            }

            if (aiTrav->ai_family == AF_INET6)
            {
                assert(aiTrav->ai_addrlen >= sizeof(sockaddr_in6));
                struct sockaddr_in6* s6 = (struct sockaddr_in6*) aiTrav->ai_addr;
                resolved = CNetAddr(s6->sin6_addr, s6->sin6_scope_id);
            }
            /* Never allow resolving to an internal address. Consider any such result invalid */
            if (!resolved.IsInternal()) {
                vIP.push_back(resolved);
            }

            aiTrav = aiTrav->ai_next;
        }

        freeaddrinfo(aiRes);

        return (vIP.size() > 0);
    }

    bool LookupHost(const char *pszName, std::vector<CNetAddr>& vIP, unsigned int nMaxSolutions, bool fAllowLookup)
    {
        std::string strHost(pszName);
        if (strHost.empty())
            return false;
        if (boost::algorithm::starts_with(strHost, "[") && boost::algorithm::ends_with(strHost, "]"))
        {
            strHost = strHost.substr(1, strHost.size() - 2);
        }
        return LookupIntern(strHost.c_str(), vIP, nMaxSolutions, fAllowLookup);
    }
}