#pragma once
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <algorithm>
#include <istream>
#include <ostream>

// ICMP header for both IPv4 and IPv6.
//
// The wire format of an ICMP header is:
// 
// 0               8               16                             31
// +---------------+---------------+------------------------------+      ---
// |               |               |                              |       ^
// |     type      |     code      |          checksum            |       |
// |               |               |                              |       |
// +---------------+---------------+------------------------------+    8 bytes
// |                               |                              |       |
// |          identifier           |       sequence number        |       |
// |                               |                              |       v
// +-------------------------------+------------------------------+      ---

class icmp_header
{
public:
    enum {
        echo_reply = 0, destination_unreachable = 3, source_quench = 4,
        redirect = 5, echo_request = 8, time_exceeded = 11, parameter_problem = 12,
        timestamp_request = 13, timestamp_reply = 14, info_request = 15,
        info_reply = 16, address_request = 17, address_reply = 18
    };

    icmp_header() { std::fill(rep_, rep_ + sizeof(rep_), 0); }

    unsigned char type() const { return rep_[0]; }
    unsigned char code() const { return rep_[1]; }
    unsigned short checksum() const { return decode(2, 3); }
    unsigned short identifier() const { return decode(4, 5); }
    unsigned short sequence_number() const { return decode(6, 7); }

    void type(unsigned char n) { rep_[0] = n; }
    void code(unsigned char n) { rep_[1] = n; }
    void checksum(unsigned short n) { encode(2, 3, n); }
    void identifier(unsigned short n) { encode(4, 5, n); }
    void sequence_number(unsigned short n) { encode(6, 7, n); }

    friend std::istream& operator >> (std::istream& is, icmp_header& header)
    {
        return is.read(reinterpret_cast<char*>(header.rep_), 8);
    }

    friend std::ostream& operator<<(std::ostream& os, const icmp_header& header)
    {
        return os.write(reinterpret_cast<const char*>(header.rep_), 8);
    }

private:
    unsigned short decode(int a, int b) const
    {
        return (rep_[a] << 8) + rep_[b];
    }

    void encode(int a, int b, unsigned short n)
    {
        rep_[a] = static_cast<unsigned char>(n >> 8);
        rep_[b] = static_cast<unsigned char>(n & 0xFF);
    }

    unsigned char rep_[8];
};

template <typename Iterator>
void compute_checksum(icmp_header& header,
    Iterator body_begin, Iterator body_end)
{
    unsigned int sum = (header.type() << 8) + header.code()
        + header.identifier() + header.sequence_number();

    Iterator body_iter = body_begin;
    while (body_iter != body_end)
    {
        sum += (static_cast<unsigned char>(*body_iter++) << 8);
        if (body_iter != body_end)
            sum += static_cast<unsigned char>(*body_iter++);
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    header.checksum(static_cast<unsigned short>(~sum));
}

// Packet header for IPv4.
//
// The wire format of an IPv4 header is:
// 
// 0               8               16                             31
// +-------+-------+---------------+------------------------------+      ---
// |       |       |               |                              |       ^
// |version|header |    type of    |    total length in bytes     |       |
// |  (4)  | length|    service    |                              |       |
// +-------+-------+---------------+-+-+-+------------------------+       |
// |                               | | | |                        |       |
// |        identification         |0|D|M|    fragment offset     |       |
// |                               | |F|F|                        |       |
// +---------------+---------------+-+-+-+------------------------+       |
// |               |               |                              |       |
// | time to live  |   protocol    |       header checksum        |   20 bytes
// |               |               |                              |       |
// +---------------+---------------+------------------------------+       |
// |                                                              |       |
// |                      source IPv4 address                     |       |
// |                                                              |       |
// +--------------------------------------------------------------+       |
// |                                                              |       |
// |                   destination IPv4 address                   |       |
// |                                                              |       v
// +--------------------------------------------------------------+      ---
// |                                                              |       ^
// |                                                              |       |
// /                        options (if any)                      /    0 - 40
// /                                                              /     bytes
// |                                                              |       |
// |                                                              |       v
// +--------------------------------------------------------------+      ---

class ipv4_header
{
public:
    ipv4_header() { std::fill(rep_, rep_ + sizeof(rep_), 0); }

    unsigned char version() const { return (rep_[0] >> 4) & 0xF; }
    unsigned short header_length() const { return (rep_[0] & 0xF) * 4; }
    unsigned char type_of_service() const { return rep_[1]; }
    unsigned short total_length() const { return decode(2, 3); }
    unsigned short identification() const { return decode(4, 5); }
    bool dont_fragment() const { return (rep_[6] & 0x40) != 0; }
    bool more_fragments() const { return (rep_[6] & 0x20) != 0; }
    unsigned short fragment_offset() const { return decode(6, 7) & 0x1FFF; }
    unsigned int time_to_live() const { return rep_[8]; }
    unsigned char protocol() const { return rep_[9]; }
    unsigned short header_checksum() const { return decode(10, 11); }

    boost::asio::ip::address_v4 source_address() const
    {
        boost::asio::ip::address_v4::bytes_type bytes
            = { { rep_[12], rep_[13], rep_[14], rep_[15] } };
        return boost::asio::ip::address_v4(bytes);
    }

    boost::asio::ip::address_v4 destination_address() const
    {
        boost::asio::ip::address_v4::bytes_type bytes
            = { { rep_[16], rep_[17], rep_[18], rep_[19] } };
        return boost::asio::ip::address_v4(bytes);
    }

    friend std::istream& operator >> (std::istream& is, ipv4_header& header)
    {
        is.read(reinterpret_cast<char*>(header.rep_), 20);
        if (header.version() != 4)
            is.setstate(std::ios::failbit);
        std::streamsize options_length = header.header_length() - 20;
        if (options_length < 0 || options_length > 40)
            is.setstate(std::ios::failbit);
        else
            is.read(reinterpret_cast<char*>(header.rep_) + 20, options_length);
        return is;
    }

private:
    unsigned short decode(int a, int b) const
    {
        return (rep_[a] << 8) + rep_[b];
    }

    unsigned char rep_[60];
};

using boost::asio::ip::icmp;
using boost::asio::deadline_timer;
namespace posix_time = boost::posix_time;

class pinger
{
public:
    pinger(const char* destination, int ping_count = 10)
        : resolver_(io_service_), socket_(io_service_, icmp::v4())
        , timer_(io_service_), sequence_number_(0), num_replies_(0), ping_count_(ping_count)
    {
        icmp::resolver::query query(icmp::v4(), destination, "");
        destination_ = *resolver_.resolve(query);

        start_send();
        start_receive();
    }

    time_t detect()
    {
        io_service_.run();
        return ping_intval();

    }

private:
    void start_send()
    {
        std::string body("\"Hello!\" from Asio ping.");

        // Create an ICMP header for an echo request.
        icmp_header echo_request;
        echo_request.type(icmp_header::echo_request);
        echo_request.code(0);
        echo_request.identifier(get_identifier());
        echo_request.sequence_number(++sequence_number_);
        compute_checksum(echo_request, body.begin(), body.end());

        // Encode the request packet.
        boost::asio::streambuf request_buffer;
        std::ostream os(&request_buffer);
        os << echo_request << body;

        // Send the request.
        time_sent_ = posix_time::microsec_clock::universal_time();
        socket_.send_to(request_buffer.data(), destination_);

        // Wait up to five seconds for a reply.
        //num_replies_ = 0;
        timer_.expires_at(time_sent_ + posix_time::seconds(5));
        timer_.async_wait(boost::bind(&pinger::handle_timeout, this, boost::asio::placeholders::error));
    }

    void handle_timeout(const boost::system::error_code& err)
    {
//         posix_time::ptime now = posix_time::microsec_clock::universal_time();
//         std::cout << "handle_timeout,err " << (err ? "true " : "false ") << now << std::endl;

        if (!should_end()) {
            // Requests must be sent no less than one second apart.
            timer_.expires_at(time_sent_ + posix_time::seconds(1));
            timer_.async_wait(boost::bind(&pinger::start_send, this));
        }
    }

    void start_receive()
    {
        // Discard any data already in the buffer.
        reply_buffer_.consume(reply_buffer_.size());

        // Wait for a reply. We prepare the buffer to receive up to 64KB.
        socket_.async_receive(reply_buffer_.prepare(65536),
            boost::bind(&pinger::handle_receive, this, _2));
    }

    void handle_receive(std::size_t length)
    {
        // The actual number of bytes received is committed to the buffer so that we
        // can extract it using a std::istream object.
        reply_buffer_.commit(length);

        // Decode the reply packet.
        std::istream is(&reply_buffer_);
        ipv4_header ipv4_hdr;
        icmp_header icmp_hdr;
        is >> ipv4_hdr >> icmp_hdr;

        // We can receive all ICMP packets received by the host, so we need to
        // filter out only the echo replies that match the our identifier and
        // expected sequence number.
        if (is && icmp_hdr.type() == icmp_header::echo_reply
            && icmp_hdr.identifier() == get_identifier()
            && icmp_hdr.sequence_number() == sequence_number_)
        {
            // If this is the first reply, interrupt the five second timeout.
            posix_time::ptime now = posix_time::microsec_clock::universal_time();
//             std::cout << "num_replies=" << num_replies_ << ", now=" << now << std::endl;

            ++num_replies_;
            timer_.cancel();

            // Print out some information about the reply packet.
            int64_t this_intval = (now - time_sent_).total_microseconds();
            ping_intval_ += this_intval;

//             std::cout << length - ipv4_hdr.header_length()
//                 << " bytes from " << ipv4_hdr.source_address()
//                 << ": icmp_seq=" << icmp_hdr.sequence_number()
//                 << ", ttl=" << ipv4_hdr.time_to_live()
//                 << ", time=" << this_intval << " ms"
//                 << std::endl;
        }
        if (should_end()) {
            io_service_.stop();
            return;
        }
        start_receive();
    }

    bool should_end() { return num_replies_ >= ping_count_; }
    time_t ping_intval() { return ping_intval_ / ping_count_; }

    static unsigned short get_identifier()
    {
#if defined(BOOST_WINDOWS)
        return static_cast<unsigned short>(::GetCurrentProcessId());
#else
        return static_cast<unsigned short>(::getpid());
#endif
    }

    boost::asio::io_service io_service_;
    icmp::resolver resolver_;
    icmp::endpoint destination_;
    icmp::socket socket_;
    deadline_timer timer_;
    unsigned short sequence_number_;
    posix_time::ptime time_sent_;
    boost::asio::streambuf reply_buffer_;
    std::size_t num_replies_;
    int ping_count_ = 10;
    time_t ping_intval_ = 0;
};
