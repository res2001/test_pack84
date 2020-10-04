#include "portable_endian.h"

#if BYTE_ORDER != LITTLE_ENDIAN && BYTE_RODER != BIG_ENDIAN
#   error No support byte order!
#endif

#include <cstdint>
#include <cerrno>
#include <climits>
#include <cstring>
#include <iostream>
#include <bitset>
#include <cassert>

struct data_s
{
    uint16_t ctx_id;
    uint32_t dcn_adr, tcp_id;
};

constexpr size_t buf_size = sizeof(data_s{}.ctx_id) + sizeof(data_s{}.dcn_adr) + sizeof(data_s{}.tcp_id) + 1;
constexpr uint8_t header = 0b0010;

static void usage(const char *progname)
{
    assert(progname);
    std::clog << "Usage: " << progname << " <16-bits Context ID> <32-bits DCN Address> <32-bits Local TCP-ID>" << std::endl;
}

static long strtol_and_validate(const char *str, const char *name, int64_t min, int64_t max)
{
    assert(str && name);
    char *str_end = nullptr;
    errno = 0;
    const int64_t tmp_var = std::strtoll(str, & str_end, 0);
    if(errno == ERANGE || (str_end != nullptr && *str_end != 0) || tmp_var < min || tmp_var > max)
    {
        std::cerr << name << " error: " << tmp_var << std::endl
                  << "Value is must be range [" << min << "; " << max << "]." << std::endl;
        exit(2);
    }
    return tmp_var;
}

template<typename T>
struct BinaryForm {
    BinaryForm(const T& v) : _v(v) {}
    const T _v;
};
template<typename T>
static std::ostream& operator<<(std::ostream& os, const BinaryForm<T>& bf)
{
    const char *bin_byte[] = {
        "0000", "0001", "0010", "0011", "0100", "0101", "0110", "0111",
        "1000", "1001", "1010", "1011", "1100", "1101", "1110", "1111"
    };
    const uint8_t *byte = reinterpret_cast<const uint8_t*>(& bf._v);
    const uint8_t *end = byte + sizeof(bf._v);
    char space[2] = { 0 };
    while(byte < end)
    {
        os << space << bin_byte[((*byte) & 0xf)] << ' ' << bin_byte[(*byte) >> 4];
        ++byte; space[0] = ' ';
    }
    return os;
}

template<typename T>
struct HexForm {
    HexForm(const T& v) : _v(v) {}
    const T _v;
};
template<typename T>
static std::ostream& operator<<(std::ostream& os, const HexForm<T>& hf)
{
    const uint8_t *byte = reinterpret_cast<const uint8_t*>(& hf._v);
    const uint8_t *end = byte + sizeof(hf._v);
    os << std::hex;
    while(byte < end)
    {
        os << static_cast<uint16_t>((*byte) & 0xf) << static_cast<uint16_t>((*byte) >> 4);
        ++byte;
    }
    os << std::dec;
    return os;
}

static void print_data(const char *firstline, const data_s& data)
{
    assert(firstline);
    std::cout << firstline << std::endl
              << "\tContext ID\t:" << std::dec << data.ctx_id << "\t(raw: 0x" << HexForm{data.ctx_id}
              << ",\t0b" << BinaryForm{data.ctx_id} << ")" << std::endl
              << "\tDCN Address\t:" << std::dec << data.dcn_adr << "\t(raw: 0x" << HexForm{data.dcn_adr}
              << ",\t0b" << BinaryForm(data.dcn_adr) << ")" << std::endl
              << "\tLocal TCP-ID\t:" << std::dec << data.tcp_id << "\t(raw: 0x" << HexForm{data.tcp_id}
              << ",\t0b" << BinaryForm(data.tcp_id) << ")" << std::endl;
}

static void serialize_uint16(uint8_t buf[sizeof(uint16_t) + 1], uint16_t data)
{
    data = htobe16(data);
    std::clog << __func__ << "(): BE data: 0x" << HexForm{data} << std::endl;
    uint8_t *dc = reinterpret_cast<uint8_t*>(& data);
    buf[0] |= dc[0] << 4;
    buf[1] = (dc[0] >> 4) | (dc[1] << 4);
    buf[2] = dc[1] >> 4;
}

static void serialize_uint32(uint8_t buf[sizeof(uint32_t) + 1], uint32_t data)
{
    data = htobe32(data);
    std::clog << __func__ << "(): BE data: 0x" << HexForm{data} << std::endl;
    uint8_t *dc = reinterpret_cast<uint8_t*>(& data);
    buf[0] |= dc[0] << 4;
    buf[1] = (dc[0] >> 4) | (dc[1] << 4);
    buf[2] = (dc[1] >> 4) | (dc[2] << 4);
    buf[3] = (dc[2] >> 4) | (dc[3] << 4);
    buf[4] = dc[3] >> 4;
}

static uint16_t deserialize_uint16(const uint8_t buf[sizeof(uint16_t) + 1])
{
    uint16_t data = 0;
    uint8_t *dc = reinterpret_cast<uint8_t*>(& data);
    dc[0] = (buf[0] >> 4) | (buf[1] << 4);
    dc[1] = (buf[1] >> 4) | (buf[2] << 4);
    data = be16toh(data);
    std::clog << __func__ << "(): Host endian data: 0x" << HexForm{data} << std::endl;
    return data;
}

static uint32_t deserialize_uint32(const uint8_t buf[sizeof(uint32_t) + 1])
{
    uint32_t data = 0;
    uint8_t *dc = reinterpret_cast<uint8_t*>(& data);
    dc[0] = (buf[0] >> 4) | (buf[1] << 4);
    dc[1] = (buf[1] >> 4) | (buf[2] << 4);
    dc[2] = (buf[2] >> 4) | (buf[3] << 4);
    dc[3] = (buf[3] >> 4) | (buf[4] << 4);
    data = be32toh(data);
    std::clog << __func__ << "(): Host endian data: 0x" << HexForm{data} << std::endl;
    return data;
}

static void serialize_data(uint8_t buf[buf_size], data_s data)
{
    buf[0] = header;
    serialize_uint16(& buf[0], data.ctx_id);
    serialize_uint32(& buf[2], data.dcn_adr);
    serialize_uint32(& buf[6], data.tcp_id);
}

static void deserialize_data(const uint8_t buf[buf_size], data_s& data)
{
    data.ctx_id = deserialize_uint16(& buf[0]);
    data.dcn_adr = deserialize_uint32(& buf[2]);
    data.tcp_id = deserialize_uint32(& buf[6]);
}

int main(int argc, char **argv)
{
    if(argc < 4)
    {
        usage(argv[0]);
        return 1;
    }

    data_s data;
    data.ctx_id = static_cast<std::uint16_t>(strtol_and_validate(argv[1], "Context ID", 0, UINT16_MAX));
    data.dcn_adr = static_cast<std::uint32_t>(strtol_and_validate(argv[2], "DCN Address", 0, UINT32_MAX));
    data.tcp_id = static_cast<std::uint32_t>(strtol_and_validate(argv[3], "Local TCP-ID", 0, UINT32_MAX));
    print_data("Original value:", data);

    uint8_t buf[buf_size] = { 0 };
    serialize_data(buf, data);
    std::cout << "Serialized bytes array:" << std::endl << "\t0x";
    for(size_t i = 0; i < sizeof(buf); ++i)
    {
        std::cout << HexForm{buf[i]};
    }
    std::cout << std::endl << "\t0b";
    for(size_t i = 0; i < sizeof(buf); ++i)
    {
        std::cout << BinaryForm{buf[i]} << " ";
    }
    std::cout << std::endl;

    data_s data2 = { 0, 0, 0 };
    deserialize_data(buf, data2);
    print_data("Deserialize value:", data2);
    return 0;
}
