#define DEBUG true
#define HANDLE_RELAYED_INTRODUCTIONS false
#define PORT 1234 // UDP/3960+ may be used by the game client

#include <iostream>

#include <lzf.hpp>
#include <main.hpp>
#include <md5.hpp>
#include <MemoryRefReader.hpp>
#include <netAdaptor.hpp>
#include <Server.hpp>
#include <ServerServiceUdp.hpp>
#include <Socket.hpp>
#include <string.hpp>
#include <StringWriter.hpp>
#include <time.hpp>
#include <utility.hpp>

extern "C"
{
	// inputData may be modified. Returns true if input data could successfully be decoded as DTLS traffic.
	bool ReadData(uint8_t* inputData, size_t inputDataLength, uint8_t* pendingSendBuffer, size_t* pendingSendLength, uint8_t decryptedDataBuffer[4096], size_t* decryptedDataLength, const char* endpoint);
	void WriteData(const uint8_t* rawData, size_t rawDataLength, uint8_t* encryptedData, size_t* encryptedDataLength, const char* endpoint);
	void init();
	void deinit();
}

using namespace soup;

SOUP_FORCEINLINE uint64_t md5_checksum(const char* data, size_t size, const std::string_view& salt)
{
	md5::State st;
	st.append(data, size);
	st.append(salt.data(), salt.size());
	union {
		uint8_t digest[md5::DIGEST_BYTES];
		uint64_t chksum64;
	} u;
	st.finalise();
	st.getDigest(u.digest);
	return u.chksum64;
}

SOUP_FORCEINLINE std::string compressPacket(std::string&& data)
{
	uint16_t decompressed_size = data.size() - 1;
	uint8_t buffer[0x1000];
	if (decompressed_size <= 0x3F)
	{
		if (auto compressed_size = lzf::compress(data.data() + 1, data.size() - 1, buffer + 1, sizeof(buffer) - 1);
			compressed_size != 0 && (compressed_size + 1) < data.size()
			)
		{
			buffer[0] = decompressed_size;
			return std::string((const char*)buffer, compressed_size + 1);
		}
	}
	else
	{
		if (auto compressed_size = lzf::compress(data.data() + 1, data.size() - 1, buffer + 2, sizeof(buffer) - 2);
			compressed_size != 0 && (compressed_size + 2) < data.size()
			)
		{
			buffer[0] = (decompressed_size >> 6) | 0xC0;
			buffer[1] = (decompressed_size & 0x3F) | 0x80;
			return std::string((const char*)buffer, compressed_size + 2);
		}
	}
	return data;
}

SOUP_FORCEINLINE std::string packData(const std::string& data, const std::string_view& salt)
{
	StringWriter sw;

	sw.skip(9); // placeholder for compression byte + CRC

	uint32_t magic = 0x80000000;
	sw.u32_le(magic);

	sw.str_lp<u16_le_t>(data);

	*(uint64_t*)(sw.data.data() + 1) = md5_checksum(sw.data.data() + 9, sw.data.size() - 9, salt);

#if DEBUG
	//std::cout << "Server says: " << string::bin2hex(sw.data) << std::endl;
#endif

#if true
	return compressPacket(std::move(sw.data));
#else
	static_assert(DEBUG);
	SOUP_MOVE_RETURN(sw.data);
#endif
}

SOUP_NOINLINE static bool unpackData(const SocketAddr& addr, MemoryRefReader& sr, std::string& data) // OBFUS!
{
	uint8_t unk_byte;
	sr.u8(unk_byte);
	if (unk_byte != 0)
	{
		uint16_t expected_decompressed_size = unk_byte;
		if (unk_byte & 0x80)
		{
			expected_decompressed_size &= 0x3F;
			while (unk_byte & 0x40)
			{
				sr.u8(unk_byte);
				expected_decompressed_size <<= 6;
				expected_decompressed_size |= unk_byte & 0x3F;
			}
		}

		char buffer[0x1000];
		const auto decompressed_size = lzf::decompress(data.data() + sr.getPosition(), data.size() - sr.getPosition(), buffer, sizeof(buffer));
		if (decompressed_size != expected_decompressed_size)
		{
#if DEBUG
			std::cout << addr.toString() << " - Decompressed size mismatch (got " << decompressed_size << ", expected " << expected_decompressed_size << "): " << string::bin2hex(data) << std::endl;
#endif
			return false;
		}
		data = std::string(buffer, decompressed_size);
		sr = MemoryRefReader(data);
	}
	return true;
}

template <typename T>
SOUP_FORCEINLINE bool ser_str(T& s, std::string& str)
{
	uint32_t len = str.size();
	s.u32_le(len);
	return s.str(len, str);
}

struct AccountData
{
	native_u32_t ip;
	native_u16_t client_port = 3962;
	native_u16_t server_port = 3960;
#if HANDLE_RELAYED_INTRODUCTIONS
	std::string salt;
#endif
	time_t last_nat_bind;

	bool isActive() const noexcept
	{
		return time::unixSecondsSince(last_nat_bind) <= 120;
	}
};
static std::unordered_map<std::string, AccountData> account_map;

SOUP_FORCEINLINE void collect_garbage()
{
	for (auto it = account_map.begin(); it != account_map.end(); )
	{
		if (it->second.isActive())
		{
			++it;
		}
		else
		{
			account_map.erase(it);
		}
	}
}

SOUP_NOINLINE std::string get_salt(const SocketAddr& addr, MemoryRefReader& sr, const std::string& data) // OBFUS!
{
	uint64_t chksum64;
	sr.u64_le(chksum64);
#if DEBUG
	//std::cout << "Recvd chksum: " << chksum64 << std::endl;
#endif
	const char* salt = "6f7fd17e0eb641ab7"; // < U11 && >= U10.8
	if (md5_checksum(data.data() + sr.getPosition(), data.size() - sr.getPosition(), salt) != chksum64)
	{
		salt = "6f7fd17e0eb641ab6"; // < U10.8 && >= U8.3
		if (md5_checksum(data.data() + sr.getPosition(), data.size() - sr.getPosition(), salt) != chksum64)
		{
			salt = "3bd61b742870d0bb3"; // < U8.3
			if (md5_checksum(data.data() + sr.getPosition(), data.size() - sr.getPosition(), salt) != chksum64)
			{
#if DEBUG
				std::cout << addr.toString() << " - Checksum mismatch: " << string::bin2hex(data) << std::endl;
#endif
				return {};
			}
		}
	}
	return salt;
}

using packet_handler_t = void(*)(Socket& s, const SocketAddr& addr, MemoryRefReader& sr, const std::string& data, const std::string& salt, uint8_t packet_id);

SOUP_NOINLINE void test_packet_handler(Socket& s, const SocketAddr& addr, MemoryRefReader& sr, const std::string& data, const std::string& salt, uint8_t packet_id) // OBFUS!
{
	// ',' acctId ',' NatHash

	StringWriter sw;
	uint8_t b = 39 << 2;
	sw.u8(b);
	std::string tmp = addr.toString();
	ser_str(sw, tmp);
	s.udpServerSend(addr, packData(sw.data, salt));
}

SOUP_NOINLINE void bind_packet_handler(Socket& s, const SocketAddr& addr, MemoryRefReader& sr, const std::string& data, const std::string& salt, uint8_t packet_id) // OBFUS!
{
	sr.skip(1); // ','
	std::string acctId;
	sr.str(24, acctId);
	SOUP_IF_UNLIKELY (char sep = 0; sr.c(sep), sep != ',')
	{
#if DEBUG
		std::cout << addr.toString() << " - Malformed packet: " << string::bin2hex(data) << std::endl;
#endif
		return;
	}
	std::string NatHash_hex;
	sr.str(128, NatHash_hex);
	std::string NatHash = string::hex2bin(NatHash_hex);
	if (NatHash.substr(0, 4) != "OWF1" || NatHash.back() != '\0')
	{
#if DEBUG
		std::cout << addr.toString() << " - Malformed packet: " << string::bin2hex(data) << std::endl;
#endif
		return;
	}
	const char* username = NatHash.c_str() + 4;
	SOUP_IF_UNLIKELY (char sep = 0; sr.c(sep), sep != ',')
	{
#if DEBUG
		std::cout << addr.toString() << " - Malformed packet: " << string::bin2hex(data) << std::endl;
#endif
		return;
	}
	// The rest of this packet is a LAN IP:port (192.168.x.y:3962) tho note that it may not match the 'addr' in cases where the game client picks a different network adaptor.

	AccountData* account;
	if (auto e = account_map.find(acctId); e != account_map.end())
	{
		account = &e->second;
	}
	else
	{
		collect_garbage();
		if (account_map.size() >= 4)
		{
			std::cout << "The limit of 4 players has been reached." << std::endl;
			return;
		}
		account = &account_map.emplace(acctId, AccountData{}).first->second;
		std::cout << "Hello, " << username << std::endl;
	}
	account->ip = addr.ip.getV4NativeEndian();
	if (packet_id == 0x42)
	{
		account->client_port = addr.getPort();
#if DEBUG
		//std::cout << "Client: " << addr.toString() << std::endl;
#endif
	}
	else
	{
		account->server_port = addr.getPort();
#if DEBUG
		//std::cout << "Server: " << addr.toString() << std::endl;
#endif
	}
#if HANDLE_RELAYED_INTRODUCTIONS
	account->salt = salt;
#endif
	account->last_nat_bind = time::unixSeconds();

	StringWriter sw;
	uint8_t b = 37 << 2;
	sw.u8(b);
	// U8 does not need anything in the response, but U10.8 needs this:
	std::string tmp = addr.toString();
	ser_str(sw, tmp);
	std::string resp_data = packData(sw.data, salt);
	s.udpServerSend(addr, resp_data);
}

SOUP_NOINLINE void logout_packet_handler(Socket& s, const SocketAddr& addr, MemoryRefReader& sr, const std::string& data, const std::string& salt, uint8_t packet_id) // OBFUS!
{
	sr.skip(1); // ','
	std::string acctId;
	sr.str(24, acctId);
	SOUP_IF_UNLIKELY (char sep = 0; sr.c(sep), sep != ',')
	{
#if DEBUG
		std::cout << addr.toString() << " - Malformed packet: " << string::bin2hex(data) << std::endl;
#endif
		return;
	}
	std::string NatHash_hex;
	sr.str(128, NatHash_hex);
	std::string NatHash = string::hex2bin(NatHash_hex);
	if (NatHash.substr(0, 4) != "OWF1" || NatHash.back() != '\0')
	{
#if DEBUG
		std::cout << addr.toString() << " - Malformed packet: " << string::bin2hex(data) << std::endl;
#endif
		return;
	}
	const char* username = NatHash.c_str() + 4;

	//account_map.erase(acctId);
	if (auto e = account_map.find(acctId); e != account_map.end())
	{
		account_map.erase(e);
		std::cout << "Goodbye, " << username << std::endl;
	}
}

SOUP_NOINLINE void resolve_packet_handler(Socket& s, const SocketAddr& addr, MemoryRefReader& sr, const std::string& data, const std::string& salt, uint8_t packet_id) // OBFUS!
{
	sr.skip(1); // ','
	sr.skip(24); // acctId
	SOUP_IF_UNLIKELY (char sep = 0; sr.c(sep), sep != ',')
	{
#if DEBUG
		std::cout << addr.toString() << " - Malformed packet: " << string::bin2hex(data) << std::endl;
#endif
		return;
	}
	sr.skip(128); // NatHash
	SOUP_IF_UNLIKELY (char sep = 0; sr.c(sep), sep != ',')
	{
#if DEBUG
		std::cout << addr.toString() << " - Malformed packet: " << string::bin2hex(data) << std::endl;
#endif
		return;
	}
	std::string task_id; sr.str(1, task_id);
	sr.skip(1); // ','
#if DEBUG
	//std::cout << "Resolve pending punchthroughs: " << data.substr(sr.getPosition()) << std::endl;
#endif
	auto targets = string::explode(data.substr(sr.getPosition()), ',');
	std::string res;
	for (const auto& target : targets)
	{
		res.append(target);
		res.push_back(',');
		if (auto e = account_map.find(target); e != account_map.end())
		{
			if (e->second.isActive())
			{
				res.append(IpAddr(e->second.ip).toString());
				res.push_back(',');
				res.append(std::to_string((packet_id & 0x20) ? e->second.server_port : e->second.client_port));
#if false
				res.append(",priv,");
				res.append(IpAddr(e->second.ip).toString());
				res.push_back(',');
				res.append(std::to_string((packet_id & 0x20) ? e->second.server_port : e->second.client_port));

#endif
				res.push_back(',');
				continue;
			}
			account_map.erase(e);
		}
		res.append(",0,0,");
	}
	if (!res.empty())
	{
		res.pop_back();
		StringWriter sw;
		{ uint8_t b = 28 << 2; sw.u8(b); }
		ser_str(sw, task_id);
		ser_str(sw, res);
		s.udpServerSend(addr, packData(sw.data, salt));
	}
}

static packet_handler_t packet_handlers[] = {
	&bind_packet_handler, // 0x01
	&resolve_packet_handler, // 0x02
	nullptr, // 0x03
	&test_packet_handler, // 0x04
	&logout_packet_handler, // 0x05
};

SOUP_NOINLINE packet_handler_t get_packet_handler(uint8_t packet_id) // OBFUS!
{
	// 0x42, 0x62 -> 0x02
	// 0x49, 0x69 -> 0x09
	// 0x52, 0x72 -> 0x12
	// 0x54, 0x74 -> 0x14
	// 0x55       -> 0x15
	packet_id &= 0x1f;

	// 0x02 -> 0x01
	// 0x09 -> 0x08
	uint8_t _10_mask = (packet_id & 0x10);
	packet_id -= (_10_mask == 0);
	// 0x12 -> 0x02
	// 0x14 -> 0x04
	// 0x15 -> 0x05
	packet_id &= ~_10_mask;

	SOUP_IF_LIKELY (packet_id > 0 && packet_id <= 5)
	{
		return packet_handlers[packet_id - 1];
	}
	return nullptr;
}

static void handle_datagram(Socket& s, SocketAddr&& addr, std::string&& data, ServerServiceUdp&)
{
	bool is_dtls = false;
	{
		std::string data_copy = data;
		uint8_t pendingSend[4096];
		uint8_t decryptedData[4096];
		size_t pendingSendLength = 0;
		size_t decryptedDataLength = 0;
		std::string endpoint = addr.toString();
		is_dtls = ReadData((uint8_t*)data_copy.data(), data_copy.size(), pendingSend, &pendingSendLength, decryptedData, &decryptedDataLength, endpoint.c_str());
		if (pendingSendLength > 0)
		{
			s.udpServerSend(addr, (const char*)pendingSend, pendingSendLength);
		}
		if (decryptedDataLength != 0)
		{
			const uint8_t AESkey[] = { 0x63, 0x8C, 0x59, 0x2C, 0xE1, 0x57, 0xC2, 0x1B };
			if (decryptedDataLength == sizeof(AESkey) && memcmp(decryptedData, AESkey, sizeof(AESkey)) == 0)
			{
				uint8_t encryptedData[4096];
				size_t encryptedDataLength = 0;
				WriteData(AESkey, sizeof(AESkey), encryptedData, &encryptedDataLength, endpoint.c_str());
				if (encryptedDataLength > 0)
				{
					s.udpServerSend(addr, (const char*)encryptedData, encryptedDataLength);
				}
				//std::cout << addr.toString() << " - Sent AES key" << std::endl;
				return;
			}
			data = std::string((const char*)decryptedData, decryptedDataLength);
		}
		else if (is_dtls)
		{
			return;
		}
	}

	MemoryRefReader sr(data);
	SOUP_IF_UNLIKELY (!unpackData(addr, sr, data))
	{
		return;
	}

#if DEBUG
	std::cout << addr.toString() << " > " << string::bin2hex(data) << std::endl;
#endif

	std::string salt = get_salt(addr, sr, data);
	SOUP_IF_UNLIKELY (salt.empty())
	{
		return;
	}

	uint8_t packet_id;
	sr.u8(packet_id);
	//std::cout << "packet_id = " << (int)packet_id << std::endl;
	const auto packet_handler = get_packet_handler(packet_id);
	//std::cout << "packet_handler = " << (void*)packet_handler << std::endl;
	SOUP_IF_LIKELY (packet_handler)
	{
		return packet_handler(s, addr, sr, data, salt, packet_id);
	}
	// Note: All packet handlers should have their own obfuscation function.
	switch (packet_id)
	{
#if HANDLE_RELAYED_INTRODUCTIONS // These old versions are a bit inconsistent in general, but "Join Session" seems to work without this, whereas accepting invites does not.
	case 0x49: // Relayed client introduction request
	case 0x69: // Relayed server introduction request
		{
			sr.skip(1); // ','
			std::string acctId;
			sr.str(24, acctId);
			SOUP_IF_UNLIKELY (char sep = 0; sr.c(sep), sep != ',')
			{
#if DEBUG
				std::cout << addr.toString() << " - Malformed packet: " << string::bin2hex(data) << std::endl;
#endif
				return;
			}
			sr.skip(128); // NatHash
			SOUP_IF_UNLIKELY (char sep = 0; sr.c(sep), sep != ',')
			{
#if DEBUG
				std::cout << addr.toString() << " - Malformed packet: " << string::bin2hex(data) << std::endl;
#endif
				return;
			}
			std::string task_id; sr.str(1, task_id);
			sr.skip(1); // ','
			std::string target;
			sr.str(24, target);
			SOUP_IF_UNLIKELY (sr.hasMore())
			{
#if DEBUG
				std::cout << addr.toString() << " - Malformed packet: " << string::bin2hex(data) << std::endl;
#endif
				return;
			}

			if (auto e = account_map.find(target); e != account_map.end())
			{
				if (e->second.isActive())
				{
					SocketAddr to_addr(e->second.ip, (packet_id & 0x20) ? e->second.server_port : e->second.client_port);
					StringWriter sw;
					{
						uint8_t b = 24 << 2;
						sw.u8(b);
						ser_str(sw, acctId);
						ser_str(sw, target);
						std::string tmp = addr.toString();
						ser_str(sw, tmp);
						ser_str(sw, task_id);
					}
					s.udpServerSend(to_addr, packData(sw.data, e->second.salt));
				}
				else
				{
					account_map.erase(e);
				}
			}
		}
		break;
#endif

#if DEBUG
	default:
		std::cout << addr.toString() << " - Unknown packet with id " << (int)packet_id << ": " << string::bin2hex(data) << std::endl;
		break;
#endif
	}
}

SOUP_NOINLINE int entry(std::vector<std::string>&& args, bool console) // OBFUS!
{
	Server serv;

	IpAddr bind_addr;
	for (const auto& ad : netAdaptor::getAll())
	{
		if (!ad.isVirtual()
			&& (ad.ip_addr & SOUP_IPV4(255, 255, 0, 0)) == SOUP_IPV4(192, 168, 0, 0) // We definitely don't wanna bind 0.0.0.0, but limit to 192.168.x.y for now.
			&& ad.netmask == SOUP_IPV4(255, 255, 255, 0)
			)
		{
			bind_addr = ad.ip_addr;
			std::cout << "Using " << ad.name << " (" << bind_addr.toString() << ")" << std::endl;
			break;
		}
	}
	if (bind_addr.isZero())
	{
		std::cerr << "No appropriate network adaptor found" << std::endl;
		return 1;
	}

	ServerServiceUdp srv(handle_datagram);
	if (!serv.bindUdp(bind_addr, PORT, &srv))
	{
		std::cout << "Failed to bind UDP/" << PORT << std::endl;
		return 1;
	}
	std::cout << "Bound UDP/" << PORT << std::endl;
	std::cout << "> Set \"nrsAddresses\" to [\"" << bind_addr.toString() << ":" << PORT << "\"]" << std::endl;

	init();
	serv.run();
	return 0;
}

SOUP_MAIN_CLI(entry);
