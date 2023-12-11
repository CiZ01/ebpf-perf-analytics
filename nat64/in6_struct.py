import ipaddress
from ctypes import *
from socket import htons, htonl, ntohs, ntohl


class in6_addr_union(Union):
    _fields_ = [
        ("u6_addr8", c_uint8 * 16),
        ("u6_addr16", c_uint16 * 8),
        ("u6_addr32", c_uint32 * 4),
    ]


class in6_addr(Structure):
    _fields_ = [("in6_u", in6_addr_union)]

    def __str__(self):
        """
        return the in6_addr as a string
        """
        ipv6_list = [
            self.in6_u.u6_addr32[0],
            self.in6_u.u6_addr32[1],
            self.in6_u.u6_addr32[2],
            self.in6_u.u6_addr32[3],
        ]
        # ipv6_address = 0
        # for i in range(4):
        #    ipv6_address += ipv6_list[i] << (96 - 32 * i)

        return str(ipv6_list)

    def __repr__(self):
        return str(self)

    def set_u6_addr8(self, ipv6_list):
        self.in6_u.u6_addr8[0] = ipv6_list[0]
        self.in6_u.u6_addr8[1] = ipv6_list[1]
        self.in6_u.u6_addr8[2] = ipv6_list[2]
        self.in6_u.u6_addr8[3] = ipv6_list[3]
        self.in6_u.u6_addr8[4] = ipv6_list[4]
        self.in6_u.u6_addr8[5] = ipv6_list[5]
        self.in6_u.u6_addr8[6] = ipv6_list[6]
        self.in6_u.u6_addr8[7] = ipv6_list[7]
        self.in6_u.u6_addr8[8] = ipv6_list[8]
        self.in6_u.u6_addr8[9] = ipv6_list[9]
        self.in6_u.u6_addr8[10] = ipv6_list[10]
        self.in6_u.u6_addr8[11] = ipv6_list[11]
        self.in6_u.u6_addr8[12] = ipv6_list[12]
        self.in6_u.u6_addr8[13] = ipv6_list[13]
        self.in6_u.u6_addr8[14] = ipv6_list[14]
        self.in6_u.u6_addr8[15] = ipv6_list[15]
        return self

    def set_u6_addr16(self, ipv6_list):
        self.in6_u.u6_addr16[0] = ipv6_list[0]
        self.in6_u.u6_addr16[1] = ipv6_list[1]
        self.in6_u.u6_addr16[2] = ipv6_list[2]
        self.in6_u.u6_addr16[3] = ipv6_list[3]
        self.in6_u.u6_addr16[4] = ipv6_list[4]
        self.in6_u.u6_addr16[5] = ipv6_list[5]
        self.in6_u.u6_addr16[6] = ipv6_list[6]
        self.in6_u.u6_addr16[7] = ipv6_list[7]
        return self

    def set_u6_addr32(self, ipv6_list):
        self.in6_u.u6_addr32[0] = ipv6_list[0]
        self.in6_u.u6_addr32[1] = ipv6_list[1]
        self.in6_u.u6_addr32[2] = ipv6_list[2]
        self.in6_u.u6_addr32[3] = ipv6_list[3]
        return self

    def setFromString(self, ip6: str):
        """
        set the in6_addr from a string
        """
        ipv6_address = int(ipaddress.IPv6Address(ip6))
        # Converte l'indirizzo IPv6 in una lista di 4 valori di 32 bit
        ipv6_list32 = [(int(ipv6_address >> i & 0xFFFFFFFF)) for i in (96, 64, 32, 0)]

        print(self.set_u6_addr32(ipv6_list32))

        # Converte la lista di 4 valori di 32 bit in una lista di 8 valori di 16 bit
        ipv6_list16 = [
            int(ipv6_address >> i & 0xFFFF) for i in (112, 96, 80, 64, 48, 32, 16, 0)
        ]
        self.set_u6_addr16(ipv6_list16)

        # Converte la lista di 8 valori di 16 bit in una lista di 16 valori di 8 bit
        ipv6_list8 = [
            int(ipv6_address >> i & 0xFF)
            for i in (120, 112, 104, 96, 88, 80, 72, 64, 56, 48, 40, 32, 24, 16, 8, 0)
        ]
        self.set_u6_addr8(ipv6_list8)
        return self
