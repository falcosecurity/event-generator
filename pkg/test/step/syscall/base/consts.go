package base

import "golang.org/x/sys/unix"

var openFlags = map[string]int{
	"O_ACCMODE":   unix.O_ACCMODE,
	"O_RDONLY":    unix.O_RDONLY,
	"O_WRONLY":    unix.O_WRONLY,
	"O_RDWR":      unix.O_RDWR,
	"O_APPEND":    unix.O_APPEND,
	"O_ASYNC":     unix.O_ASYNC,
	"O_CLOEXEC":   unix.O_CLOEXEC,
	"O_CREAT":     unix.O_CREAT,
	"O_DIRECT":    unix.O_DIRECT,
	"O_DIRECTORY": unix.O_DIRECTORY,
	"O_DSYNC":     unix.O_DSYNC,
	"O_EXCL":      unix.O_EXCL,
	"O_FSYNC":     unix.O_FSYNC,
	"O_LARGEFILE": unix.O_LARGEFILE,
	"O_NDELAY":    unix.O_NDELAY,
	"O_NOATIME":   unix.O_NOATIME,
	"O_NOCTTY":    unix.O_NOCTTY,
	"O_NOFOLLOW":  unix.O_NOFOLLOW,
	"O_NONBLOCK":  unix.O_NONBLOCK,
	"O_PATH":      unix.O_PATH,
	"O_RSYNC":     unix.O_RSYNC,
	"O_SYNC":      unix.O_SYNC,
	"O_TMPFILE":   unix.O_TMPFILE,
	"O_TRUNC":     unix.O_TRUNC,
}

var openModes = map[string]int{
	"S_IRWXU": unix.S_IRWXU, // user has read, write, and execute permission
	"S_IRUSR": unix.S_IRUSR, // user has read permission
	"S_IWUSR": unix.S_IWUSR, // user has write permission
	"S_IXUSR": unix.S_IXUSR, // user has execute permission
	"S_IRWXG": unix.S_IRWXG, // group has read, write, and execute permission
	"S_IRGRP": unix.S_IRGRP, // group has read permission
	"S_IWGRP": unix.S_IWGRP, // group has write permission
	"S_IXGRP": unix.S_IXGRP, // group has execute permission
	"S_IRWXO": unix.S_IRWXO, // others have read, write, and execute permission
	"S_IROTH": unix.S_IROTH, // others have read permission
	"S_IWOTH": unix.S_IWOTH, // others have write permission
	"S_IXOTH": unix.S_IXOTH, // others have execute permission
	"S_ISUID": unix.S_ISUID, // set-user-ID bit
	"S_ISGID": unix.S_ISGID, // set-group-ID bit (see inode(7)).
	"S_ISVTX": unix.S_ISVTX, // sticky bit (see inode(7)).
}

var openHowResolveFlags = map[string]int{
	"RESOLVE_NO_XDEV":       unix.RESOLVE_NO_XDEV,
	"RESOLVE_NO_MAGICLINKS": unix.RESOLVE_NO_MAGICLINKS,
	"RESOLVE_NO_SYMLINKS":   unix.RESOLVE_NO_SYMLINKS,
	"RESOLVE_BENEATH":       unix.RESOLVE_BENEATH,
	"RESOLVE_IN_ROOT":       unix.RESOLVE_IN_ROOT,
	"RESOLVE_CACHED":        0x20,
}

var linkAtFlags = map[string]int{
	"AT_SYMLINK_FOLLOW": unix.AT_SYMLINK_FOLLOW,
	"AT_EMPTY_PATH":     unix.AT_EMPTY_PATH,
}

var finitModuleFlags = map[string]int{
	"MODULE_INIT_IGNORE_MODVERSIONS": unix.MODULE_INIT_IGNORE_MODVERSIONS,
	"MODULE_INIT_IGNORE_VERMAGIC":    unix.MODULE_INIT_IGNORE_VERMAGIC,
	"MODULE_INIT_COMPRESSED_FILE":    unix.MODULE_INIT_COMPRESSED_FILE,
}

var socketDomains = map[string]int{
	"AF_UNSPEC":     unix.AF_UNSPEC,
	"AF_UNIX":       unix.AF_UNIX,      // Unix domain sockets
	"AF_LOCAL":      unix.AF_LOCAL,     // POSIX name for AF_UNIX
	"AF_INET":       unix.AF_INET,      // Internet IP Protocol
	"AF_AX25":       unix.AF_AX25,      // Amateur Radio AX.25
	"AF_IPX":        unix.AF_IPX,       // Novell IPX
	"AF_APPLETALK":  unix.AF_APPLETALK, // AppleTalk DDP
	"AF_NETROM":     unix.AF_NETROM,    // Amateur Radio NET/ROM
	"AF_BRIDGE":     unix.AF_BRIDGE,    // Multiprotocol bridge
	"AF_ATMPVC":     unix.AF_ATMPVC,    // ATM PVCs
	"AF_X25":        unix.AF_X25,       // Reserved for X.25 project
	"AF_INET6":      unix.AF_INET6,     // IP version 6
	"AF_ROSE":       unix.AF_ROSE,      // Amateur Radio X.25 PLP
	"AF_DECnet":     unix.AF_DECnet,    // Reserved for DECnet project
	"AF_NETBEUI":    unix.AF_NETBEUI,   // Reserved for 802.2LLC project
	"AF_SECURITY":   unix.AF_SECURITY,  // Security callback pseudo AF
	"AF_KEY":        unix.AF_KEY,       // PF_KEY key management API
	"AF_NETLINK":    unix.AF_NETLINK,
	"AF_ROUTE":      unix.AF_ROUTE,      // Alias to AF_NETLINK emulate 4.4BSD
	"AF_PACKET":     unix.AF_PACKET,     // Packet family
	"AF_ASH":        unix.AF_ASH,        // Ash
	"AF_ECONET":     unix.AF_ECONET,     // Acorn Econet
	"AF_ATMSVC":     unix.AF_ATMSVC,     // ATM SVCs
	"AF_RDS":        unix.AF_RDS,        // RDS sockets
	"AF_SNA":        unix.AF_SNA,        // Linux SNA Project (nutters!)
	"AF_IRDA":       unix.AF_IRDA,       // IRDA sockets
	"AF_PPPOX":      unix.AF_PPPOX,      // PPPoX sockets
	"AF_WANPIPE":    unix.AF_WANPIPE,    // Wanpipe API Sockets
	"AF_LLC":        unix.AF_LLC,        // Linux LLC
	"AF_IB":         unix.AF_IB,         // Native InfiniBand address
	"AF_MPLS":       unix.AF_MPLS,       // MPLS
	"AF_CAN":        unix.AF_CAN,        // Controller Area Network
	"AF_TIPC":       unix.AF_TIPC,       // TIPC sockets
	"AF_BLUETOOTH":  unix.AF_BLUETOOTH,  // Bluetooth sockets
	"AF_IUCV":       unix.AF_IUCV,       // IUCV sockets
	"AF_RXRPC":      unix.AF_RXRPC,      // RxRPC sockets
	"AF_ISDN":       unix.AF_ISDN,       // mISDN sockets
	"AF_PHONET":     unix.AF_PHONET,     // Phonet sockets
	"AF_IEEE802154": unix.AF_IEEE802154, // IEEE802154 sockets
	"AF_CAIF":       unix.AF_CAIF,       // CAIF sockets
	"AF_ALG":        unix.AF_ALG,        // Algorithm sockets
	"AF_NFC":        unix.AF_NFC,        // NFC sockets
	"AF_VSOCK":      unix.AF_VSOCK,      // vSockets
	"AF_KCM":        unix.AF_KCM,        // Kernel Connection Multiplexor
	"AF_QIPCRTR":    unix.AF_QIPCRTR,    // Qualcomm IPC Router
	"AF_SMC":        unix.AF_SMC,        // smc sockets: reserve number for PF_SMC protocol family that reuses AF_INET address family
	"AF_XDP":        unix.AF_XDP,        // XDP sockets
	"AF_MCTP":       unix.AF_MCTP,       // Management component transport protocol
}

var socketTypes = map[string]int{
	"SOCK_STREAM":    unix.SOCK_STREAM,    // Stream (connection) socket
	"SOCK_DGRAM":     unix.SOCK_DGRAM,     // Datagram (conn.less) socket
	"SOCK_RAW":       unix.SOCK_RAW,       // Raw socket
	"SOCK_RDM":       unix.SOCK_RDM,       // Reliably-delivered message
	"SOCK_SEQPACKET": unix.SOCK_SEQPACKET, // Sequential packet socket
	"SOCK_DCCP":      unix.SOCK_DCCP,      // Datagram Congestion Control Protocol socket
	"SOCK_PACKET":    unix.SOCK_PACKET,    // Linux specific way of getting packets at the dev level
}

var socketProtocols = map[string]int{
	"IPPROTO_IP":       unix.IPPROTO_IP,       // Dummy protocol for TCP
	"IPPROTO_ICMP":     unix.IPPROTO_ICMP,     // Internet Control Message Protocol
	"IPPROTO_IGMP":     unix.IPPROTO_IGMP,     // Internet Group Management Protocol
	"IPPROTO_IPIP":     unix.IPPROTO_IPIP,     // IPIP tunnels (older KA9Q tunnels use 94)
	"IPPROTO_TCP":      unix.IPPROTO_TCP,      // Transmission Control Protocol
	"IPPROTO_EGP":      unix.IPPROTO_EGP,      // Exterior Gateway Protocol
	"IPPROTO_PUP":      unix.IPPROTO_PUP,      // PUP protocol
	"IPPROTO_UDP":      unix.IPPROTO_UDP,      // User Datagram Protocol
	"IPPROTO_IDP":      unix.IPPROTO_IDP,      // XNS IDP protocol
	"IPPROTO_TP":       unix.IPPROTO_TP,       // SO Transport Protocol Class 4
	"IPPROTO_DCCP":     unix.IPPROTO_DCCP,     // Datagram Congestion Control Protocol
	"IPPROTO_IPV6":     unix.IPPROTO_IPV6,     // IPv6-in-IPv4 tunnelling
	"IPPROTO_RSVP":     unix.IPPROTO_RSVP,     // RSVP Protocol
	"IPPROTO_GRE":      unix.IPPROTO_GRE,      // Cisco GRE tunnels (rfc 1701,1702)
	"IPPROTO_ESP":      unix.IPPROTO_ESP,      // Encapsulation Security Payload protocol
	"IPPROTO_AH":       unix.IPPROTO_AH,       // Authentication Header protocol
	"IPPROTO_MTP":      unix.IPPROTO_MTP,      // Multicast Transport Protocol
	"IPPROTO_BEETPH":   unix.IPPROTO_BEETPH,   // IP option pseudo header for BEET
	"IPPROTO_ENCAP":    unix.IPPROTO_ENCAP,    // Encapsulation Header
	"IPPROTO_PIM":      unix.IPPROTO_PIM,      // Protocol Independent Multicast
	"IPPROTO_COMP":     unix.IPPROTO_COMP,     // Compression Header Protocol
	"IPPROTO_L2TP":     unix.IPPROTO_L2TP,     // Layer 2 Tunnelling Protocol
	"IPPROTO_SCTP":     unix.IPPROTO_SCTP,     // Stream Control Transport Protocol
	"IPPROTO_UDPLITE":  unix.IPPROTO_UDPLITE,  // UDP-Lite (RFC 3828)
	"IPPROTO_MPLS":     unix.IPPROTO_MPLS,     // MPLS in IP (RFC 4023)
	"IPPROTO_ETHERNET": unix.IPPROTO_ETHERNET, // Ethernet-within-IPv6 Encapsulation
	"IPPROTO_RAW":      unix.IPPROTO_RAW,      // Raw IP packets
	"IPPROTO_SMC":      256,                   // Shared Memory Communications
	"IPPROTO_MPTCP":    unix.IPPROTO_MPTCP,    // Multipath TCP connection
}
