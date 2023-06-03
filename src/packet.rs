use pnet::packet::ethernet::{EtherType, EtherTypes};
use pnet::packet::icmp::{IcmpType, IcmpTypes};
use pnet::packet::icmpv6::{Icmpv6Type, Icmpv6Types};
use pnet::packet::tcp::TcpFlags;

pub fn get_ethertype_string(ethertype: EtherType) -> String {
    match ethertype {
        EtherTypes::Aarp => {
            return String::from("RARP");
        }
        EtherTypes::AppleTalk => {
            return String::from("AppleTalk");
        }
        EtherTypes::Arp => {
            return String::from("ARP");
        }
        EtherTypes::Cfm => {
            return String::from("CFM");
        }
        EtherTypes::CobraNet => {
            return String::from("CobraNet");
        }
        EtherTypes::DECnet => {
            return String::from("DECnet");
        }
        EtherTypes::FlowControl => {
            return String::from("FlowControl");
        }
        EtherTypes::Ipv4 => {
            return String::from("IPv4");
        }
        EtherTypes::Ipv6 => {
            return String::from("IPv6");
        }
        EtherTypes::Ipx => {
            return String::from("IPX");
        }
        EtherTypes::Lldp => {
            return String::from("LLDP");
        }
        EtherTypes::Mpls => {
            return String::from("MPLS");
        }
        EtherTypes::MplsMcast => {
            return String::from("MPLS Multicast");
        }
        EtherTypes::PBridge => {
            return String::from("Provider Bridging");
        }
        EtherTypes::PppoeDiscovery => {
            return String::from("PPPOE Discovery Stage");
        }
        EtherTypes::PppoeSession => {
            return String::from("PPPoE Session Stage");
        }
        EtherTypes::Ptp => {
            return String::from("PTP");
        }
        EtherTypes::QinQ => {
            return String::from("Q-in-Q");
        }
        EtherTypes::Qnx => {
            return String::from("QNX");
        }
        EtherTypes::Rarp => {
            return String::from("RARP");
        }
        EtherTypes::Trill => {
            return String::from("TRILL");
        }
        EtherTypes::Vlan => {
            return String::from("VLAN");
        }
        EtherTypes::WakeOnLan => {
            return String::from("Wake on Lan");
        }
        _ => {
            return String::from("Unknown");
        }
    }
}

pub fn get_icmp_type_string(icmptype: IcmpType) -> String {
    match icmptype {
        IcmpTypes::AddressMaskReply => {
            return String::from("Address Mask Reply");
        }
        IcmpTypes::AddressMaskRequest => {
            return String::from("Address Mask Request");
        }
        IcmpTypes::DestinationUnreachable => {
            return String::from("Destination Unreachable");
        }
        IcmpTypes::EchoReply => {
            return String::from("Echo Reply");
        }
        IcmpTypes::EchoRequest => {
            return String::from("Echo Request");
        }
        IcmpTypes::InformationReply => {
            return String::from("Information Reply");
        }
        IcmpTypes::InformationRequest => {
            return String::from("Information Request");
        }
        IcmpTypes::ParameterProblem => {
            return String::from("Parameter Problem");
        }
        IcmpTypes::RedirectMessage => {
            return String::from("Redirect Message");
        }
        IcmpTypes::RouterAdvertisement => {
            return String::from("Router Advertisement");
        }
        IcmpTypes::RouterSolicitation => {
            return String::from("Router Solicitation");
        }
        IcmpTypes::SourceQuench => {
            return String::from("Source Quench");
        }
        IcmpTypes::TimeExceeded => {
            return String::from("Time Exceeded");
        }
        IcmpTypes::Timestamp => {
            return String::from("Timestamp");
        }
        IcmpTypes::TimestampReply => {
            return String::from("Timestamp Reply");
        }
        IcmpTypes::Traceroute => {
            return String::from("Traceroute");
        }
        _ => {
            return String::from("Unknown");
        }
    }
}

pub fn get_icmpv6_type_string(icmpv6type: Icmpv6Type) -> String {
    match icmpv6type {
        Icmpv6Types::DestinationUnreachable => {
            return String::from("Destination Unreachable");
        }
        Icmpv6Types::EchoReply => {
            return String::from("Echo Reply");
        }
        Icmpv6Types::EchoRequest => {
            return String::from("Echo Request");
        }
        Icmpv6Types::ParameterProblem => {
            return String::from("Parameter Problem");
        }
        Icmpv6Types::TimeExceeded => {
            return String::from("Time Exceeded");
        }
        _ => {
            return String::from("Unknown");
        }
    }
}

pub fn get_tcp_flag_string(tcp_flags: u16) -> String {
    match tcp_flags {
        TcpFlags::ACK => {
            return String::from("ACK");
        }
        TcpFlags::CWR => {
            return String::from("CWR");
        }
        TcpFlags::ECE => {
            return String::from("ECE");
        }
        TcpFlags::FIN => {
            return String::from("FIN");
        }
        TcpFlags::NS => {
            return String::from("NS");
        }
        TcpFlags::PSH => {
            return String::from("PSH");
        }
        TcpFlags::RST => {
            return String::from("RST");
        }
        TcpFlags::SYN => {
            return String::from("SYN");
        }
        TcpFlags::URG => {
            return String::from("URG");
        }
        _ => {
            if tcp_flags == TcpFlags::SYN | TcpFlags::ACK {
                return String::from("SYN+ACK");
            } else if tcp_flags == TcpFlags::FIN | TcpFlags::ACK {
                return String::from("FIN+ACK");
            } else if tcp_flags == TcpFlags::RST | TcpFlags::ACK {
                return String::from("RST+ACK");
            } else if tcp_flags == TcpFlags::PSH | TcpFlags::ACK {
                return String::from("PSH+ACK");
            } else {
                return tcp_flags.to_string();
            }
        }
    }
}
