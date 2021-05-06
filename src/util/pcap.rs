use super::option::PacketCaptureOptions;
use super::packet;
use std::time::Instant;
use pnet::packet::Packet;
use chrono::Local;

pub fn start_capture(capture_options: &PacketCaptureOptions) {
    let interfaces = pnet::datalink::interfaces();
    let interface = interfaces.into_iter().filter(|interface: &pnet::datalink::NetworkInterface| interface.index == capture_options.interface_index).next().expect("Failed to get Interface");
    let (mut _tx, mut rx) = match pnet::datalink::channel(&interface, Default::default()) {
        Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };
    receive_packets(&mut rx, capture_options);
}

fn receive_packets(rx: &mut Box<dyn pnet::datalink::DataLinkReceiver>, capture_options: &PacketCaptureOptions) {
    let start_time = Instant::now();
    let mut cnt = 1;
    loop {
        match rx.next() {
            Ok(frame) => {
                let dt_now = Local::now().format("%Y%m%d%H%M%S%.3f").to_string();
                print!("[{}] [{}] ", cnt, dt_now);
                let frame = pnet::packet::ethernet::EthernetPacket::new(frame).unwrap();
                match frame.get_ethertype() {
                    pnet::packet::ethernet::EtherTypes::Ipv4 => {
                        ipv4_handler(&frame, &capture_options);
                    },
                    pnet::packet::ethernet::EtherTypes::Ipv6 => {
                        ipv6_handler(&frame, &capture_options);
                    },
                    pnet::packet::ethernet::EtherTypes::Vlan => {
                        vlan_handler(&frame, &capture_options);
                    },
                    pnet::packet::ethernet::EtherTypes::Arp => {
                        arp_handler(&frame, &capture_options);
                    },
                    pnet::packet::ethernet::EtherTypes::Rarp => {
                        rarp_handler(&frame, &capture_options);
                    },
                    _ => {
                        eth_handler(&frame, &capture_options);
                    },
                }
            },
            Err(e) => {
                println!("Failed to read: {}", e);
            }
        }
        if Instant::now().duration_since(start_time) > capture_options.timeout {
            break;
        }
        cnt += 1;
    }
}

fn ipv4_handler(ethernet: &pnet::packet::ethernet::EthernetPacket, capture_options: &PacketCaptureOptions) {
    if let Some(packet) = pnet::packet::ipv4::Ipv4Packet::new(ethernet.payload()){
        match packet.get_next_level_protocol() {
            pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
                tcp_handler(&packet, &capture_options);
            },
            pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                udp_handler(&packet, &capture_options);
            },
            pnet::packet::ip::IpNextHeaderProtocols::Icmp => {
                icmp_handler(&packet, &capture_options);
            },
            _ => {}
        }
    }
}

fn ipv6_handler(ethernet: &pnet::packet::ethernet::EthernetPacket, capture_options: &PacketCaptureOptions) {
    if let Some(packet) = pnet::packet::ipv6::Ipv6Packet::new(ethernet.payload()){
        match packet.get_next_header() {
            pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
                tcp_handler_v6(&packet, &capture_options);
            },
            pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                udp_handler_v6(&packet, &capture_options);
            },
            pnet::packet::ip::IpNextHeaderProtocols::Icmpv6 => {
                icmpv6_handler(&packet, &capture_options);
            },
            _ => {}
        }
    }
}

fn eth_handler(ethernet: &pnet::packet::ethernet::EthernetPacket, _capture_options: &PacketCaptureOptions) {
    println!("[{}, {} -> {}, Length {}]", packet::get_ethertype_string(ethernet.get_ethertype()), ethernet.get_source(), ethernet.get_destination(), ethernet.payload().len());
}

fn vlan_handler(ethernet: &pnet::packet::ethernet::EthernetPacket, _capture_options: &PacketCaptureOptions) {
    if let Some(vlan) = pnet::packet::vlan::VlanPacket::new(ethernet.payload()){
        println!("[VLAN, {} -> {}, ID {}, Length {}]", ethernet.get_source(), ethernet.get_destination(), vlan.get_vlan_identifier(), vlan.payload().len());
    }
}

fn arp_handler(ethernet: &pnet::packet::ethernet::EthernetPacket, _capture_options: &PacketCaptureOptions) {
    if let Some(arp) = pnet::packet::arp::ArpPacket::new(ethernet.payload()){
        println!("[ARP, {}({}) -> {}({}), Length {}]", arp.get_sender_proto_addr().to_string(), arp.get_sender_hw_addr().to_string(),arp.get_target_proto_addr().to_string(),arp.get_target_hw_addr().to_string(), arp.payload().len());
    }
}

fn rarp_handler(ethernet: &pnet::packet::ethernet::EthernetPacket, _capture_options: &PacketCaptureOptions) {
    if let Some(arp) = pnet::packet::arp::ArpPacket::new(ethernet.payload()){
        println!("[RARP, {}({}) -> {}({}), Length {}]", arp.get_sender_proto_addr().to_string(), arp.get_sender_hw_addr().to_string(),arp.get_target_proto_addr().to_string(),arp.get_target_hw_addr().to_string(), arp.payload().len());
    }
}

fn icmp_handler(packet: &pnet::packet::ipv4::Ipv4Packet, _capture_options: &PacketCaptureOptions) {
    if let Some(icmp) = pnet::packet::icmp::IcmpPacket::new(packet.payload()){
        println!("[IPv4, {} -> {}, ICMP {} {:?}, Length {}]", packet.get_source(), packet.get_destination(), packet::get_icmp_type_string(icmp.get_icmp_type()), icmp.get_icmp_code(), icmp.payload().len());
    }
}

fn icmpv6_handler(packet: &pnet::packet::ipv6::Ipv6Packet, _capture_options: &PacketCaptureOptions) {
    if let Some(icmp) = pnet::packet::icmpv6::Icmpv6Packet::new(packet.payload()){
        println!("[IPv6, {} -> {}, ICMPv6 {} {:?}, Length {}]", packet.get_source(), packet.get_destination(), packet::get_icmpv6_type_string(icmp.get_icmpv6_type()), icmp.get_icmpv6_code(), icmp.payload().len());
    }
}

fn tcp_handler(packet: &pnet::packet::ipv4::Ipv4Packet, _capture_options: &PacketCaptureOptions) {
    let tcp = pnet::packet::tcp::TcpPacket::new(packet.payload());
    if let Some(tcp) = tcp {
        println!("[IPv4, {}:{} -> {}:{}, TCP {}, Length {}]", packet.get_source(), tcp.get_source(), packet.get_destination(), tcp.get_destination(), packet::get_tcp_flag_string(tcp.get_flags()), tcp.payload().len());
    }
}

fn tcp_handler_v6(packet: &pnet::packet::ipv6::Ipv6Packet, _capture_options: &PacketCaptureOptions) {
    let tcp = pnet::packet::tcp::TcpPacket::new(packet.payload());
    if let Some(tcp) = tcp {
        println!("[IPv6, {}:{} -> {}:{}, TCP {}, Length {}]", packet.get_source(), tcp.get_source(), packet.get_destination(), tcp.get_destination(), packet::get_tcp_flag_string(tcp.get_flags()), tcp.payload().len());
    }
}

fn udp_handler(packet: &pnet::packet::ipv4::Ipv4Packet, _capture_options: &PacketCaptureOptions) {
    let udp = pnet::packet::udp::UdpPacket::new(packet.payload());
    if let Some(udp) = udp {
        println!("[IPv4, {}:{} -> {}:{}, UDP, Length {}]", packet.get_source(), udp.get_source(), packet.get_destination(), udp.get_destination(), udp.payload().len());
    }
}

fn udp_handler_v6(packet: &pnet::packet::ipv6::Ipv6Packet, _capture_options: &PacketCaptureOptions) {
    let udp = pnet::packet::udp::UdpPacket::new(packet.payload());
    if let Some(udp) = udp {
        println!("[IPv6, {}:{} -> {}:{}, UDP, Length {}]", packet.get_source(), udp.get_source(), packet.get_destination(), udp.get_destination(), udp.payload().len());
    }
}
