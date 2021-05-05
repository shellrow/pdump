use super::option::PacketCaptureOptions;
use std::time::Instant;
use pnet::packet::Packet;

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
    loop {
        match rx.next() {
            Ok(frame) => {
                let frame = pnet::packet::ethernet::EthernetPacket::new(frame).unwrap();
                match frame.get_ethertype() {
                    pnet::packet::ethernet::EtherTypes::Ipv4 => {
                        ipv4_handler(&frame, &capture_options);
                    },
                    pnet::packet::ethernet::EtherTypes::Ipv6 => {
                        ipv6_handler(&frame, &capture_options);
                    },
                    _ => {},
                }
            },
            Err(e) => {
                panic!("Failed to read: {}", e);
            }
        }
        if Instant::now().duration_since(start_time) > capture_options.timeout {
            break;
        }
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
            _ => {}
        }
    }
}

fn tcp_handler(packet: &pnet::packet::ipv4::Ipv4Packet, _capture_options: &PacketCaptureOptions) {
    let tcp = pnet::packet::tcp::TcpPacket::new(packet.payload());
    if let Some(tcp) = tcp {
        println!("{}:{} -> {}:{}, IPv4, TCP, Length {}", packet.get_source(), tcp.get_source(), packet.get_destination(), tcp.get_destination(), tcp.payload().len());
    }
}

fn tcp_handler_v6(packet: &pnet::packet::ipv6::Ipv6Packet, _capture_options: &PacketCaptureOptions) {
    let tcp = pnet::packet::tcp::TcpPacket::new(packet.payload());
    if let Some(tcp) = tcp {
        println!("{}:{} -> {}:{}, IPv6, TCP, Length {}", packet.get_source(), tcp.get_source(), packet.get_destination(), tcp.get_destination(), tcp.payload().len());
    }
}

fn udp_handler(packet: &pnet::packet::ipv4::Ipv4Packet, _capture_options: &PacketCaptureOptions) {
    let udp = pnet::packet::udp::UdpPacket::new(packet.payload());
    if let Some(udp) = udp {
        println!("{}:{} -> {}:{}, IPv4, UDP, Length {}", packet.get_source(), udp.get_source(), packet.get_destination(), udp.get_destination(), udp.payload().len());
    }
}

fn udp_handler_v6(packet: &pnet::packet::ipv6::Ipv6Packet, _capture_options: &PacketCaptureOptions) {
    let udp = pnet::packet::udp::UdpPacket::new(packet.payload());
    if let Some(udp) = udp {
        println!("{}:{} -> {}:{}, IPv6, UDP, Length {}", packet.get_source(), udp.get_source(), packet.get_destination(), udp.get_destination(), udp.payload().len());
    }
}