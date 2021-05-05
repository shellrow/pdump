use std::net::IpAddr;
use std::time::Duration;

pub struct PacketCaptureOptions {
    pub interface_index: u32,
    pub interface_name: String,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocols: Vec<String>,
    pub timeout: Duration,
}


