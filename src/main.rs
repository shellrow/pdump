#[macro_use]
extern crate clap;

mod util;
use util::validator;
use util::option::PacketCaptureOptions;
use util::pcap;
use util::interface;
use util::sys;

use std::env;
use std::time::Duration;
use std::net::{IpAddr, Ipv4Addr};
use clap::{App, AppSettings, Arg, Command};
use default_net;

const CRATE_UPDATE_DATE: &str = "2023-06-03";
const CRATE_AUTHOR_GITHUB: &str = "shellrow <https://github.com/shellrow>";
//const CRATE_REPOSITORY: &str = "https://github.com/shellrow/nscan/pdump";

#[cfg(target_os = "windows")]
fn get_os_type() -> String{"windows".to_owned()}

#[cfg(target_os = "linux")]
fn get_os_type() -> String{"linux".to_owned()}

#[cfg(target_os = "macos")]
fn get_os_type() -> String{"macos".to_owned()}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        show_app_desc();
        std::process::exit(0);
    }
    let app = get_app_settings();
    let matches = app.get_matches();
    let default_interface = default_net::get_default_interface().expect("Failed to get default interface information");
    let mut capture_options: PacketCaptureOptions = PacketCaptureOptions {
        interface_index: default_interface.index,
        interface_name: default_interface.name,
        src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        src_port: 0,
        dst_port: 0,
        protocols: vec![],
        duration: Duration::from_secs(60),
        promiscuous: false,
        default: false,
    };
    if matches.is_present("list") {
        println!("List of network interfaces");
        interface::list_interfaces(default_interface.index);
        std::process::exit(0);
    }
    if matches.is_present("default") {
        capture_options.default = true;
    }
    if let Some(name) = matches.value_of("interface") {
        capture_options.interface_name = name.to_string();
        if let Some(idx) = interface::get_interface_index_by_name(name.to_string()) {
            capture_options.interface_index = idx;
        }
    }
    if matches.is_present("promiscuous") {
        capture_options.promiscuous = true;
    }
    if let Some(host) = matches.value_of("host") {
        capture_options.src_ip = host.parse::<IpAddr>().expect("Invalid IP address.");
        capture_options.dst_ip = host.parse::<IpAddr>().expect("Invalid IP address.");
    }else{
        if let Some(src) = matches.value_of("src") {
            if sys::is_ipaddr(src) {
                capture_options.src_ip = src.parse::<IpAddr>().expect("Invalid IP address");
            }
        }
        if let Some(dst) = matches.value_of("dst") {
            if sys::is_ipaddr(dst) {
                capture_options.dst_ip = dst.parse::<IpAddr>().expect("Invalid IP address");
            }
        }
    }
    if let Some(port) = matches.value_of("port") {
        capture_options.src_port = port.parse::<u16>().expect("Invalid port");
        capture_options.dst_port = port.parse::<u16>().expect("Invalid port");
    }else{
        if let Some(src) = matches.value_of("src") {
            if sys::is_port(src) {
                capture_options.src_port = src.parse::<u16>().expect("Invalid port");
            }
        }
        if let Some(dst) = matches.value_of("dst") {
            if sys::is_port(dst) {
                capture_options.dst_port = dst.parse::<u16>().expect("Invalid port");
            }
        }
    }
    if let Some(protocol) = matches.value_of("protocol") {
        let protocol_vec: Vec<&str> = protocol.trim().split(",").collect();
        for protocol in protocol_vec {
            capture_options.protocols.push(protocol.to_string());
        }
    }
    if let Some(duration) = matches.value_of("duration") {
        capture_options.duration = Duration::from_secs(duration.parse::<u64>().expect("Invalid duration value"))
    }
    println!("{} {} capturing on {}", crate_name!(), crate_version!(), capture_options.interface_name);
    pcap::start_capture(capture_options);
}

fn get_app_settings<'a>() -> Command<'a> {
    let app = App::new(crate_name!())
        .version(crate_version!())
        .author(CRATE_AUTHOR_GITHUB)
        .about(crate_description!())
        .arg(Arg::with_name("list")
            .help("List network interfaces")
            .short('l')
            .long("list")
        )
        .arg(Arg::with_name("default")
            .help("Start with default settings")
            .short('a')
            .long("default")
        )
        .arg(Arg::with_name("promiscuous")
            .help("Enable promiscuous mode")
            .short('r')
            .long("promiscuous")
        )
        .arg(Arg::with_name("interface")
            .help("Specify network interface by name")
            .short('i')
            .long("interface")
            .takes_value(true)
            .value_name("name")
            .validator(validator::validate_interface)
        )
        .arg(Arg::with_name("host")
            .help("Source or destination host")
            .short('H')
            .long("host")
            .takes_value(true)
            .value_name("ip_addr")
            .validator(validator::validate_host_opt)
        )
        .arg(Arg::with_name("port")
            .help("Source or destination port")
            .short('P')
            .long("port")
            .takes_value(true)
            .value_name("port")
            .validator(validator::validate_port_opt)
        )
        .arg(Arg::with_name("src")
            .help("Source IP or Port")
            .short('S')
            .long("src")
            .takes_value(true)
            .value_name("src_ip_or_port")
            .validator(validator::validate_host_port)
        )
        .arg(Arg::with_name("dst")
            .help("Destination IP or Port")
            .short('D')
            .long("dst")
            .takes_value(true)
            .value_name("dst_ip_or_port")
            .value_parser(validator::validate_host_port)
        )
        .arg(Arg::with_name("protocol")
            .help("Protocol Filter. Can be specified as comma separated")
            .short('p')
            .long("protocol")
            .takes_value(true)
            .value_name("protocols")
            .validator(validator::validate_protocol)
        )
        .arg(Arg::with_name("duration")
            .help("Set time limit (duration)")
            .short('d')
            .long("duration")
            .takes_value(true)
            .value_name("duration")
            .validator(validator::validate_duration_opt)
        )
/*         .arg(Arg::with_name("save")
            .help("Save result to file")
            .short("s")
            .long("save")
            .takes_value(true)
            .value_name("file_path")
        ) */
        .setting(AppSettings::DeriveDisplayOrder)
        ;
        app
}

fn show_app_desc() {
    println!("{} {} ({}) {}", crate_name!(), crate_version!(), CRATE_UPDATE_DATE, get_os_type());
    println!("{}", crate_description!());
    println!("{}", CRATE_AUTHOR_GITHUB);
    println!("If you want to start with default settings:");
    println!("'{} --default'", crate_name!());
    println!("or");
    println!("'{} --help' for more information.", crate_name!());
    println!();
}
