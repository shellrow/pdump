#[macro_use]
extern crate clap;

mod util;
use util::validator;
use util::option::PacketCaptureOptions;
use util::pcap;

use std::env;
use std::time::Duration;
use std::net::{IpAddr, Ipv4Addr};
use clap::{App, AppSettings, Arg};
use default_net;

const CRATE_UPDATE_DATE: &str = "2021-05-05";
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
    let _matches = app.get_matches();
    let default_interface = default_net::get_default_interface().expect("Failed to get default interface information");
    let capture_options: PacketCaptureOptions = PacketCaptureOptions {
        interface_index: default_interface.index,
        interface_name: default_interface.name,
        src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        src_port: 0,
        dst_port: 0,
        protocols: vec![],
        timeout: Duration::from_secs(60),
    };
    pcap::start_capture(&capture_options);
}

fn get_app_settings<'a, 'b>() -> App<'a, 'b> {
    let app = App::new(crate_name!())
        .version(crate_version!())
        .author(CRATE_AUTHOR_GITHUB)
        .about(crate_description!())
        .arg(Arg::with_name("list")
            .help("List network interfaces")
            .short("l")
            .long("list")
        )
        .arg(Arg::with_name("interface")
            .help("Specify network interface by name")
            .short("i")
            .long("interface")
            .takes_value(true)
            .value_name("name")
            .validator(validator::validate_interface)
        )
        .arg(Arg::with_name("host")
            .help("Source or destination host")
            .short("n")
            .long("host")
            .takes_value(true)
            .value_name("ip_addr")
            .validator(validator::validate_host_opt)
        )
        .arg(Arg::with_name("port")
            .help("Source or destination port")
            .short("p")
            .long("port")
            .takes_value(true)
            .value_name("port")
            .validator(validator::validate_port_opt)
        )
        .arg(Arg::with_name("src")
            .help("Source IP or Port")
            .short("s")
            .long("src")
            .takes_value(true)
            .value_name("src_ip_or_port")
            //.validator(validator::validate_src)
        )
        .arg(Arg::with_name("dst")
            .help("Destination IP or Port")
            .short("d")
            .long("dst")
            .takes_value(true)
            .value_name("dst_ip_or_port")
            //.validator(validator::validate_dst)
        )
        .arg(Arg::with_name("protocol")
            .help("Protocol Filter. Can be specified as comma separated")
            .short("t")
            .long("protocol")
            .takes_value(true)
            .value_name("protocols")
            .validator(validator::validate_protocol)
        )
        .arg(Arg::with_name("save")
            .help("Save result to file")
            .short("w")
            .long("save")
            .takes_value(true)
            .value_name("file_path")
        )
        .setting(AppSettings::DeriveDisplayOrder)
        ;
        app
}

fn show_app_desc() {
    println!("{} {} ({}) {}", crate_name!(), crate_version!(), CRATE_UPDATE_DATE, get_os_type());
    println!("{}", crate_description!());
    println!("{}", CRATE_AUTHOR_GITHUB);
    println!();
    println!("'{} --help' for more information.", crate_name!());
    println!();
}
