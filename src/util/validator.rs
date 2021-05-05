use std::net::IpAddr;
use std::str::FromStr;
use super::interface;
use super::db;

pub fn validate_interface(v: String) -> Result<(), String> {
    match interface::get_interface_index_by_name(v) {
        Some(_)=>{
            Ok(())
        },
        None => {
            Err(String::from("Invalid network interface name"))
        },
    }
}

pub fn validate_host_opt(v: String) -> Result<(), String> {
    let addr = IpAddr::from_str(&v);
    match addr {
        Ok(_) => {
            return Ok(())
        },
        Err(_) => {
            return Err(String::from("Please specify ip address"));
        }
    }
}

pub fn validate_port_opt(v: String) -> Result<(), String> {
    match v.parse::<u16>() {
        Ok(_) => {
            return Ok(())
        },
        Err(_) => {
            return Err(String::from("Please specify port number"));
        }
    }
}

pub fn validate_protocol(v: String) -> Result<(), String> {
    let valid_protocols = db::get_protocol_list();
    let protocol_vec: Vec<&str> = v.trim().split(",").collect();
    for protocol in protocol_vec {
        if !valid_protocols.contains(&protocol.to_string()) {
            return Err(String::from("Invalid Protocol"));
        }
    }
    Ok(())
}
