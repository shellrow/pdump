pub fn get_interface_index_by_name(if_name: String) -> Option<u32> {
    let interfaces = default_net::get_interfaces();
    for interface in interfaces {
        if interface.name == if_name {
            return Some(interface.index);
        }
    }
    return None;
}

pub fn list_interfaces(default_interface_index: u32) {
    let interfaces = default_net::get_interfaces();
    for interface in interfaces {
        if interface.index == default_interface_index {
            println!("[{}] {} (Default)", interface.index, interface.name);
        } else {
            println!("[{}] {}", interface.index, interface.name);
        }
        println!(
            "\tFriendly Name: {}",
            interface.friendly_name.unwrap_or("".to_string())
        );
        println!(
            "\tDescription: {}",
            interface.description.unwrap_or("".to_string())
        );
        println!("\tType: {}", interface.if_type.name());
        if let Some(mac_addr) = interface.mac_addr {
            println!("\tMAC: {}", mac_addr);
        } else {
            println!("\tMAC: (Failed to get mac address)");
        }
        println!("\tIPv4: {:?}", interface.ipv4);
        println!("\tIPv6: {:?}", interface.ipv6);
        if let Some(gateway) = interface.gateway {
            println!("Gateway");
            println!("\tMAC: {}", gateway.mac_addr);
            println!("\tIP: {}", gateway.ip_addr);
        } else {
            println!("Gateway: (Not found)");
        }
        println!();
    }
}
