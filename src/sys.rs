use std::net::IpAddr;

/* pub fn type_of<T>(_: T) -> String{
    let a = std::any::type_name::<T>();
    return a.to_string();
} */

pub fn is_ipaddr(ipaddr_str: &str) -> bool {
    match ipaddr_str.parse::<IpAddr>() {
        Ok(_) => {
            return true;
        }
        Err(_) => {
            return false;
        }
    }
}

pub fn is_port(port: &str) -> bool {
    match port.parse::<u16>() {
        Ok(_) => {
            return true;
        }
        Err(_) => {
            return false;
        }
    }
}
