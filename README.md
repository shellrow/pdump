# pdump
Simple packet capture tool written in rust.

## Basic Usage
```
USAGE:
    pdump [FLAGS] [OPTIONS]

FLAGS:
    -l, --list           List network interfaces
    -a, --default        Start with default settings
    -r, --promiscuous    Enable promiscuous mode
    -h, --help           Prints help information
    -V, --version        Prints version information

OPTIONS:
    -i, --interface <name>        Specify network interface by name
    -H, --host <ip_addr>          Source or destination host
    -P, --port <port>             Source or destination port
    -S, --src <src_ip_or_port>    Source IP or Port
    -D, --dst <dst_ip_or_port>    Destination IP or Port
    -p, --protocol <protocols>    Protocol Filter. Can be specified as comma separated
    -d, --duration <duration>     Set time limit (duration)
```