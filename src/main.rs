use std::fmt::Debug;
use std::io::Write;
use std::net::IpAddr;
use std::process::{self};
use pnet::datalink::{NetworkInterface, DataLinkSender, DataLinkReceiver};
use pnet::datalink::{self, Config, Channel::Ethernet};
use pnet::packet::arp::ArpPacket;
use pnet::packet::icmp::{IcmpTypes, echo_request, echo_reply};
use pnet::packet::icmpv6::Icmpv6Types;
use pnet::packet::{Packet, ip::IpNextHeaderProtocols};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::{ipv4::Ipv4Packet, ipv6::Ipv6Packet, tcp::TcpPacket, udp::UdpPacket, icmp::IcmpPacket, icmpv6::Icmpv6Packet};
use clap::Parser;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, default_value = "", help = "Specify interface to listen")]
    interface: String,
    #[clap(short, long, default_value_t = 1)]
    count: u8
}

struct Interface {
    interface: NetworkInterface,
    _tx: Box<dyn DataLinkSender>,
    rx: Box<dyn DataLinkReceiver>
}
impl Interface {
    fn new(interface: NetworkInterface, _tx: Box<dyn DataLinkSender>, rx: Box<dyn DataLinkReceiver>) -> Self {
        Interface { interface, _tx, rx }
    }
    fn if_name(&self) -> String {
        self.interface.name.to_string()
    }
    fn listen(&mut self) {
        let if_name = self.if_name().to_owned().to_string();
        loop {
            match self.rx.next() {
                Ok(packet) => {
                    let packet = EthernetPacket::new(packet).unwrap();
                    
                    match packet.get_ethertype() {
                        EtherTypes::Ipv4 => Interface::handle_ipv4(if_name, packet),
                        EtherTypes::Ipv6 => Interface::handle_ipv6(if_name, packet),
                        EtherTypes::Arp => Interface::handle_arp(if_name, packet),
                        _ => {
                            println!("Unknown packet: {} > {}; ethertype: {} length: {}", packet.get_source(), packet.get_destination(), packet.get_ethertype(), packet.packet().len());
                        }
                    }
                },
                Err(_e) => {
                    continue;
                }
            }
            break;
        }
    }
    fn handle_ipv4(if_name: String, frame: EthernetPacket) {
        let packet = Ipv4Packet::new(frame.payload());

        match packet {
            Some(packet) => {
                let src = IpAddr::V4(packet.get_source());
                let dest = IpAddr::V4(packet.get_destination());
                match packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => Interface::handle_tcp(if_name, src, dest, packet.payload()),
                    IpNextHeaderProtocols::Udp => Interface::handle_udp(if_name, src, dest, packet.payload()),
                    IpNextHeaderProtocols::Icmp => Interface::handle_icmp(if_name, src, dest, packet.payload()),
                    _ => {
                        println!("[{}]: Unknown IPv6 packet: {} > {}; protocol: {:?}; length: {}",
                            if_name,
                            src,
                            dest,
                            packet.get_next_level_protocol(),
                            packet.payload().len());
                    }
                }
            }
            None => {
                println!("[{}]: Malformed IPv4 Packet", if_name);
                std::io::stdout().flush().unwrap();
            }
        }
    }
    fn handle_ipv6(if_name: String, frame: EthernetPacket) {
        let packet = Ipv6Packet::new(frame.payload());

        match packet {
            Some(packet) => {
                let src = IpAddr::V6(packet.get_source());
                let dest = IpAddr::V6(packet.get_destination());
                match packet.get_next_header() {
                    IpNextHeaderProtocols::Tcp => Interface::handle_tcp(if_name, src, dest, packet.payload()),
                    IpNextHeaderProtocols::Udp => Interface::handle_udp(if_name, src, dest, packet.payload()),
                    IpNextHeaderProtocols::Icmpv6 => Interface::handle_icmpv6(if_name, src, dest, packet.payload()),
                    _ => {
                        println!("[{}]: Unknown IPv6 packet: {} > {}; protocol: {:?}; length: {}",
                            if_name,
                            src,
                            dest,
                            packet.get_next_header(),
                            packet.payload().len());
                    }
                }
            }
            None => {
                println!("[{}]: Malformed IPv6 Packet", if_name);
                std::io::stdout().flush().unwrap();
            }
        }
    }
    fn handle_arp(if_name: String, frame: EthernetPacket) {
        let packet = ArpPacket::new(frame.payload());

        match packet {
            Some(packet) => {
                println!("[{}]: ARP Packet: {}({}) > {}({}); operation: {:?}",
                    if_name,
                    frame.get_source(),
                    packet.get_sender_proto_addr(),
                    frame.get_destination(),
                    packet.get_target_proto_addr(),
                    packet.get_operation());
            }
            None => {
                println!("[{}]: Malformed Arp Packet", if_name);
                std::io::stdout().flush().unwrap();
            }
        }
    }
    fn handle_tcp(if_name: String, src: IpAddr, dest: IpAddr, packet: &[u8]) {
        let segment = TcpPacket::new(packet);

        match segment {
            Some(segment) => {
                println!("[{}]: TCP Packet: {}:{} > {}:{}; length: {}",
                    if_name,
                    src,
                    segment.get_source(),
                    dest,
                    segment.get_destination(),
                    packet.len());
            }
            None => {
                println!("[{}]: Malformed TCP Packet", if_name);
                std::io::stdout().flush().unwrap();
            }
        }
    }
    fn handle_udp(if_name: String, src: IpAddr, dest: IpAddr, packet: &[u8]) {
        let segment = UdpPacket::new(packet);

        match segment {
            Some(segment) => {
                println!("[{}]: UDP Packet: {}:{} > {}:{}; length: {}",
                    if_name,
                    src,
                    segment.get_source(),
                    dest,
                    segment.get_destination(),
                    packet.len());
            }
            None => {
                println!("[{}]: Malformed UDP Packet", if_name);
                std::io::stdout().flush().unwrap();
            }
        }
    }
    fn handle_icmp(if_name: String, src: IpAddr, dest: IpAddr, packet: &[u8]) {
        let segment = IcmpPacket::new(packet);

        match segment {
            Some(segment) => {
                match segment.get_icmp_type() {
                    IcmpTypes::EchoRequest => {
                        let echo_req_packet = echo_request::EchoRequestPacket::new(segment.payload()).unwrap();
                        println!("[{}]: ICMP echo request {} > {} (seq={:?}, id={:?})",
                            if_name,
                            src,
                            dest,
                            echo_req_packet.get_sequence_number(),
                            echo_req_packet.get_identifier());
                    }
                    IcmpTypes::EchoReply => {
                        let echo_rep_packet = echo_reply::EchoReplyPacket::new(segment.payload()).unwrap();
                        println!("[{}]: ICMP echo reply {} > {} (seq={:?}, id={:?})",
                            if_name,
                            src,
                            dest,
                            echo_rep_packet.get_sequence_number(),
                            echo_rep_packet.get_identifier());                        
                    }
                    _ => {
                        println!("[{}]: ICMP echo request {} > {} (type={:?})",
                            if_name,
                            src,
                            dest,
                            segment.get_icmp_type());
                    }
                }
            }
            None => {
                println!("[{}]: Malformed ICMP Packet", if_name);
                std::io::stdout().flush().unwrap();
            }
        }
    }
    fn handle_icmpv6(if_name: String, src: IpAddr, dest: IpAddr, packet: &[u8]) {
        let segment = Icmpv6Packet::new(packet);

        match segment {
            Some(segment) => {
                match segment.get_icmpv6_type() {
                    Icmpv6Types::EchoRequest => {
                        let echo_req_packet = echo_request::EchoRequestPacket::new(segment.payload()).unwrap();
                        println!("[{}]: ICMPv6 echo request {} > {} (seq={:?}, id={:?})",
                            if_name,
                            src,
                            dest,
                            echo_req_packet.get_sequence_number(),
                            echo_req_packet.get_identifier());
                    }
                    Icmpv6Types::EchoReply => {
                        let echo_rep_packet = echo_reply::EchoReplyPacket::new(segment.payload()).unwrap();
                        println!("[{}]: ICMPv6 echo reply {} > {} (seq={:?}, id={:?})",
                            if_name,
                            src,
                            dest,
                            echo_rep_packet.get_sequence_number(),
                            echo_rep_packet.get_identifier());                        
                    }
                    _ => {
                        println!("[{}]: ICMPv6 echo request {} > {} (type={:?})",
                            if_name,
                            src,
                            dest,
                            segment.get_icmpv6_type());
                    }
                }
            }
            None => {
                println!("[{}]: Malformed ICMPv6 Packet", if_name);
                std::io::stdout().flush().unwrap();
            }
        }
    }
}

fn main() {
    let args = Args::parse();
    let mut channels = vec![];

    if args.interface == "" {
        for interface in datalink::interfaces() {
            let mut configuration: Config = Default::default();
            configuration.promiscuous = true;
            match datalink::channel(&interface, configuration) {
                Ok(Ethernet(tx, rx)) => {
                    channels.push(Interface::new(interface, tx, rx));
                }
                Ok(_) => {
                    eprintln!("Fatal: Unhandled channel type");
                    process::exit(exitcode::IOERR);
                }
                Err(e) => {
                    eprintln!("Fatal: Could not open interface \"{}\"", interface.name);
                    eprintln!("Message: {}", e);
                    process::exit(exitcode::IOERR);
                }
            };
        }
    } else {
        for selected_if in args.interface.split(',') {
            let mut is_found = false;
            for interface in datalink::interfaces() {
                if selected_if == interface.name {
                    let mut configuration: Config = Default::default();
                    configuration.promiscuous = true;
                    match datalink::channel(&interface, configuration) {
                        Ok(Ethernet(tx, rx)) => {
                            channels.push(Interface::new(interface, tx, rx));
                        }
                        Ok(_) => {
                            eprintln!("Fatal: Unhandled channel type");
                            process::exit(exitcode::IOERR);
                        }
                        Err(e) => {
                            eprintln!("Fatal: Could not open interface \"{}\"", &selected_if);
                            eprintln!("Message: {}", e);
                            process::exit(exitcode::IOERR);
                        }
                    };
                    is_found = true;
                    break;
                }
            }
            if !is_found {
                eprintln!("Error: \"{}\" is not found", &selected_if);
                process::exit(exitcode::USAGE);
            }
        }
    }

    loop {
        for c in &mut channels {
            c.listen();
        }
    }
}
