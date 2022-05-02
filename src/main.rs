use std::fmt::Debug;
use std::io::Write;
use std::thread;
use std::sync::{Mutex, Arc};
use std::net::IpAddr;
use std::process::{self};
use pnet::datalink::{
        self,
        Config,
        NetworkInterface,
        Channel::Ethernet,
        DataLinkSender,
        DataLinkReceiver };
use pnet::packet::{
        Packet,
        ethernet::{EthernetPacket, EtherTypes},
        arp::ArpPacket,
        ip::IpNextHeaderProtocols,
        ipv4::Ipv4Packet,
        ipv6::Ipv6Packet,
        tcp::TcpPacket,
        udp::UdpPacket,
        icmp::{IcmpPacket, IcmpTypes, echo_request, echo_reply},
        icmpv6::{Icmpv6Packet, Icmpv6Types} };
use clap::Parser;
use chrono::{Local};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, help = "Specify interfaces to listen")]
    interface: Option<String>,
    #[clap(short, long, help = "Output file name", value_name = "FILE")]
    output: Option<String>
}

struct Interface {
    interface: NetworkInterface,
    _tx: Box<dyn DataLinkSender>,
    rx: Box<dyn DataLinkReceiver>,
}
impl Interface {
    fn new(interface: NetworkInterface, _tx: Box<dyn DataLinkSender>, rx: Box<dyn DataLinkReceiver>) -> Self {
        Interface { interface, _tx, rx }
    }
    fn if_name(&self) -> String {
        self.interface.name.to_string()
    }
    fn listen(&mut self, lock: &Mutex<bool>) {
        loop {
            let if_name = self.if_name().to_owned().to_string();
            match self.rx.next() {
                Ok(packet) => {
                    let packet = EthernetPacket::new(packet).unwrap();
                    let time_stamp = Local::now().format("%Y-%m-%d %H:%M:%S.%6f %Z").to_string();
                    let _lock = lock.lock().unwrap();

                    match packet.get_ethertype() {
                        EtherTypes::Ipv4 => Interface::handle_ipv4(time_stamp, if_name, packet),
                        EtherTypes::Ipv6 => Interface::handle_ipv6(time_stamp, if_name, packet),
                        EtherTypes::Arp => Interface::handle_arp(time_stamp, if_name, packet),
                        _ => {
                            println!("{}: [{}]: Unknown packet: {} > {}; ethertype: {} length: {}",
                                time_stamp,
                                if_name,
                                packet.get_source(),
                                packet.get_destination(),
                                packet.get_ethertype(),
                                packet.packet().len());
                        }
                    }
                },
                Err(_e) => {
                    continue;
                }
            }
        }
    }
    fn handle_ipv4(time_stamp: String, if_name: String, frame: EthernetPacket) {
        let packet = Ipv4Packet::new(frame.payload());

        match packet {
            Some(packet) => {
                let src = IpAddr::V4(packet.get_source());
                let dest = IpAddr::V4(packet.get_destination());
                match packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => Interface::handle_tcp(time_stamp, if_name, src, dest, packet.payload()),
                    IpNextHeaderProtocols::Udp => Interface::handle_udp(time_stamp, if_name, src, dest, packet.payload()),
                    IpNextHeaderProtocols::Icmp => Interface::handle_icmp(time_stamp, if_name, src, dest, packet.payload()),
                    _ => {
                        println!("{}: [{}]: Unknown IPv6 packet: {} > {}; protocol: {:?}; length: {}",
                            time_stamp,
                            if_name,
                            src,
                            dest,
                            packet.get_next_level_protocol(),
                            packet.payload().len());
                    }
                }
            }
            None => {
                println!("{}: [{}]: Malformed IPv4 Packet", time_stamp, if_name);
                std::io::stdout().flush().unwrap();
            }
        }
    }
    fn handle_ipv6(time_stamp: String, if_name: String, frame: EthernetPacket) {
        let packet = Ipv6Packet::new(frame.payload());

        match packet {
            Some(packet) => {
                let src = IpAddr::V6(packet.get_source());
                let dest = IpAddr::V6(packet.get_destination());
                match packet.get_next_header() {
                    IpNextHeaderProtocols::Tcp => Interface::handle_tcp(time_stamp, if_name, src, dest, packet.payload()),
                    IpNextHeaderProtocols::Udp => Interface::handle_udp(time_stamp, if_name, src, dest, packet.payload()),
                    IpNextHeaderProtocols::Icmpv6 => Interface::handle_icmpv6(time_stamp, if_name, src, dest, packet.payload()),
                    _ => {
                        println!("{}: [{}]: Unknown IPv6 packet: {} > {}; protocol: {:?}; length: {}",
                            time_stamp,
                            if_name,
                            src,
                            dest,
                            packet.get_next_header(),
                            packet.payload().len());
                    }
                }
            }
            None => {
                println!("{}: [{}]: Malformed IPv6 Packet", time_stamp, if_name);
                std::io::stdout().flush().unwrap();
            }
        }
    }
    fn handle_arp(time_stamp: String, if_name: String, frame: EthernetPacket) {
        let packet = ArpPacket::new(frame.payload());

        match packet {
            Some(packet) => {
                println!("{}: [{}]: ARP Packet: {}({}) > {}({}); operation: {:?}",
                    time_stamp,
                    if_name,
                    frame.get_source(),
                    packet.get_sender_proto_addr(),
                    frame.get_destination(),
                    packet.get_target_proto_addr(),
                    packet.get_operation());
            }
            None => {
                println!("{}: [{}]: Malformed Arp Packet", time_stamp, if_name);
                std::io::stdout().flush().unwrap();
            }
        }
    }
    fn handle_tcp(time_stamp: String, if_name: String, src: IpAddr, dest: IpAddr, packet: &[u8]) {
        let segment = TcpPacket::new(packet);

        match segment {
            Some(segment) => {
                println!("{}: [{}]: TCP Packet: {}:{} > {}:{}; length: {}",
                    time_stamp,
                    if_name,
                    src,
                    segment.get_source(),
                    dest,
                    segment.get_destination(),
                    packet.len());
            }
            None => {
                println!("{}: [{}]: Malformed TCP Packet", time_stamp, if_name);
                std::io::stdout().flush().unwrap();
            }
        }
    }
    fn handle_udp(time_stamp: String, if_name: String, src: IpAddr, dest: IpAddr, packet: &[u8]) {
        let segment = UdpPacket::new(packet);

        match segment {
            Some(segment) => {
                println!("{}: [{}]: UDP Packet: {}:{} > {}:{}; length: {}",
                    time_stamp,
                    if_name,
                    src,
                    segment.get_source(),
                    dest,
                    segment.get_destination(),
                    packet.len());
            }
            None => {
                println!("{}: [{}]: Malformed UDP Packet", time_stamp, if_name);
                std::io::stdout().flush().unwrap();
            }
        }
    }
    fn handle_icmp(time_stamp: String, if_name: String, src: IpAddr, dest: IpAddr, packet: &[u8]) {
        let segment = IcmpPacket::new(packet);

        match segment {
            Some(segment) => {
                match segment.get_icmp_type() {
                    IcmpTypes::EchoRequest => {
                        let echo_req_packet = echo_request::EchoRequestPacket::new(segment.payload()).unwrap();
                        println!("{}: [{}]: ICMP echo request {} > {} (seq={:?}, id={:?})",
                            time_stamp,
                            if_name,
                            src,
                            dest,
                            echo_req_packet.get_sequence_number(),
                            echo_req_packet.get_identifier());
                    }
                    IcmpTypes::EchoReply => {
                        let echo_rep_packet = echo_reply::EchoReplyPacket::new(segment.payload()).unwrap();
                        println!("{}: [{}]: ICMP echo reply {} > {} (seq={:?}, id={:?})",
                            time_stamp,
                            if_name,
                            src,
                            dest,
                            echo_rep_packet.get_sequence_number(),
                            echo_rep_packet.get_identifier());                        
                    }
                    _ => {
                        println!("{}: [{}]: ICMP echo request {} > {} (type={:?})",
                            time_stamp,
                            if_name,
                            src,
                            dest,
                            segment.get_icmp_type());
                    }
                }
            }
            None => {
                println!("{}: [{}]: Malformed ICMP Packet", time_stamp, if_name);
                std::io::stdout().flush().unwrap();
            }
        }
    }
    fn handle_icmpv6(time_stamp: String, if_name: String, src: IpAddr, dest: IpAddr, packet: &[u8]) {
        let segment = Icmpv6Packet::new(packet);

        match segment {
            Some(segment) => {
                match segment.get_icmpv6_type() {
                    Icmpv6Types::EchoRequest => {
                        let echo_req_packet = echo_request::EchoRequestPacket::new(segment.payload()).unwrap();
                        println!("{}: [{}]: ICMPv6 echo request {} > {} (seq={:?}, id={:?})",
                            time_stamp,
                            if_name,
                            src,
                            dest,
                            echo_req_packet.get_sequence_number(),
                            echo_req_packet.get_identifier());
                    }
                    Icmpv6Types::EchoReply => {
                        let echo_rep_packet = echo_reply::EchoReplyPacket::new(segment.payload()).unwrap();
                        println!("{}: [{}]: ICMPv6 echo reply {} > {} (seq={:?}, id={:?})",
                            time_stamp,
                            if_name,
                            src,
                            dest,
                            echo_rep_packet.get_sequence_number(),
                            echo_rep_packet.get_identifier());                        
                    }
                    _ => {
                        println!("{}: [{}]: ICMPv6 echo request {} > {} (type={:?})",
                            time_stamp,
                            if_name,
                            src,
                            dest,
                            segment.get_icmpv6_type());
                    }
                }
            }
            None => {
                println!("{}: [{}]: Malformed ICMPv6 Packet", time_stamp, if_name);
                std::io::stdout().flush().unwrap();
            }
        }
    }
}

fn main() {
    let args = Args::parse();
    let mut channels = vec![];

    match args.interface {
        Some(interfaces) => {
            for selected_if in interfaces.split(',') {
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
        None => {
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
        }
    }
    
    let lock = Arc::new(Mutex::new(false));
    let mut thread_handles = vec![];
    for mut c in channels {
        let lock = Arc::clone(&lock);
        thread_handles.push(thread::spawn(move || {
            c.listen(&lock);
        }));
    }

    for handle in thread_handles {
        handle.join().unwrap();
    }
}
