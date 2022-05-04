use std::net::IpAddr;
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
use chrono::{Local, DateTime};

const TIMESTAMP_FORMAT: &str = "%Y-%m-%d %H:%M:%S.%6f %Z";

pub fn handle_ethernet_packet(time_stamp: DateTime<Local>, if_name: String, data: &[u8]) {
    let packet = EthernetPacket::new(data).unwrap();
    let time_stamp_str = time_stamp.format(TIMESTAMP_FORMAT).to_string();

    match packet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4(time_stamp_str, if_name, packet),
        EtherTypes::Ipv6 => handle_ipv6(time_stamp_str, if_name, packet),
        EtherTypes::Arp => handle_arp(time_stamp_str, if_name, packet),
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
}

pub fn handle_ipv4(time_stamp: String, if_name: String, frame: EthernetPacket) {
    let packet = Ipv4Packet::new(frame.payload());

    match packet {
        Some(packet) => {
            let src = IpAddr::V4(packet.get_source());
            let dest = IpAddr::V4(packet.get_destination());
            match packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => handle_tcp(time_stamp, if_name, src, dest, packet.payload()),
                IpNextHeaderProtocols::Udp => handle_udp(time_stamp, if_name, src, dest, packet.payload()),
                IpNextHeaderProtocols::Icmp => handle_icmp(time_stamp, if_name, src, dest, packet.payload()),
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
        }
    }
}
pub fn handle_ipv6(time_stamp: String, if_name: String, frame: EthernetPacket) {
    let packet = Ipv6Packet::new(frame.payload());

    match packet {
        Some(packet) => {
            let src = IpAddr::V6(packet.get_source());
            let dest = IpAddr::V6(packet.get_destination());
            match packet.get_next_header() {
                IpNextHeaderProtocols::Tcp => handle_tcp(time_stamp, if_name, src, dest, packet.payload()),
                IpNextHeaderProtocols::Udp => handle_udp(time_stamp, if_name, src, dest, packet.payload()),
                IpNextHeaderProtocols::Icmpv6 => handle_icmpv6(time_stamp, if_name, src, dest, packet.payload()),
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
        }
    }
}
pub fn handle_arp(time_stamp: String, if_name: String, frame: EthernetPacket) {
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
        }
    }
}