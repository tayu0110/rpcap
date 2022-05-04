// https://tools.ietf.org/id/draft-gharris-opsawg-pcap-00.html

use serde::{Serialize, Deserialize};

const DEFAULT_SNAP_LENGTH: u32 = 0xFFFF;    // 65536
const DEFAULT_LINK_TYPE: u32 = 1;           // 1 = Ethernet. For more details, please refer to https://www.tcpdump.org/linktypes.html

#[repr(C)]
#[derive(Serialize, Deserialize)]
pub struct PcapHeader {
    // Magic Number:    0xA1B2C3D4 or 0xA1B23C4D
    //                  If 0xA1B2C3D4, time stamps in Packet Records are in seconds and microseconds,
    //                  if 0xA1B23C4D, time stamps in Packet Records are in seconds and nanoseconds.
    magic_number: u32,
    // Major Version:   Current Version is 2.
    major_version: u16,
    // Minor Version:   Current Version is 4.
    minor_version: u16,
    // Reserved1:       Reserved. Should be filled with 0.
    _rsvd1: u32,
    // Reserved2:       Reserved. Should be filled with 0.
    _rsvd2: u32,
    // SnapLen:         The maximum number of octets captured from each packets.
    //                  MUST NOT be 0. Should be greater than or equal the largest packet length in the file.
    snap_len: u32,
    // LinkType:        04-28: The link layer type of packets in the file.
    //                  03   : "F" bit. If this is set, the FCS bits provide the number of bytes of FCS that are appended to each packet.
    //                  00-02: "FCS" bits. Between 0 and 7.
    link_type: u32
}

impl PcapHeader {
    pub fn new() -> Self {
        let snap_len = DEFAULT_SNAP_LENGTH;
        let link_type = DEFAULT_LINK_TYPE;
        PcapHeader { magic_number: 0xA1B2C3D4, major_version: 2, minor_version: 4, _rsvd1: 0, _rsvd2: 0, snap_len, link_type }
    }
    pub fn get_magic_number(&self) -> u32 {
        self.magic_number
    }
}

#[repr(C)]
#[derive(Serialize, Deserialize)]
pub struct PacketRecordHeader {
    // Timestamp (Seconds):
    //                  UNIX Time (the number of seconds that have elapsed since 1970-01-01 00:00:00 UTC)
    timestamp_sec: u32,
    // Timestamp (Microseconds or nanoseconds):
    //                  The number of microseconds or nanoseconds that have elapsed since that seconds.
    //                  Whether the value represents microseconds or nanoseconds is specified by the magic number in the File Header.
    timestamp_msec: u32,
    // Captured Packet Length:
    //                  The number of octets captured from packet (i.e. the length of the Packet Data Field).
    captured_packet_length: u32,
    // Original Packet Length:
    //                  The actual length of the packet when it was transmitted on the network.
    original_packet_length: u32
}

impl PacketRecordHeader {
    fn new(timestamp_sec: u32, timestamp_msec: u32, captured_packet_length: u32, original_packet_length: u32) -> Self {
        PacketRecordHeader { timestamp_sec, timestamp_msec, captured_packet_length, original_packet_length }
    }
    pub fn get_captured_packet_length(&self) -> u32 {
        self.captured_packet_length
    }
}

#[repr(C)]
#[derive(Serialize, Deserialize)]
pub struct PacketRecord {
    header: PacketRecordHeader,
    // Packet Data:     The data coming from the network, including link-layer headers.
    //                  The actual length of this field is Captured Packet Length.
    #[serde(with = "serde_bytes")]
    packet_data: Vec<u8>
}

impl PacketRecord {
    pub fn new(timestamp_sec: u32, timestamp_msec: u32, captured_packet_length: u32, original_packet_length: u32, data: &[u8]) -> Self {
        let mut packet_data = vec![];
        for v in data {
            packet_data.push(*v);
        }
        let header = PacketRecordHeader::new(timestamp_sec, timestamp_msec, captured_packet_length, original_packet_length);
        PacketRecord { header, packet_data }
    }
}