pub mod ethernet {
    use pnet::packet::Packet;
    use pnet::util::MacAddr;
    use pnet::packet::ethernet::EthernetPacket;

    pub struct IEEE802_3and802_2Packet {
        destination: MacAddr,
        source: MacAddr,
        length: u16,
        dsap: u8,
        ssap: u8,
        control: u8,
        data: Vec<u8>
    }

    impl IEEE802_3and802_2Packet {
        pub fn new(packet: &[u8]) -> Option<Self> {
            let ether_packet = EthernetPacket::new(packet);

            if let Some(ether_packet) = ether_packet {
                if ether_packet.payload().len() < 46 {
                    eprintln!("payload: {}", ether_packet.payload().len());
                    return None;
                }

                let destination = ether_packet.get_destination();
                let source = ether_packet.get_source();
                let length = ether_packet.get_ethertype().0;
                let dsap = ether_packet.payload()[0];
                let ssap = ether_packet.payload()[1];
                let control = ether_packet.payload()[2];
                let data = ether_packet.payload()[3..].iter().copied().collect::<Vec<u8>>();

                return Some(IEEE802_3and802_2Packet { destination, source, length, dsap, ssap, control, data });
            }

            None
        }
        pub fn get_destination(&self) -> MacAddr { self.destination }
        pub fn get_source(&self) -> MacAddr { self.source }
        pub fn get_length(&self) -> u16 { self.length }
        pub fn get_dsap(&self) -> u8 { self.dsap }
        pub fn get_ssap(&self) -> u8 { self.ssap }
        pub fn get_control(&self) -> u8 { self.control }
        pub fn payload(&self) -> &[u8] { self.data.as_slice() }
    }
}

pub mod icmpv6 {
    pub mod destination_unreachable {
        #[allow(non_snake_case)]
        #[allow(non_upper_case_globals)]
        pub mod Icmpv6Codes {
            use pnet::packet::icmpv6::Icmpv6Code;

            pub const NoRouteToDestination: Icmpv6Code = Icmpv6Code(0);
            pub const CommunicationWithDestinationAdministrativelyProhibited: Icmpv6Code = Icmpv6Code(1);
            pub const BeyondScopeOfSourceAddress: Icmpv6Code = Icmpv6Code(2);
            pub const AddressUnreachable: Icmpv6Code = Icmpv6Code(3);
            pub const PortUnreachable: Icmpv6Code = Icmpv6Code(4);
            pub const SourceAddressFailedIngressOrEgressPolicy: Icmpv6Code = Icmpv6Code(5);
            pub const RejectRouteToDestination: Icmpv6Code = Icmpv6Code(6);
            pub const ErrorInSourceRoutingHeader: Icmpv6Code = Icmpv6Code(7);
            pub const HeadersTooLong: Icmpv6Code = Icmpv6Code(8);
        }
    }

    pub mod time_exceeded {
        #[allow(non_snake_case)]
        #[allow(non_upper_case_globals)]
        pub mod Icmpv6Codes {
            use pnet::packet::icmpv6::Icmpv6Code;

            pub const HopLimitExceededInTransit: Icmpv6Code = Icmpv6Code(0);
            pub const FragmentReassemblyTimeExceeded: Icmpv6Code = Icmpv6Code(1);
        }
    }
}

pub mod stp {
    use byteorder::{self, ByteOrder};

    #[repr(C, packed)]
    pub struct BPDUv0Format {
        protocol_id: u16,
        protocol_version: u8,
        bpdu_type: u8,
        bpdu_flags: u8,
        root_id: u64,
        root_path_cost: u32,
        bridge_id: u64,
        port_id: u16,
        message_age: u16,
        max_age: u16,
        hello_time: u16,
        forward_delay: u16
    }

    impl BPDUv0Format {
        pub fn new(data: &[u8]) -> Option<Self> {
            if data.len() < 35 {
                return None;
            }

            let protocol_id = byteorder::NetworkEndian::read_u16(data[0..2].try_into().unwrap());
            let protocol_version = data[2];
            let bpdu_type = data[3];
            let bpdu_flags = data[4];
            let root_id = byteorder::NetworkEndian::read_u64(data[5..13].try_into().unwrap());
            let root_path_cost = byteorder::NetworkEndian::read_u32(data[13..17].try_into().unwrap());
            let bridge_id = byteorder::NetworkEndian::read_u64(data[17..25].try_into().unwrap());
            let port_id = byteorder::NetworkEndian::read_u16(data[25..27].try_into().unwrap());
            let message_age = byteorder::NetworkEndian::read_u16(data[27..29].try_into().unwrap());
            let max_age = byteorder::NetworkEndian::read_u16(data[29..31].try_into().unwrap());
            let hello_time = byteorder::NetworkEndian::read_u16(data[31..33].try_into().unwrap());
            let forward_delay = byteorder::NetworkEndian::read_u16(data[33..35].try_into().unwrap());

            return Some(BPDUv0Format {
                        protocol_id,
                        protocol_version,
                        bpdu_type,
                        bpdu_flags,
                        root_id,
                        root_path_cost,
                        bridge_id,
                        port_id,
                        message_age,
                        max_age,
                        hello_time,
                        forward_delay,
                    });
        }
        pub fn get_protocol_id(&self) -> u16 { self.protocol_id }
        pub fn get_protocol_version(&self) -> u8 { self.protocol_version }
        pub fn get_bpdu_type(&self) -> u8 { self.bpdu_type }
        pub fn get_bpdu_flags(&self) -> u8 { self.bpdu_flags }
        pub fn get_root_id(&self) -> u64 { self.root_id }
        pub fn get_root_path_cost(&self) -> u32 { self.root_path_cost }
        pub fn get_bridge_id(&self) -> u64 { self.bridge_id }
        pub fn get_port_id(&self) -> u16 { self.port_id }
        pub fn get_message_age(&self) -> u16 { self.message_age }
        pub fn get_max_age(&self) -> u16 { self.max_age }
        pub fn get_hello_time(&self) -> u16 { self.hello_time }
        pub fn get_forward_delay(&self) -> u16 { self.forward_delay }
    }

    #[repr(C, packed)]
    pub struct BPDUv2Format {
        protocol_id: u16,
        protocol_version: u8,
        bpdu_type: u8,
        bpdu_flags: u8,
        root_id: u64,
        root_path_cost: u32,
        bridge_id: u64,
        port_id: u16,
        message_age: u16,
        max_age: u16,
        hello_time: u16,
        forward_delay: u16,
        version1_length: u8
    }

    impl BPDUv2Format {
        pub fn new(data: &[u8]) -> Option<Self> {
            if data.len() < 36 {
                return None;
            }

            let protocol_id = byteorder::NetworkEndian::read_u16(data[0..2].try_into().unwrap());
            let protocol_version = data[2];
            let bpdu_type = data[3];
            let bpdu_flags = data[4];
            let root_id = byteorder::NetworkEndian::read_u64(data[5..13].try_into().unwrap());
            let root_path_cost = byteorder::NetworkEndian::read_u32(data[13..17].try_into().unwrap());
            let bridge_id = byteorder::NetworkEndian::read_u64(data[17..25].try_into().unwrap());
            let port_id = byteorder::NetworkEndian::read_u16(data[25..27].try_into().unwrap());
            let message_age = byteorder::NetworkEndian::read_u16(data[27..29].try_into().unwrap());
            let max_age = byteorder::NetworkEndian::read_u16(data[29..31].try_into().unwrap());
            let hello_time = byteorder::NetworkEndian::read_u16(data[31..33].try_into().unwrap());
            let forward_delay = byteorder::NetworkEndian::read_u16(data[33..35].try_into().unwrap());
            let version1_length = data[35];

            return Some(BPDUv2Format {
                        protocol_id,
                        protocol_version,
                        bpdu_type,
                        bpdu_flags,
                        root_id,
                        root_path_cost,
                        bridge_id,
                        port_id,
                        message_age,
                        max_age,
                        hello_time,
                        forward_delay,
                        version1_length
                    });
        }
        pub fn get_protocol_id(&self) -> u16 { self.protocol_id }
        pub fn get_protocol_version(&self) -> u8 { self.protocol_version }
        pub fn get_bpdu_type(&self) -> u8 { self.bpdu_type }
        pub fn get_bpdu_flags(&self) -> u8 { self.bpdu_flags }
        pub fn get_root_id(&self) -> u64 { self.root_id }
        pub fn get_root_path_cost(&self) -> u32 { self.root_path_cost }
        pub fn get_bridge_id(&self) -> u64 { self.bridge_id }
        pub fn get_port_id(&self) -> u16 { self.port_id }
        pub fn get_message_age(&self) -> u16 { self.message_age }
        pub fn get_max_age(&self) -> u16 { self.max_age }
        pub fn get_hello_time(&self) -> u16 { self.hello_time }
        pub fn get_forward_delay(&self) -> u16 { self.forward_delay }
        pub fn get_version1_length(&self) -> u8 { self.version1_length }
    }
}