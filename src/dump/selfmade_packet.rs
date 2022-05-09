pub mod ethernet {
    use pnet::packet::Packet;
    use pnet::util::MacAddr;
    use pnet::packet::ethernet::EthernetPacket;

    pub struct IEEE802_3and802_2Packet {
        pub destination: MacAddr,
        pub source: MacAddr,
        pub length: u16,
        pub dsap: u8,
        pub ssap: u8,
        pub control: u8,
        pub data: Vec<u8>
    }

    impl IEEE802_3and802_2Packet {
        pub fn new(packet: &[u8]) -> Option<Self> {
            let ether_packet = EthernetPacket::new(packet);

            if let Some(ether_packet) = ether_packet {
                if ether_packet.payload().len() < 46 {
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
        pub fn get_destination(&self) -> MacAddr {
            self.destination
        }
        pub fn get_source(&self) -> MacAddr {
            self.source
        }
        pub fn get_length(&self) -> u16 {
            self.length
        }
        pub fn get_dsap(&self) -> u8 {
            self.dsap
        }
        pub fn get_ssap(&self) -> u8 {
            self.ssap
        }
        pub fn get_control(&self) -> u8 {
            self.control
        }
        pub fn payload(&self) -> &[u8] {
            self.data.as_slice()
        }
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
    use super::ethernet::IEEE802_3and802_2Packet;
    use serde::{Serialize, Deserialize};
    use bincode;

    #[repr(C, packed)]
    #[derive(Serialize, Deserialize)]
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
        pub fn new(packet: &[u8]) -> Option<Self> {
            if let Some(ieee8023_8022_packet) = IEEE802_3and802_2Packet::new(packet) {
                let data = ieee8023_8022_packet.payload();

                if let Ok(packet) = bincode::deserialize(data) {
                    return Some(packet);
                }
            }

            None
        }
    }

    #[repr(C, packed)]
    #[derive(Serialize, Deserialize)]
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
        pub fn new(packet: &[u8]) -> Option<Self> {
            if let Some(ieee8023_8022_packet) = IEEE802_3and802_2Packet::new(packet) {
                let data = ieee8023_8022_packet.payload();

                if let Ok(packet) = bincode::deserialize(data) {
                    return Some(packet);
                }
            }

            None
        }
    }
}