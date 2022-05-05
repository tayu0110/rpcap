use std::sync::{Mutex, Arc};
use std::option::Option;
use pnet::datalink::{
        NetworkInterface,
        DataLinkSender,
        DataLinkReceiver };
use chrono::{Local};

use super::dump;
use super::pcap;

pub struct Interface {
    interface: NetworkInterface,
    _tx: Box<dyn DataLinkSender>,
    rx: Box<dyn DataLinkReceiver>,
    pwriter: Arc<Mutex<Option<pcap::writer::PcapWriter>>>
    // preader: pcap::reader::PcapReader,
}

impl Interface {
    pub fn new(
            interface: NetworkInterface,
            _tx: Box<dyn DataLinkSender>,
            rx: Box<dyn DataLinkReceiver>,
            pwriter: Arc<Mutex<Option<pcap::writer::PcapWriter>>>) -> Self {
        Interface { interface, _tx, rx, pwriter }
    }
    fn if_name(&self) -> String {
        self.interface.name.to_string()
    }
    pub fn listen(&mut self) {
        loop {
            let if_name = self.if_name().to_owned().to_string();
            match self.rx.next() {
                Ok(data) => {
                    let time_stamp = Local::now();
                    let mut pwriter = self.pwriter.lock().unwrap();

                    match &mut *pwriter {
                        Some(pwriter) => {
                            pcap::handler::handle_write_pcap(time_stamp, data, pwriter);
                        }
                        None => {
                            dump::handler::handle_ethernet_packet(time_stamp, if_name, data);
                        }
                    }                
                },
                Err(_e) => {
                    continue;
                }
            }
        }
    }
}
