use std::fs::File;
use std::io::Read;
use std::process::{self};

use super::format;

pub struct PcapReader {
    file: File
}

impl PcapReader {
    pub fn new(fname: String) -> Self {
        let file = File::create(fname.clone());
        
        match file {
            Ok(file) => PcapReader { file },
            Err(e) => {
                eprintln!("Fatal: Could not create the file \"{}\"", &fname);
                eprintln!("Message: {}", e);
                process::exit(exitcode::CANTCREAT);
            }
        }
    }
    fn check_header(&self, buf: &Vec<u8>) -> bool {
        if buf.len() < 24 {
            return false;
        }

        let mut header_buf = vec![];
        for i in 0..24 {
            header_buf.push(buf[i]);
        }
        let header = match bincode::deserialize::<format::PcapHeader>(&buf) {
            Ok(header) => header,
            Err(e) => {
                eprintln!("Fatal: Internal Error is occured.");
                eprintln!("Message: {}", &e);
                process::exit(exitcode::DATAERR);
            }
        };

        header.get_magic_number() == 0xA1B2C3D4 || header.get_magic_number() == 0xA1B23C4D
    }
    pub fn read_all(&mut self) -> Vec<Vec<u8>> {
        let mut buf = vec![];
        self.file.read_to_end(&mut buf).unwrap();

        if !self.check_header(&buf) {
            eprintln!("Error: This file is not pcap format");
            process::exit(exitcode::USAGE);
        }

        let mut index = 25;
        let mut res = vec![];
        while index < buf.len() {
            let mut header_buf = vec![];
            for _ in 0..16 {
                if index >= buf.len() {
                    eprintln!("Error: Malformed pcap file");
                    process::exit(exitcode::DATAERR);
                }
                header_buf.push(buf[index]);
                index += 1;
            }

            let header = match bincode::deserialize::<format::PacketRecordHeader>(&header_buf) {
                Ok(header) => header,
                Err(e) => {
                    eprintln!("Fatal: Internal Error is occured");
                    eprintln!("Message: {}", e);
                    process::exit(exitcode::DATAERR);
                }
            };

            let data_len = header.get_captured_packet_length();
            let mut data = vec![];
            for _ in 0..data_len {
                if index >= buf.len() {
                    eprintln!("Error: Malformed pcap file");
                    process::exit(exitcode::DATAERR);
                }
                data.push(buf[index]);
                index += 1;
            }

            res.push(data);
        }

        res
    }
}