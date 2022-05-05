use std::fs::File;
use std::io::Read;
use std::process::{self};

use super::format;

pub struct PcapReader {
    file: File
}

impl PcapReader {
    pub fn new(fname: String) -> Self {
        let file = File::open(fname.clone());
        
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
    pub fn read_all(&mut self) -> Vec<format::PacketRecord> {
        let mut buf = vec![];

        if let Err(e) = self.file.read_to_end(&mut buf) {
            eprintln!("Fatal: Failed to open or read file");
            eprintln!("Message: {}", e);
            process::exit(exitcode::IOERR);
        }

        if !self.check_header(&buf) {
            eprintln!("Error: This file is not pcap format");
            process::exit(exitcode::USAGE);
        }

        // Since pcap header is 24 bytes, packet record is read from the 25th byte (24th byte in 0-based) from the beginning of the file.
        let mut index = 24;
        let mut res = vec![];
        while index < buf.len() {
            let mut header_buf = vec![];
            for _ in 0..16 {
                if index >= buf.len() {
                    eprintln!("Error: Malformed pcap packet header");
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

            let timestamp_sec = header.timestamp_sec;
            let timestamp_msec = header.timestamp_msec;
            let captured_packet_length = header.captured_packet_length;
            let original_packet_length = header.original_packet_length;

            let mut data = vec![];
            for _ in 0..captured_packet_length {
                if index >= buf.len() {
                    eprintln!("Error: Malformed pcap packet data");
                    process::exit(exitcode::DATAERR);
                }
                data.push(buf[index]);
                index += 1;
            }

            let record = format::PacketRecord::new(timestamp_sec, timestamp_msec, captured_packet_length, original_packet_length, &data);

            res.push(record);
        }

        res
    }
}