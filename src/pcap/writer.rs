use std::fs::File;
use std::io::Write;
use std::process::{self};
use exitcode;

use super::format;

pub struct PcapWriter {
    file: File
}

impl PcapWriter {
    pub fn new(fname: String) -> Self {
        let file = File::create(fname.clone());
        
        match file {
            Ok(mut file) => {
                PcapWriter::write_header(&mut file);
                PcapWriter { file }
            }
            Err(e) => {
                eprintln!("Fatal: Could not create the file \"{}\"", &fname);
                eprintln!("Message: {}", e);
                process::exit(exitcode::CANTCREAT);
            }
        }
    }
    fn write_header(file: &mut File) {
        let header = format::PcapHeader::new();
        let buf_res = bincode::serialize(&header);
        
        let buf = match buf_res {
            Ok(buf) => buf,
            Err(e) => {
                eprintln!("Fatal: Internal Error");
                eprintln!("Message: {}", e);
                process::exit(exitcode::DATAERR);
            }
        };
    
        let status = file.by_ref().write(&buf);

        match status {
            Ok(_) => return,
            Err(e) => {
                eprintln!("Fatal: Failed to write data to output file");
                eprintln!("Message: {}", e);
                process::exit(exitcode::IOERR);
            }
        }
    }
    pub fn write(&mut self, timestamp_sec: u32, timestamp_msec: u32, captured_packet_length: u32, original_packet_length: u32, data: &[u8]) {
        let record_header = format::PacketRecordHeader::new(timestamp_sec, timestamp_msec, captured_packet_length, original_packet_length);
        let buf_res = bincode::serialize(&record_header);

        let buf = match buf_res {
            Ok(buf) => buf,
            Err(e) => {
                eprintln!("Fatal: Internal Error");
                eprintln!("Message: {}", e);
                process::exit(exitcode::DATAERR);
            }
        };

        if let Err(e) = self.file.by_ref().write(buf.as_slice()) {
            eprintln!("Fatal: Failed to write data to output file");
            eprintln!("Message: {}", e);
            process::exit(exitcode::IOERR);
        }

        if let Err(e) = self.file.by_ref().write(data) {
            eprintln!("Fatal: Failed to write data to output file");
            eprintln!("Message: {}", e);
            process::exit(exitcode::IOERR);
        }
    }
}
