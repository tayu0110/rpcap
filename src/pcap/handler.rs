use chrono::TimeZone;
use chrono::{Local, DateTime};

use super::reader;
use super::writer;
use super::super::dump;

pub fn handle_write_pcap(time_stamp: DateTime<Local>, data: &[u8], pwriter: &mut writer::PcapWriter) {
    let timestamp_sec = time_stamp.timestamp() as u32;
    let timestamp_msec = time_stamp.timestamp_subsec_micros();
    let captured_packet_length = data.len() as u32;
    let original_packet_length = data.len() as u32;

    pwriter.write(timestamp_sec, timestamp_msec, captured_packet_length, original_packet_length, data);
}

pub fn handle_dump_pcap(fname: String) {
    let mut preader = reader::PcapReader::new(fname);

    let recoder_all = preader.read_all();

    for record in recoder_all {
        let data = record.packet_data.as_slice();
        let time_stamp = Local.timestamp(record.header.timestamp_sec as i64, record.header.timestamp_msec * 1000);
        dump::handler::handle_ethernet_packet(time_stamp, "Unknown".to_string(), data);
    }
}