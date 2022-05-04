use chrono::{Local, DateTime};

use super::writer;

pub fn handle_pcap(time_stamp: DateTime<Local>, data: &[u8], pwriter: &mut writer::PcapWriter) {
    let timestamp_sec = time_stamp.timestamp() as u32;
    let timestamp_msec = time_stamp.timestamp_subsec_micros();
    let captured_packet_length = data.len() as u32;
    let original_packet_length = data.len() as u32;

    pwriter.write(timestamp_sec, timestamp_msec, captured_packet_length, original_packet_length, data);
}