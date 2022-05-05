use std::fmt::Debug;
use std::thread;
use std::option::Option;
use std::sync::{Mutex, Arc};
use std::process::{self};
use pnet::datalink::{
        self,
        Config,
        Channel::Ethernet };
use clap::Parser;

pub mod interface;
use interface::Interface;
pub mod pcap;
pub mod dump;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, help = "Specify interfaces to listen")]
    interface: Option<String>,
    #[clap(short, long, help = "Input file name, pcap format is only allowed", value_name = "FILE")]
    read_from: Option<String>,
    #[clap(short, long, help = "Output file name", value_name = "FILE")]
    write_to: Option<String>
}

fn main() {
    let args = Args::parse();
    
    let (pwriter, wflag) = match args.write_to {
        Some(fname) => (Arc::new(Mutex::new(Some(pcap::writer::PcapWriter::new(fname)))), true),
        None => (Arc::new(Mutex::new(None)), false)
    };

    if let Some(fname) = args.read_from {
        if wflag {
            eprintln!("Error: Cannot specify both read-from and write-to options at the same time");
            process::exit(exitcode::USAGE);
        }
        pcap::handler::handle_dump_pcap(fname);
        process::exit(exitcode::OK);
    }
    
    let mut channels = vec![];
    match args.interface {
        Some(interfaces) => {
            for selected_if in interfaces.split(',') {
                let mut is_found = false;
                for interface in datalink::interfaces() {
                    if selected_if == interface.name {
                        let mut configuration: Config = Default::default();
                        configuration.promiscuous = true;
                        match datalink::channel(&interface, configuration) {
                            Ok(Ethernet(tx, rx)) => {
                                let pwriter = Arc::clone(&pwriter);
                                channels.push(Interface::new(interface, tx, rx, pwriter));
                            }
                            Ok(_) => {
                                eprintln!("Fatal: Unhandled channel type");
                                eprintln!("rpcap supports only Ethernet. \"{}\" may not be an Ethernet interface...", selected_if);
                                process::exit(exitcode::IOERR);
                            }
                            Err(e) => {
                                eprintln!("Fatal: Could not open interface \"{}\"", &selected_if);
                                eprintln!("Message: {}", e);
                                process::exit(exitcode::IOERR);
                            }
                        };
                        is_found = true;
                        break;
                    }
                }
                if !is_found {
                    eprintln!("Error: \"{}\" is not found", &selected_if);
                    process::exit(exitcode::USAGE);
                }
            }
        }
        None => {
            for interface in datalink::interfaces() {
                let mut configuration: Config = Default::default();
                configuration.promiscuous = true;
                match datalink::channel(&interface, configuration) {
                    Ok(Ethernet(tx, rx)) => {
                        let pwriter = Arc::clone(&pwriter);
                        channels.push(Interface::new(interface, tx, rx, pwriter));
                    }
                    Ok(_) => {
                        eprintln!("Fatal: Unhandled channel type");
                        process::exit(exitcode::IOERR);
                    }
                    Err(e) => {
                        eprintln!("Fatal: Could not open interface \"{}\"", interface.name);
                        eprintln!("Message: {}", e);
                        process::exit(exitcode::IOERR);
                    }
                };
            }
        }
    }
    
    let mut thread_handles = vec![];
    for mut c in channels {
        thread_handles.push(thread::spawn(move || {
            c.listen();
        }));
    }

    for handle in thread_handles {
        handle.join().unwrap();
    }
}
