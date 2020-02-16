use std::fs::File;
use std::env;
use std::io::Read;

use dns::buffer::DnsBuffer;
use dns::packet::DnsPacket;

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut buf = DnsBuffer::new();

    let mut packet = DnsPacket::from_query(&args[1]).unwrap();
    packet.write(&mut buf).unwrap();
}
