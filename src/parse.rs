use std::fs::File;
use std::env;
use std::io::Read;

use dns::buffer::DnsBuffer;
use dns::packet::DnsPacket;

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut buf = DnsBuffer::new();
    let mut f = File::open(&args[1]).unwrap();
    f.read(&mut buf.buf).unwrap();

    let mut packet = DnsPacket::new();
    packet.read(&mut buf).unwrap();

    println!("{}", packet);

}
