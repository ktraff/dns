use std::fs::File;
use std::env;
use std::io::Read;

use dns::buffer::DnsBuffer;
use dns::packet::DnsPacket;
use dns::client::DnsClient;

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut buf = DnsBuffer::new();
    let mut query_type = String::from("A");
    if args.len() > 2 {
        query_type = String::from(&args[2]);
    }

    let packet = DnsPacket::from_query(&args[1], &query_type).unwrap();
    packet.write(&mut buf).unwrap();

    let client = DnsClient::new().unwrap();
    let response_packet = client.query(&buf).unwrap();

    println!("{}", response_packet);
}
