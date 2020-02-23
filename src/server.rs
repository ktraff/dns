use std::fs::File;
use std::env;
use std::io::Read;

use dns::packet::DnsPacket;
use dns::server::DnsServer;

fn main() {
    let args: Vec<String> = env::args().collect();
    let server = DnsServer::new().unwrap();

    loop {
        let result = server.talk().unwrap_or_else(|err| {
            eprintln!("Error communicating with client: {}", err);
            DnsPacket::new()
        });

        println!("{}", result);
    }
}
