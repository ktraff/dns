use std::fs::File;
use std::env;
use std::io::Read;

use dns::server::DnsServer;

fn main() {
    let args: Vec<String> = env::args().collect();
    let server = DnsServer::new().unwrap();

    loop {
        let result = server.talk();
        if result.is_err() {
            println!("Couldn't receive");
        } else {
            println!("{}", result.unwrap());
        }
    }
}
