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
    packet.read(&mut buf);

    println!("Header");
    println!("------");
    println!("{:?}", packet.header);
    println!();
    for idx in 0..packet.header.question_count {
        println!("Question");
        println!("--------");
        println!("{:?}", packet.questions[idx as usize]);
        println!();
    }
    for idx in 0..packet.header.answer_count {
        println!("Answer");
        println!("------");
        println!("{:?}", packet.answers[idx as usize]);
        println!();
    }
    for idx in 0..packet.header.nameserver_count {
        println!("Authority");
        println!("---------");
        println!("{:?}", packet.authorities[idx as usize]);
        println!();
    }
    for idx in 0..packet.header.additional_count {
        println!("Additional");
        println!("----------");
        println!("{:?}", packet.additional[idx as usize]);
        println!();
    }

}
