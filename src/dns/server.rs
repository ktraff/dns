
use std::io::Result;
use std::net::UdpSocket;

use crate::buffer::DnsBuffer;
use crate::packet::{DnsPacket, ResponseCode};
use crate::client::DnsClient;

pub struct DnsServer {
    pub socket: UdpSocket,
}

impl DnsServer {
    pub fn new() -> Result<DnsServer> {
        Ok(DnsServer {
            socket: UdpSocket::bind("0.0.0.0:10053")?,
        })
    }

    pub fn talk(&self) -> Result<DnsPacket> {
        let mut query_buffer = DnsBuffer::new();
        let (_, src) = self.socket.recv_from(&mut query_buffer.buf)?;
        let mut query_packet = DnsPacket::new();

        query_packet.read(&mut query_buffer)?;

        let mut response_packet = DnsPacket::new();
        response_packet.header.id = query_packet.header.id;
        response_packet.header.recursion_desired = true;

        if query_packet.questions.is_empty() {
            response_packet.header.response_code = ResponseCode::FORMERR;
        } else {
            let client = DnsClient::new()?;
            let mut buf = DnsBuffer::new();
            response_packet.header.question_count = 1;
            response_packet.questions.push(query_packet.questions[0].clone());
            response_packet.write(&mut buf)?;
            response_packet = client.query(&buf)?;
        }

        response_packet.header.recursion_available = true;
        response_packet.header.query_response = true;
        let mut response_buffer = DnsBuffer::new();
        response_packet.write(&mut response_buffer)?;
        self.socket.send_to(&response_buffer.buf[0..response_buffer.pos], src)?;
        Ok(response_packet)
    }
}