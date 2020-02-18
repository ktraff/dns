
use std::io::Result;
use std::net::UdpSocket;

use crate::buffer::DnsBuffer;
use crate::packet::DnsPacket;

pub struct DnsClient<'a> {
    pub server: (&'a str, u16),
    pub socket: UdpSocket,
}

impl DnsClient<'_> {
    pub fn new() -> Result<DnsClient<'static>> {
        Ok(DnsClient {
            server: ("8.8.8.8", 53),
            socket: UdpSocket::bind("0.0.0.0:43210")?,
        })
    }

    pub fn query(&self, buf: &DnsBuffer) -> Result<DnsPacket> {
        let bytes_written = self.socket.send_to(&buf.buf[0..buf.pos], self.server)?;
        let mut response_buf = DnsBuffer::new();
        let mut response_packet = DnsPacket::new();
        let (bytes_read, origin) = self.socket.recv_from(&mut response_buf.buf)?;

        response_packet.read(&mut response_buf)?;
        Ok(response_packet)
    }
}