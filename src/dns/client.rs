
use std::io::Result;
use std::net::UdpSocket;

use crate::buffer::DnsBuffer;
use crate::packet::DnsPacket;

pub struct DnsClient<'a> {
    pub server: (&'a str, u16),
    pub socket: UdpSocket,
}

/// Queries the Google DNS server using a provided DNS packet.
impl DnsClient<'_> {
    pub fn new() -> Result<DnsClient<'static>> {
        Ok(DnsClient {
            server: ("8.8.8.8", 53),
            socket: UdpSocket::bind("0.0.0.0:43210")?,
        })
    }

    pub fn query(&self, buf: &DnsBuffer) -> Result<DnsPacket> {
        let _bytes_written = self.socket.send_to(&buf.buf[0..buf.pos], self.server)?;
        let mut response_buf = DnsBuffer::new();
        let mut response_packet = DnsPacket::new();
        let (_bytes_read, _origin) = self.socket.recv_from(&mut response_buf.buf)?;

        response_packet.read(&mut response_buf)?;
        Ok(response_packet)
    }
}