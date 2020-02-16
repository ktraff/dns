use std::io::{Result, Read};
use std::fs::File;
use std::net::Ipv4Addr;

use crate::buffer::DnsBuffer;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResponseCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
}

impl ResponseCode {
    pub fn from_num(num: u8) -> ResponseCode {
        match num {
            0 => ResponseCode::NOERROR,
            1 => ResponseCode::FORMERR,
            2 => ResponseCode::SERVFAIL,
            3 => ResponseCode::NXDOMAIN,
            4 => ResponseCode::NOTIMP,
            _ => ResponseCode::NOERROR
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DnsHeader {
    pub id: u16,
    // false if it is a query, true if it is a response
    pub query_response: bool,
    // Usually always 0, can ignore
    pub opcode: u8, // 4 bits
    // Set to true if the responding server has the canonical record for the query
    pub authoritative_answer: bool,
    // true if the message exceeds 512 bytes and therefore needs to be reissued via TCP
    pub truncated_message: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    // Used for DNSSec, can ignore for now
    pub z: u8,
    // Whether the response was successful
    pub response_code: ResponseCode,
    // Number of DNS questions contained in the response
    pub question_count: u16,
    // Number of DNS answers contained in the response
    pub answer_count: u16,
    // Number of DNS nameservers contained in the response
    pub nameserver_count: u16,
    // Number of additional DNS records contained in the response
    pub additional_count: u16,
}

impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0,
            query_response: false,
            opcode: 0,
            authoritative_answer: false,
            truncated_message: false,
            recursion_desired: false,
            recursion_available: false,
            z: 0,
            response_code: ResponseCode::NOERROR,
            question_count: 0,
            answer_count: 0,
            nameserver_count: 0,
            additional_count: 0
        }
    }

    pub fn read(&mut self, buf: &mut DnsBuffer) -> Result<()> {
        self.id = buf.read_u16()?;

        let cur = buf.read()?;
        self.query_response = cur & 0x80 == 0x80;
        self.opcode = (cur & 0x78) >> 3;
        self.authoritative_answer = cur & 0x04 == 0x4;
        self.truncated_message = cur & 0x02 == 0x02;
        self.recursion_desired = cur & 0x01 == 0x01;

        let cur = buf.read()?;
        self.recursion_available = cur & 0x80 == 0x80;
        self.z = (cur & 0x70) >> 4;
        self.response_code = ResponseCode::from_num(cur & 0x0F);

        self.question_count = buf.read_u16()?;
        self.answer_count = buf.read_u16()?;
        self.nameserver_count = buf.read_u16()?;
        self.additional_count = buf.read_u16()?;

        Ok(())
    }

    pub fn write(&self, buf: &mut DnsBuffer) -> Result<()> {
        buf.write_u16(self.id)?;

        let mut byte = 0 as u8;
        // TODO
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum RecordType {
    UNKNOWN = 0,
    A = 1,
    NS = 2,
    CNAME = 5,
}

impl RecordType {
    pub fn from_num(num: u16) -> RecordType {
        match num {
            1 => RecordType::A,
            2 => RecordType::NS,
            5 => RecordType::CNAME,
            _ => RecordType::UNKNOWN,
        }
    }

    pub fn to_num(&self) -> u16 {
        match *self {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::CNAME => 5,
            _ => 0,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum RecordClass {
    UNKNOWN = 0,
    IN = 1,
    MX = 15,
}

impl RecordClass {
    pub fn from_num(num: u16) -> RecordClass {
        match num {
            1 => RecordClass::IN,
            15 => RecordClass::MX,
            _ => RecordClass::UNKNOWN,
        }
    }

    pub fn to_num(&self) -> u16 {
        match *self {
            RecordClass::IN => 1,
            RecordClass::MX => 15,
            _ => 0
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DnsQuestion {
    name: String,
    record_type: RecordType,
    record_class: RecordClass,
}

impl DnsQuestion {
    pub fn new() -> DnsQuestion {
        DnsQuestion {
            name: String::new(),
            record_type: RecordType::UNKNOWN,
            record_class: RecordClass::UNKNOWN,
        }
    }

    pub fn read(&mut self, buf: &mut DnsBuffer) -> Result<()> {
        let mut output_str = String::new();
        buf.read_label(&mut output_str)?;
        self.name = output_str;
        self.record_type = RecordType::from_num(buf.read_u16()?);
        self.record_class = RecordClass::from_num(buf.read_u16()?);
        
        Ok(())
    }

    pub fn write(&self, buf: &mut DnsBuffer) -> Result<()> {
        buf.write_label(&self.name[..])?;
        buf.write_u16(self.record_type.to_num())?;
        buf.write_u16(self.record_class.to_num())?;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DnsRecordPreamble {
    name: String,
    record_type: RecordType,
    record_class: RecordClass,
    ttl: u32,
    length: u16,
}

impl DnsRecordPreamble {
    pub fn new() -> DnsRecordPreamble {
        DnsRecordPreamble {
            name: String::new(),
            record_type: RecordType::UNKNOWN,
            record_class: RecordClass::UNKNOWN,
            ttl: 0,
            length: 0
        }
    }
    pub fn read(&mut self, buf: &mut DnsBuffer) -> Result<()> {
        let mut output_str = String::new();
        buf.read_label(&mut output_str)?;
        self.name = output_str;
        self.record_type = RecordType::from_num(buf.read_u16()?);
        self.record_class = RecordClass::from_num(buf.read_u16()?);
        self.ttl = buf.read_u32()?;
        self.length = buf.read_u16()?;
        Ok(())
    }

    pub fn write(&self, buf: &mut DnsBuffer) -> Result<()> {
        buf.write_label(&self.name[..])?;
        buf.write_u16(self.record_type.to_num())?;
        buf.write_u16(self.record_class.to_num())?;
        buf.write_u32(self.ttl)?;
        buf.write_u16(self.length)?;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum DnsRecordBody {
    UNKNOWN {
        record_type: u16
    },
    A {
        address: Ipv4Addr
    }
}

impl DnsRecordBody {

    /// Reads the DNS record body based on the record type provided by the record preamble.
    pub fn read(&mut self, record_type: &RecordType, buf: &mut DnsBuffer) -> Result<DnsRecordBody> {
        match *record_type {
            RecordType::A => {
                Ok(DnsRecordBody::A {
                    address: Ipv4Addr::new(buf.read()?, buf.read()?, buf.read()?, buf.read()?)
                })
            }
            _ => {
                Ok(DnsRecordBody::UNKNOWN {
                    record_type: record_type.to_num()
                })
            }
        }
    }

    pub fn write(&self, buf: &mut DnsBuffer) -> Result<()> {
        match self {
            DnsRecordBody::A { address } => {
                buf.write(address.octets()[0])?;
                buf.write(address.octets()[1])?;
                buf.write(address.octets()[2])?;
                buf.write(address.octets()[3])?;
            },
            // TODO: other record types
            _ => {

            }
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DnsRecord {
    preamble: DnsRecordPreamble,
    body: DnsRecordBody
}

impl DnsRecord {
    pub fn new() -> DnsRecord {
        DnsRecord {
            preamble: DnsRecordPreamble::new(),
            body: DnsRecordBody::UNKNOWN {
                record_type: 0
            }
        }
    }

    pub fn read(&mut self, buf: &mut DnsBuffer) -> Result<()> {
        self.preamble.read(buf)?;
        self.body = self.body.read(&self.preamble.record_type, buf)?;
        Ok(())
    }

    pub fn write(&self, buf: &mut DnsBuffer) -> Result<()> {
        self.preamble.write(buf)?;
        self.body.write(buf)?;
        Ok(())
    }
}

pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additional: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additional: Vec::new(),
        }
    }

    pub fn read(&mut self, buf: &mut DnsBuffer) -> Result<()> {
        self.header.read(buf)?;

        for _ in 0..self.header.question_count {
            let mut question = DnsQuestion::new();
            question.read(buf)?;
            self.questions.push(question);
        }

        for _ in 0..self.header.answer_count {
            let mut answer = DnsRecord::new();
            answer.read(buf)?;
            self.answers.push(answer);
        }

        for _ in 0..self.header.nameserver_count {
            let mut ns = DnsRecord::new();
            ns.read(buf)?;
            self.authorities.push(ns);
        }

        for _ in 0..self.header.additional_count {
            let mut record = DnsRecord::new();
            record.read(buf)?;
            self.additional.push(record);
        }
        Ok(())
    }

    pub fn from_query(hostname: &String) -> Result<DnsPacket> {
        let mut packet = DnsPacket::new();
        packet.header.recursion_desired = true;

        let mut question = DnsQuestion::new();
        question.name = String::from(hostname);
        question.record_type =  RecordType::A;
        question.record_class =  RecordClass::IN;
        packet.questions.push(question);

        Ok(packet)
    }

    pub fn write(&self, buf: &mut DnsBuffer) -> Result<()> {
        self.header.write(buf)?;

        for idx in 0..self.header.question_count {
            self.questions[idx as usize].write(buf)?;
        }

        for idx in 0..self.header.answer_count {
            self.answers[idx as usize].write(buf)?;
        }
        
        for idx in 0..self.header.nameserver_count {
            self.authorities[idx as usize].write(buf)?;
        }
        
        for idx in 0..self.header.nameserver_count {
            self.additional[idx as usize].write(buf)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_header(header: &DnsHeader) {
        assert_eq!(header.id, 29600);
        assert_eq!(header.query_response, true);
        assert_eq!(header.opcode, 0);
        assert_eq!(header.authoritative_answer, false);
        assert_eq!(header.truncated_message, false);
        assert_eq!(header.recursion_desired, true);
        assert_eq!(header.recursion_available, true);
        assert_eq!(header.z, 0);
        assert_eq!(header.response_code, ResponseCode::NOERROR);
        assert_eq!(header.question_count, 1);
        assert_eq!(header.answer_count, 1);
        assert_eq!(header.nameserver_count, 0);
        assert_eq!(header.additional_count, 0);
    }

    #[test]
    fn test_bit_shift() {
        // Bit shifting experiments to make sure my assumptions are correct
        assert_eq!(0x80 >> 4, 0x8);
        assert_eq!(0x70 >> 2, 0x1C);
    }

    #[test]
    fn test_parse() {
        let mut buf = DnsBuffer::new();
        let mut f = File::open("response.txt").unwrap();
        f.read(&mut buf.buf).unwrap();

        let mut header = DnsHeader::new();
        header.read(&mut buf).unwrap();

        assert_header(&header);
        assert_eq!(buf.pos, 12);

        for _ in 0..header.question_count {
            let mut question = DnsQuestion::new();
            question.read(&mut buf).unwrap();

            assert_eq!(question.name, "google.com");
            assert_eq!(question.record_type, RecordType::A);
            assert_eq!(question.record_class, RecordClass::IN);
        }
        assert_eq!(buf.pos, 28);

        for _ in 0..header.answer_count {
            let mut answer = DnsRecord::new();
            answer.read(&mut buf).unwrap();

            assert_eq!(answer.preamble.name, "google.com");
            assert_eq!(answer.preamble.record_type, RecordType::A);
            assert_eq!(answer.preamble.record_class, RecordClass::IN);
            assert_eq!(answer.preamble.ttl, 64);
            assert_eq!(answer.preamble.length, 4);
            match answer.body {
                DnsRecordBody::A {address} => {
                    assert_eq!(address, Ipv4Addr::new(172, 217, 14, 238));
                },
                _ => {
                    panic!("The A record should have an ip address");
                }
            }
        }
    }

    #[test]
    fn test_parse_packet() {
        let mut buf = DnsBuffer::new();
        let mut f = File::open("response.txt").unwrap();
        f.read(&mut buf.buf).unwrap();

        let mut packet = DnsPacket::new();
        packet.read(&mut buf);
        assert_header(&packet.header);

        assert_eq!(packet.header.question_count, 1);
        assert_eq!(packet.questions[0].name, "google.com");
        assert_eq!(packet.questions[0].record_type, RecordType::A);
        assert_eq!(packet.questions[0].record_class, RecordClass::IN);


        assert_eq!(packet.answers[0].preamble.name, "google.com");
        assert_eq!(packet.answers[0].preamble.record_type, RecordType::A);
        assert_eq!(packet.answers[0].preamble.record_class, RecordClass::IN);
        assert_eq!(packet.answers[0].preamble.ttl, 64);
        assert_eq!(packet.answers[0].preamble.length, 4);
        match packet.answers[0].body {
            DnsRecordBody::A {address} => {
                assert_eq!(address, Ipv4Addr::new(172, 217, 14, 238));
            },
            _ => {
                panic!("The A record should have an ip address");
            }
        }

        assert_eq!(packet.header.nameserver_count, 0);
        assert_eq!(packet.header.additional_count, 0);
    }
}