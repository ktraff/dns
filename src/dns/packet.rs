use std::io::{Result, Error, ErrorKind, Read};
use std::fs::File;

use crate::buffer::DnsBuffer;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ResponseCode {
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
struct DnsHeader {
    id: u16,
    // false if it is a query, true if it is a response
    query_response: bool,
    // Usually always 0, can ignore
    opcode: u8, // 4 bits
    // Set to true if the responding server has the canonical record for the query
    authoritative_answer: bool,
    // true if the message exceeds 512 bytes and therefore needs to be reissued via TCP
    truncated_message: bool,
    recursion_desired: bool,
    recursion_available: bool,
    // Used for DNSSec, can ignore for now
    z: u8,
    // Whether the response was successful
    response_code: ResponseCode,
    // Number of DNS questions contained in the response
    question_count: u16,
    // Number of DNS answers contained in the response
    answer_count: u16,
    // Number of DNS nameservers contained in the response
    nameserver_count: u16,
    // Number of additional DNS records contained in the response
    additional_count: u16,
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
}

#[derive(Debug, PartialEq, Eq)]
enum RecordType {
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
}

#[derive(Debug, PartialEq, Eq)]
enum RecordClass {
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
}

struct DnsQuestion {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bit_shift() {
        // Bit shifting experiments to make sure my assumptions are correct
        assert_eq!(0x80 >> 4, 0x8);
        assert_eq!(0x70 >> 2, 0x1C);
    }

    #[test]
    fn test_header() {
        let mut buf = DnsBuffer::new();
        let mut f = File::open("response.txt").unwrap();
        f.read(&mut buf.buf).unwrap();

        let mut header = DnsHeader::new();
        header.read(&mut buf).unwrap();

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
        assert_eq!(buf.pos, 12);
    }

    #[test]
    fn test_question() {
        let mut buf = DnsBuffer::new();
        let mut f = File::open("response.txt").unwrap();
        f.read(&mut buf.buf).unwrap();

        let mut header = DnsHeader::new();
        header.read(&mut buf).unwrap();

        for _ in 0..header.question_count {
            let mut question = DnsQuestion::new();
            question.read(&mut buf).unwrap();

            assert_eq!(question.name, "google.com");
            assert_eq!(question.record_type, RecordType::A);
            assert_eq!(question.record_class, RecordClass::IN);
        }
    }
}