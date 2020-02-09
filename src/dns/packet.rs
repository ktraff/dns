use std::io::{Result, Error, ErrorKind};

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
    pub fn from_num(&self, num: u8) -> ResponseCode {
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
    pub fn read(buf: &mut DnsBuffer) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_header() {
        assert!(true)
    }
}