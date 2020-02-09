use std::io::{Result, Error, ErrorKind, Read};
use std::fs::File;

pub struct DnsBuffer {
    pub pos: usize,
    pub buf: [u8; 512]
}

impl DnsBuffer {
    pub fn new() -> DnsBuffer {
        DnsBuffer {
            pos: 0,
            buf: [0 as u8; 512]
        }
    }

    pub fn get(&self, pos: usize) -> Result<u8> {
        if pos >= 512 {
            return Err(Error::new(ErrorKind::InvalidInput, "Position is beyond the buffer"));
        }
        Ok(self.buf[pos])
    }

    pub fn get_range(&self, pos: usize, len: usize) -> Result<&[u8]> {
        if pos + len >= 512 {
            return Err(Error::new(ErrorKind::InvalidInput, "Getting a range beyond the buffer"))
        }
        Ok(&self.buf[pos..pos + len])
    }

    pub fn seek(&mut self, pos: usize) -> Result<()> {
        if pos >= 512 {
            return Err(Error::new(ErrorKind::InvalidInput, "Seeking beyond the buffer"))
        }
        self.pos = pos;
        Ok(())
    }

    pub fn read(&mut self) -> Result<u8> {
        if self.pos >= 511 {
            return Err(Error::new(ErrorKind::InvalidInput, "Reading beyond the buffer"))
        }
        let res = self.buf[self.pos];
        self.pos += 1;
        Ok(res)
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        let res = (self.read()? as u16) << 8 |
                  (self.read()? as u16);
        Ok(res)
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        let res = (self.read()? as u32) << 24 |
                  (self.read()? as u32) << 16 |
                  (self.read()? as u32) << 8 |
                  (self.read()? as u32);
        Ok(res)
    }

    pub fn read_label(&mut self, output_str: &mut String) -> Result<()> {
        let mut pos = self.pos;
        let is_jump = false;
        let mut delimiter = "";

        loop {
            // Check to see if the next byte is a jump value
            let seek = self.get(pos)?;
            let is_jump = (seek & 0xC0) == 0xC0;
            if is_jump {
                let next = self.get(pos + 1)?;
                let jump_value = (seek as u16) ^ 0xC0 << 8 |
                                  next as u16;

                // Jump to that value.
                pos = jump_value as usize;
            } else {
                // Get the length of the next sequence.  If it is zero, we're finished.
                let len = self.get(pos)?;
                pos += 1;
                if len == 0 {
                    break;
                }
                output_str.push_str(delimiter);
                output_str.push_str(&String::from_utf8_lossy(self.get_range(pos, len as usize)?));
                // All delimiters after the first will be a period, as in google.com
                delimiter = ".";
                pos += len as usize;
            }
        }

        if is_jump {
            // Skip past the jump value
            self.seek(self.pos + 2)?;
        } else {
            self.seek(pos)?;
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        let mut f = File::open("query.txt").unwrap();
        let mut buf = DnsBuffer::new();
        f.read(&mut buf.buf).unwrap();

        assert_eq!(buf.get(0).unwrap(), 115);

        // Move to google.com
        let mut output_str = String::new();
        buf.seek(12).unwrap();
        buf.read_label(&mut output_str).unwrap();
        assert_eq!(output_str, "google.com");
    }
}