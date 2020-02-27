use std::io::{Result, Error, ErrorKind, Read};
use std::fs::File;

/// Handles all the reading and writing of DNS packets.
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

    pub fn get_u16(&self, pos: usize) -> Result<u16> {
        let res = (self.get(pos)? as u16) << 8 |
                  (self.get(pos + 1)? as u16);
        Ok(res)
    }

    pub fn get_u32(&self, pos: usize) -> Result<u32> {
        let res = (self.get(pos)? as u32) << 24 |
                  (self.get(pos + 1)? as u32) << 16 |
                  (self.get(pos + 2)? as u32) << 8 |
                  (self.get(pos + 3)? as u32);
        Ok(res)
    }

    pub fn set(&mut self, pos: usize, val: u8) -> Result<()> {
        if pos >= 512 {
            return Err(Error::new(ErrorKind::InvalidInput, "Set position is beyond the buffer"));
        }
        self.buf[pos] = val;
        Ok(())
    }

    pub fn set_u16(&mut self, pos: usize, val: u16) -> Result<()> {
        self.set(pos,(val >> 8) as u8)?;
        self.set(pos + 1, (val & 0xFF) as u8)?;
        Ok(())
    }

    /// Reads a DNS label sequence, such as google.com, without advancing
    /// the position of the buffer.
    pub fn get_label(&mut self, pos: usize) -> Result<String> {
        let tmp_pos = self.pos;
        self.pos = pos;
        let mut output_str = String::new();
        self.read_label(&mut output_str)?;
        self.pos = tmp_pos;
        Ok(String::from(output_str))
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
        if self.pos >= 512 {
            return Err(Error::new(ErrorKind::InvalidInput, "Reading beyond the buffer"))
        }
        let res = self.buf[self.pos];
        self.pos += 1;
        Ok(res)
    }

    pub fn write(&mut self, byte: u8) -> Result<()> {
        if self.pos >= 512 {
            return Err(Error::new(ErrorKind::InvalidInput, "Writing beyond the buffer"))
        }
        self.buf[self.pos] = byte;
        self.pos += 1;
        Ok(())
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        let res = (self.read()? as u16) << 8 |
                  (self.read()? as u16);
        Ok(res)
    }

    pub fn write_u16(&mut self, bytes: u16) -> Result<()> {
        let b1 = (bytes >> 8) as u8;
        let b2 = (bytes & 0xFF) as u8;
        self.write(b1)?;
        self.write(b2)?;
        Ok(())
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        let res = (self.read()? as u32) << 24 |
                  (self.read()? as u32) << 16 |
                  (self.read()? as u32) << 8 |
                  (self.read()? as u32);
        Ok(res)
    }

    pub fn write_u32(&mut self, bytes: u32) -> Result<()> {
        let b1 = ((bytes >> 24) & 0xFF) as u8;
        let b2 = ((bytes >> 16) & 0xFF) as u8;
        let b3 = ((bytes >> 8) & 0xFF) as u8;
        let b4 = (bytes & 0xFF) as u8;
        self.write(b1)?;
        self.write(b2)?;
        self.write(b3)?;
        self.write(b4)?;
        Ok(())
    }

    pub fn read_label(&mut self, output_str: &mut String) -> Result<()> {
        let mut pos = self.pos;
        let mut is_jump = false;
        let mut delimiter = "";

        loop {
            // Check to see if the next byte is a jump value.  A jump value
            // will always begin with 2 1-bits, followed by the jump position.
            let seek = self.get(pos)?;
            let is_jump_cur = (seek & 0xC0) == 0xC0;
            if is_jump_cur {
                if !is_jump {
                    is_jump = true;
                    // Move to the jump point, if we are not parsing
                    // a label at a jump position
                    self.seek(pos)?;
                }
                let next = self.get(pos + 1)?;
                let jump_value = seek ^ 0xC0;
                let jump_value = (jump_value as u16) << 8 | (next as u16);

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

    pub fn write_label(&mut self, label: &str) -> Result<()> {
        for part in label.split('.') {
            let len = part.len();
            self.write(len as u8)?;
            for byte in part.as_bytes() {
                self.write(*byte)?;
            }
        }
        self.write(0)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bit_shift() {
        assert_eq!(8 & 0xFF, 8 & 0x0F);
        assert_eq!(17, 0x11);
        assert_ne!(17 & 0xFF, 17 & 0x0F);
    }

    #[test]
    fn test_read() {
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

    #[test]
    fn test_write() {
        let mut buf = DnsBuffer::new();
        buf.write(1).unwrap();
        assert_eq!(buf.get(0).unwrap(), 1);
        buf.write_u16(2).unwrap();
        assert_eq!(buf.get_u16(1).unwrap(), 2);
        buf.write_u16(3).unwrap();
        assert_eq!(buf.get_u16(3).unwrap(), 3);
        buf.write_u32(4).unwrap();
        assert_eq!(buf.get_u32(5).unwrap(), 4);
        buf.write_label("google.com").unwrap();
        assert_eq!(buf.get_label(9).unwrap(), "google.com");
    }
}