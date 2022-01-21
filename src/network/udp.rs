use std::fmt;

#[derive(Default)]
pub struct UDPHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
}

impl UDPHeader {
    pub fn new(data: &[u8]) -> UDPHeader {
        let source_port = ((data[34] as u16) << 8) | data[35] as u16;
        let destination_port = ((data[36] as u16) << 8) | data[37] as u16;
        let length = ((data[38] as u16) << 8) | data[39] as u16;
        let checksum = ((data[40] as u16) << 8) | data[41] as u16;
        
        UDPHeader { source_port, destination_port, length, checksum }
    }

    #[allow(dead_code)]
    fn is_same_sequence(&self, other: UDPHeader) -> bool {
        (self.source_port == other.destination_port && self.destination_port == other.source_port)
    }
}
impl fmt::Display for UDPHeader {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Source Port: {}\t", self.source_port)?;
        write!(f, "Destination Port: {}\t", self.destination_port)?;
        write!(f, "Length: {} Bytes\n", self.length)?;
        write!(f, "Checksum: 0x{:04X}\t", self.checksum)
    }
}