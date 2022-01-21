use std::fmt;

#[derive(Default)]
pub struct TCPHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub ack_number: u32,
    pub header_length: u8,
    pub flags: u16,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub options: Vec<u8>,
    pub payload_length: usize,
}

impl TCPHeader {
    pub fn new(data: &[u8]) -> TCPHeader {
        let source_port = ((data[34] as u16) << 8) | data[35] as u16;
        let destination_port = ((data[36] as u16) << 8) | data[37] as u16;
        let sequence_number = ((data[38] as u32) << 24) | ((data[39] as u32) << 16) | ((data[40] as u32) << 8) | data[41] as u32;
        let ack_number = ((data[42] as u32) << 24) | ((data[43] as u32) << 16) | ((data[44] as u32) << 8) | data[45] as u32;
        let header_length = data[46];
        let flags = (((data[46] as u16) & 0x0f) << 8) | data[47] as u16;
        let window_size = ((data[48] as u16) << 8) | data[49] as u16;
        let checksum = ((data[50] as u16) << 8) | data[51] as u16;
        let urgent_pointer = ((data[54] as u16) << 8) | data[53] as u16;
        let data_left = ((header_length>>2)-21) as usize;
        let mut options = Vec::new();
        let payload_length = data.len()-(54+data_left+1);
        for i in 0..=data_left {
            options.push(data[(54+i as usize)]);
        }
        
        TCPHeader { source_port, destination_port, sequence_number, ack_number, header_length, flags, window_size, checksum, urgent_pointer, options, payload_length }
    }

    #[allow(dead_code)]
    fn is_same_sequence(&self, other: TCPHeader) -> bool {
        (self.source_port == other.destination_port && self.destination_port == other.source_port)
    }
}
impl fmt::Display for TCPHeader {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Source Port: {}\t", self.source_port)?;
        write!(f, "Destination Port: {}\t", self.destination_port)?;
        write!(f, "Sequence Number: 0x{:08X}\t", self.sequence_number)?;
        write!(f, "ACK Number: 0x{:08X}\t", self.ack_number)?;
        write!(f, "Header Length: {} Bytes\n", self.header_length>>2)?;
        write!(f, "Flags: 0x{:04X}\t", self.flags)?;
        write!(f, "Window Size: {}\t", self.window_size)?;
        write!(f, "Calculated Window Size: {}\t", (self.window_size as u32)*128)?;
        write!(f, "Checksum: 0x{:04X}\t", self.checksum)?;
        write!(f, "Urgent Pointer: 0x{:04X}\n", self.urgent_pointer)?;
        write!(f, "Options: {:02X?}\t", self.options)?;
        write!(f, "Data Length: {:02X?}", self.payload_length)
    }
}