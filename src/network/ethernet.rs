use std::fmt;

#[derive(Copy, Clone)]
pub struct EthernetHeader {
    // Ethernet frame headers
    pub destination_mac: [u8; 6],
    pub source_mac: [u8; 6],
    pub ether_type: u16,
}


impl EthernetHeader {
    pub fn new(data: &[u8]) -> EthernetHeader {
        let mut destination_mac: [u8; 6] = [0; 6];
        destination_mac.clone_from_slice(&data[..6]);
        let mut source_mac: [u8; 6] = [0; 6];
        source_mac.clone_from_slice(&data[6..12]);
        let ether_type = ((data[12] as u16) << 8) | data[13] as u16;

        EthernetHeader { destination_mac, source_mac, ether_type }
    }
}

impl fmt::Display for EthernetHeader {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "To: ")?;
        for i in 0..6 {
            if (i+1) % 6 == 0 {
                write!(f, "{:02X?}", self.destination_mac[i])?;    
            } else {
                write!(f, "{:02X?}:", self.destination_mac[i])?;
            }
        }
        write!(f, "\t From: ")?;
        for i in 0..6 {
            if (i+1) % 6 == 0 {
                write!(f, "{:02X?}", self.source_mac[i])?;    
            } else {
                write!(f, "{:02X?}:", self.source_mac[i])?;
            }
        }
        write!(f, "\tType 0x{:04X?}", self.ether_type)
    }
}
