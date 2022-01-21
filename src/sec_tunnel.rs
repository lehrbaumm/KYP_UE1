use std::fmt;

#[derive(Default)]
pub struct SecureTunnelHeader {
    pub sender: String,
    pub receiver: String,
    pub len: usize
}
impl fmt::Display for SecureTunnelHeader {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "From: {}\t", self.sender)?;
        write!(f, "To: {}\t", self.receiver)?;
        write!(f, "Length: {}\n", self.len)
    }
}

#[derive(Default)]//b':'.join([self.hdr, bytes(str(len(parts_enc)), 'ascii'), self.nonce, self.tail])
pub struct SecureTunnelConfig {
    pub header: String,
    pub count: u32,
    pub nonce: [u8; 8],
    pub tail: String
}
impl fmt::Display for SecureTunnelConfig {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Header: {}\t", self.header)?;
        write!(f, "Count: {}\n", self.count)?;
        write!(f, "Nonce: {:02X?}\t", self.nonce)?;
        write!(f, "Tail: {}\t", self.tail)
    }
}

#[derive(Default)]//b':'.join([self.hdr, bytes(str(i), 'ascii'), part, self.tail, hmac(part, self.key)])
pub struct SecureTunnelPayload {
    pub header: String,
    pub counter: u32,
    pub ciphertext: Vec<u8>,
    pub tail: String,
    pub hmac: [u8; 16]
}
impl fmt::Display for SecureTunnelPayload {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Header: {}\t", self.header)?;
        write!(f, "Counter: {}\n", self.counter)?;
        write!(f, "Ciphertext: {:02X?}\n", self.ciphertext)?;
        write!(f, "Tail: {}\t", self.tail)?;
        write!(f, "HMAC: {:02X?}\t", self.hmac)
    }
}