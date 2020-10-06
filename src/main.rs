use std::{net::UdpSocket, default::Default};
use std::fmt::Debug;
use std::net::Ipv4Addr;
use deku::{ctx::BitSize, prelude::*};

// parse DNS packet
// stub resolver

#[derive(Debug, Default, DekuRead, DekuWrite)]
#[deku(endian = "big")]
struct DnsHeader {
    id: u16,

    #[deku(bits = "1")] message_type: u8,
    #[deku(bits = "4")] opcode: u8,
    #[deku(bits = "1")] authoritative_answer: u8,
    #[deku(bits = "1")] truncated_message: u8,
    #[deku(bits = "1")] recursion_desired: u8,
    #[deku(bits = "1")] recursion_available: u8,
    #[deku(bits = "1")] zz: u8,  // reserved as 0
    #[deku(bits = "1")] authed_data: u8,
    #[deku(bits = "1")] checking_disabled: u8,
    #[deku(bits = "4")] rescode: u8,

    questions: u16,
    answers: u16,
    authorities: u16,
    resources: u16,
}

#[derive(DekuRead)]
struct LabelPart {
    count: u8,
    #[deku(count = "*count as usize")]
    bytes: Vec<u8>
}

#[derive(DekuRead)]
struct Label {
    #[deku(
        reader = "read_label(rest, BitSize(8))"
    )]
    parts: Vec<LabelPart>,
}

impl Debug for Label {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for part in &self.parts {
            let s = String::from_utf8(part.bytes.clone()).unwrap();
            write!(f, "{}.", s)?
        }
        Ok(())
    }
}

fn read_label(rest: &BitSlice<Msb0, u8>, _bit_size: BitSize) -> Result<(&BitSlice<Msb0, u8>, Vec<LabelPart>), DekuError> {
    // FIXME: this is really gross
    let mut value: Vec<LabelPart> = vec![];
    let mut rest = rest;
    loop {
        let (_, len) = u8::read(rest, _bit_size)?;
        if (len & 0xC0) == 0xC0 {
            todo!("handle jumps");
        }
        let parts = LabelPart::read(rest, ())?;
        rest = parts.0;
        if parts.1.count == 0 {
            break;
        }
        value.push(parts.1);
    }
    Ok((rest, value))
}

#[derive(Debug, DekuRead)]
struct DnsQuestion {
    qname: Label,
    #[deku(endian = "big")] qtype: u16,
    #[deku(endian = "big")] _qclass: u16,  // ignored
}

#[derive(Debug, DekuRead)]
struct DnsRecordPreamble {
    rname: Label,
    #[deku(endian = "big")] rtype: u16,
    #[deku(endian = "big")] _rclass: u16,  // ignored
    #[deku(endian = "big")] ttl: u32,
    #[deku(endian = "big")] length: u16,
}

#[derive(Debug, DekuRead)]
struct DnsRecord {
    preamble: DnsRecordPreamble,
    body: Ipv4Addr,  // TODO!
}

#[derive(Default, Debug, DekuRead)]
struct DnsPacket {
    header: DnsHeader,
    #[deku(count = "header.questions")]
    questions: Vec<DnsQuestion>,
    #[deku(count = "header.answers")]
    answers: Vec<DnsRecord>,
    #[deku(count = "header.authorities")]
    authorities: Vec<DnsRecord>,
    #[deku(count = "header.resources")]
    resources: Vec<DnsRecord>,
}

fn handle_query(socket: &UdpSocket) -> std::io::Result<()> {
    let mut data = [0u8; 512];
    let (n, src) = socket.recv_from(&mut data)?;
    let data = &data[..n];

    println!("bytes: {:?}", data);
    let res = DnsPacket::from_bytes((data, 0));
    let request: DnsPacket = match res {
        Ok((_, request)) => request,
        Err(e) =>  { eprintln!("error parsing: {}", e); todo!(); }
    };

    // let data = include_bytes!("../examples/response.google.dns"); // FIXME
    // let (_, mut response) = DnsPacket::from_bytes((data, 0)).unwrap();
    // response.header.id = request.header.id;
    // response.header.message_type = 1; // response
    //let resp_buf = response.to_bytes().unwrap();

    println!("request: {:?}", request);
    // println!("response: {:?}", response);
    let resp_buf = [0u8; 512];

    socket.send_to(&resp_buf, src)?;
    Ok(())
}

fn main() -> std::io::Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", 1053))?;

    loop {
        match handle_query(&socket) {
            Ok(_) => eprintln!("I: handled packet"),
            Err(e) => eprintln!("E: {}", e),
        }
    }
}
