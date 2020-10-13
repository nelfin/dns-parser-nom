use std::{borrow::Cow, net::Ipv4Addr};
use std::fmt::Debug;

#[macro_use] extern crate nom;
use nom::{Err, IResult};
use nom::number::complete::{be_u8, be_u16};
use nom::bytes::complete::take;

#[derive(Debug)]
pub struct DnsHeader {
    id: u16,

    message_type: u8,
    opcode: u8,
    authoritative_answer: u8,
    truncated_message: u8,
    recursion_desired: u8,
    recursion_available: u8,
    zz: u8,  // reserved as 0
    authed_data: u8,
    checking_disabled: u8,
    rescode: u8,

    questions: u16,
    answers: u16,
    authorities: u16,
    resources: u16,
}

pub fn parse_dns_header(input: &[u8]) -> IResult<&[u8], DnsHeader> {
    do_parse!(input,
        id: be_u16 >>
        b0: bits!(tuple!(
            take_bits!(1u8), // message_type
            take_bits!(4u8), // opcode
            take_bits!(1u8), // authoritative_answer
            take_bits!(1u8), // truncated_message
            take_bits!(1u8), // recursion_desired
            take_bits!(1u8), // recursion_available
            take_bits!(1u8), // zz
            take_bits!(1u8), // authed_data
            take_bits!(1u8), // checking_disabled
            take_bits!(4u8)  // rescode
        )) >>
        questions: be_u16 >>
        answers: be_u16 >>
        authorities: be_u16 >>
        resources: be_u16 >>
        (
            DnsHeader {
                id,
                message_type: b0.0,
                opcode: b0.1,
                authoritative_answer: b0.2,
                truncated_message: b0.3,
                recursion_desired: b0.4,
                recursion_available: b0.5,
                zz: b0.6,
                authed_data: b0.7,
                checking_disabled: b0.8,
                rescode: b0.9,
                questions,
                answers,
                authorities,
                resources,
            }
        )
    )
}

pub struct Label<'a> {
    parts: Vec<Cow<'a, str>>,
}

pub enum LabelPart<'a> {
    Root,
    Regular(Cow<'a, str>),
    Backreference(usize),
}

pub fn parse_label_part<'a>(input: &'a [u8]) -> IResult<&[u8], LabelPart<'a>> {
    let (_, tag_byte) = be_u8(input)?;  // peek
    if (tag_byte & 0xC0) == 0xC0 {
        let (input, addr) = be_u16(input)?;
        let addr: usize = (addr & 0x03FF).into();
        Ok((input, LabelPart::Backreference(addr)))
    } else {
        let (input, count) = be_u8(input)?;  // TODO: assert <= 63
        if count == 0u8 {
            return Ok((input, LabelPart::Root))
        }
        let (input, parts) = take(count)(input)?;
        Ok((input, LabelPart::Regular(String::from_utf8_lossy(parts))))
    }
}

fn parse_label_inner<'a>(input: &'a [u8], start_of_packet: &'a [u8], label: Label<'a>, jumps: usize) -> IResult<&'a [u8], Label<'a>> {
    assert!(jumps < 5, "maximum number of indirections reached");
    let (input, part) = parse_label_part(input)?;
    match part {
        LabelPart::Root => Ok((&input[..0], label)),  // XXX: lying about input bytes because we may have jumped
        LabelPart::Regular(s) => {
            let mut label = label;
            label.parts.push(s);
            parse_label_inner(input, start_of_packet, label, jumps)
        }
        LabelPart::Backreference(j) => {
            // TODO: ensure jump backwards
            assert!(j < 512, "jump is longer than 512");
            parse_label_inner(&start_of_packet[j..], start_of_packet, label, jumps+1)
        }
    }
}

pub fn parse_label<'a>(input: &'a [u8], start_of_packet: &'a [u8]) -> IResult<&'a [u8], Label<'a>> {
    // TODO: enforce letters-digits-hyphen rule for allowed characters?
    let label = Label { parts: vec![] };
    parse_label_inner(input, start_of_packet, label, 0)
}

impl Debug for Label<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for part in &self.parts {
            write!(f, "{}.", part)?
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct DnsQuestion<'a> {
    qname: Label<'a>,
    qtype: u16,
}

// pub fn parse_question(input: &[u8]) -> IResult<&[u8], DnsQuestion> {
//     let (input, qname) = parse_label(input)?;
//     let (input, qtype) = be_u16(input)?;
//     let (input, _qclass) = be_u16(input)?;  // expected to be 1u16
//     Ok((input, DnsQuestion { qname, qtype }))
// }

// #[derive(Debug)]
// struct DnsRecordPreamble {
//     rname: Label,
//     rtype: u16,
//     _rclass: u16,  // ignored
//     ttl: u32,
//     length: u16,
// }

// #[derive(Debug)]
// struct DnsRecord {
//     preamble: DnsRecordPreamble,
//     body: Ipv4Addr,  // TODO!
// }

// #[derive(Default, Debug)]
// struct DnsPacket {
//     header: DnsHeader,
//     questions: Vec<DnsQuestion>,
//     answers: Vec<DnsRecord>,
//     authorities: Vec<DnsRecord>,
//     resources: Vec<DnsRecord>,
// }

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_header() {
        let bytes = include_bytes!("../examples/query.google.dns");
        if let Ok((_, actual)) = parse_dns_header(bytes) {
            println!("{:?}", actual);
            assert_eq!(actual.id, 0x5c91, "id mismatch");
            assert_eq!(actual.message_type, 0u8);
            assert_eq!(actual.questions, 1u16, "num questions mismatch");
        } else {
            panic!("fail");
        }
    }

    #[test]
    fn test_parse_label() {
        let start_of_packet = include_bytes!("../examples/query.google.dns");
        let input = &start_of_packet[12..24];
        let (rest, label) = parse_label(input, start_of_packet).unwrap();
        println!("rest: {:02x?}", rest);
        assert!(rest.len() == 0);
        assert_eq!(label.parts, vec!["google", "com"]);
    }

    #[test]
    fn test_parse_label_jump() {
        let start_of_packet = include_bytes!("../examples/response.google.dns");
        let input = &start_of_packet[28..30];
        let (rest, label) = parse_label(input, start_of_packet).unwrap();
        println!("rest: {:?}", rest);
        assert!(rest.len() == 0);
        assert_eq!(label.parts, vec!["google", "com"]);
    }
}
