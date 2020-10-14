use std::{borrow::Cow, net::Ipv4Addr};
use std::fmt::Debug;

#[macro_use] extern crate nom;
use nom::{Err, IResult};
use nom::number::complete::{be_u8, be_u16, be_u32};
use nom::bytes::complete::take;
use nom::multi::count;

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
        LabelPart::Root => Ok((input, label)),
        LabelPart::Regular(s) => {
            let mut label = label;
            label.parts.push(s);
            parse_label_inner(input, start_of_packet, label, jumps)
        }
        LabelPart::Backreference(j) => {
            // TODO: ensure jump backwards
            assert!(j < 512, "jump is longer than 512");
            // We reset the input reference here to the jumped location and so discard the returned value
            // of input, instead returning input from parse_label_part, i.e. after the u16 of the backref
            let (_, label) = parse_label_inner(&start_of_packet[j..], start_of_packet, label, jumps+1)?;
            Ok((input, label))
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

pub fn parse_question<'a>(input: &'a [u8], start_of_packet: &'a [u8]) -> IResult<&'a [u8], DnsQuestion<'a>> {
    let (input, qname) = parse_label(input, start_of_packet)?;
    let (input, qtype) = be_u16(input)?;
    let (input, _qclass) = be_u16(input)?;  // expected to be 1u16
    Ok((input, DnsQuestion { qname, qtype }))
}

#[repr(u16)]
#[derive(Debug, PartialEq)]
pub enum RecordType {
    UNKNOWN,
    A = 1,
}

impl From<u16> for RecordType {
    fn from(tag: u16) -> Self {
        match tag {
            1 => RecordType::A,
            _ => RecordType::UNKNOWN,
        }
    }
}

fn parse_record_type(input: &[u8]) -> IResult<&[u8], RecordType> {
    let (input, rtype_tag) = be_u16(input)?;
    Ok((input, RecordType::from(rtype_tag)))
}

#[derive(Debug)]
pub struct DnsRecordPreamble<'a> {
    rname: Label<'a>,
    rtype: RecordType,
    ttl: u32,
    length: u16,
}

pub fn parse_record_preamble<'a>(input: &'a [u8], start_of_packet: &'a [u8]) -> IResult<&'a [u8], DnsRecordPreamble<'a>> {
    let (input, rname) = parse_label(input, start_of_packet)?;
    let (input, rtype) = parse_record_type(input)?;
    let (input, _rclass) = be_u16(input)?;  // expected to be 1u16
    let (input, ttl) = be_u32(input)?;
    let (input, length) = be_u16(input)?;
    Ok((input, DnsRecordPreamble { rname, rtype, ttl, length }))
}

#[derive(Debug)]
pub enum DnsRecord<'a> {
    UNKNOWN { preamble: DnsRecordPreamble<'a> },
    A       { preamble: DnsRecordPreamble<'a>, ipv4: Ipv4Addr },
}

pub fn parse_record<'a>(input: &'a [u8], start_of_packet: &'a [u8]) -> IResult<&'a [u8], DnsRecord<'a>> {
    let (input, preamble) = parse_record_preamble(input, start_of_packet)?;
    match preamble.rtype {
        RecordType::UNKNOWN => {
            let (input, _) = take(preamble.length)(input)?;
            Ok((input, DnsRecord::UNKNOWN { preamble }))
        },
        RecordType::A => {
            let (input, ipv4) = be_u32(input)?;
            Ok((input, DnsRecord::A { preamble, ipv4: Ipv4Addr::from(ipv4) }))
        }
    }
}

#[derive(Debug)]
pub struct DnsPacket<'a> {
    header: DnsHeader,
    questions: Vec<DnsQuestion<'a>>,
    answers: Vec<DnsRecord<'a>>,
    authorities: Vec<DnsRecord<'a>>,
    resources: Vec<DnsRecord<'a>>,
}

pub fn parse_packet<'a>(input: &'a [u8], start_of_packet: &'a [u8]) -> IResult<&'a [u8], DnsPacket<'a>> {
    let (input, header) = parse_dns_header(input)?;
    // FIXME: convert these to usize on input?
    let (input, questions) = count(|i| parse_question(i, start_of_packet), header.questions.into())(input)?;
    let (input, answers) = count(|i| parse_record(i, start_of_packet), header.answers.into())(input)?;
    let (input, authorities) = count(|i| parse_record(i, start_of_packet), header.authorities.into())(input)?;
    let (input, resources) = count(|i| parse_record(i, start_of_packet), header.resources.into())(input)?;

    Ok((input, DnsPacket {
        header,
        questions,
        answers,
        authorities,
        resources,
    }))
}

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

    #[test]
    fn test_parse_question() {
        let start_of_packet = include_bytes!("../examples/query.google.dns");
        let input = &start_of_packet[12..];
        let (rest, question) = parse_question(input, start_of_packet).unwrap();
        assert!(rest.len() == 0);
        assert!(question.qtype == 1u16);
        assert_eq!(question.qname.parts, vec!["google", "com"]);
    }

    #[test]
    fn test_parse_simple_record() {
        let start_of_packet = include_bytes!("../examples/response.google.dns");
        let input = &start_of_packet[28..];
        println!("input: {:x?}", input);
        let res = parse_record_preamble(input, start_of_packet);
        assert!(res.is_ok());
        let (rest, record) = res.unwrap();
        println!("record: {:?}", record);
        assert!(rest.len() == 4); // IP left over
        assert!(record.rtype == RecordType::A);
        assert!(record.rname.parts == vec!["google", "com"]);  // TODO
    }

    #[test]
    fn test_full_A_record() {
        let start_of_packet = include_bytes!("../examples/response.ai.");
        let input = &start_of_packet[0x14..];
        let res = parse_record(input, start_of_packet);
        assert!(res.is_ok());
        let (rest, record) = res.unwrap();
        assert!(rest.len() == 0);
        if let DnsRecord::A { preamble, ipv4 } = record {
            assert!(preamble.rname.parts == vec!["ai"]);
            assert_eq!(ipv4, Ipv4Addr::new(209, 59, 119, 34));
        } else {
            assert!(false, "wrong record type");
        }
    }

    #[test]
    fn test_parse_full_query() {
        let start_of_packet = include_bytes!("../examples/query.ai.");
        let input = &start_of_packet[..];
        let res = parse_packet(input, start_of_packet);
        assert!(res.is_ok());
        let (rest, packet) = res.unwrap();
        assert!(rest.len() == 0);
        assert_eq!(packet.header.questions, 1);
        let q = &packet.questions[0];
        assert_eq!(q.qname.parts, vec!["ai"]);
    }

    #[test]
    fn test_parse_full_response() {
        let start_of_packet = include_bytes!("../examples/response.ai.");
        let input = &start_of_packet[..];
        let res = parse_packet(input, start_of_packet);
        assert!(res.is_ok());
        let (rest, packet) = res.unwrap();
        assert!(rest.len() == 0);
        assert_eq!(packet.header.questions, 1);
        let q = &packet.questions[0];
        assert_eq!(q.qname.parts, vec!["ai"]);
        assert_eq!(packet.header.answers, 1);
        let a = &packet.answers[0];
        if let DnsRecord::A { preamble, ipv4 } = a {
            assert_eq!(preamble.rname.parts, vec!["ai"]);
            assert_eq!(*ipv4, Ipv4Addr::new(209, 59, 119, 34));
        } else {
            assert!(false, "invalid parse");
        }
    }
}
