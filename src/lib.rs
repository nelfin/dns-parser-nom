use std::net::Ipv4Addr;
use std::fmt::Debug;

#[macro_use] extern crate nom;
use nom::{Err, IResult};
use nom::number::complete::{be_u8, be_u16};
use nom::bytes::complete::take;
use nom::multi::many_till;

fn _blah() {
    todo!();
    // FIXME: this is really gross
    // let mut value: Vec<LabelPart> = vec![];
    // let mut rest = rest;
    // loop {
    //     let (_, len) = u8::read(rest, _bit_size)?;
    //     if (len & 0xC0) == 0xC0 {
    //         todo!("handle jumps");
    //     }
    //     let parts = LabelPart::read(rest, ())?;
    //     rest = parts.0;
    //     if parts.1.count == 0 {
    //         break;
    //     }
    //     value.push(parts.1);
    // }
    // Ok((rest, value))
}

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

pub struct Label {
    parts: Vec<Vec<u8>>,
}

pub fn parse_label_part(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
    let (input, count) = be_u8(input)?;
    let (input, parts) = take(count)(input)?;
    Ok((input, parts.to_vec()))
}

named!(empty_root, tag!([0u8]));

pub fn parse_label(input: &[u8]) -> IResult<&[u8], Label> {
    // TODO: enforce letters-digits-hyphen rule for allowed characters?
    let (input, (parts, _)) = many_till(parse_label_part, empty_root)(input)?;
    Ok((input, Label { parts }))
}

impl Debug for Label {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for part in &self.parts {
            write!(f, "{}.", String::from_utf8_lossy(part))?
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct DnsQuestion {
    qname: Label,
    qtype: u16,
}

pub fn parse_question(input: &[u8]) -> IResult<&[u8], DnsQuestion> {
    let (input, qname) = parse_label(input)?;
    let (input, qtype) = be_u16(input)?;
    let (input, _qclass) = be_u16(input)?;  // expected to be 1u16
    Ok((input, DnsQuestion { qname, qtype }))
}

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
        let bytes = include_bytes!("../examples/query.google.dns");
        let label_bytes = &bytes[12..24];
        let (rest, label) = parse_label(label_bytes).unwrap();
        assert!(rest.len() == 0);
        assert_eq!(label.parts.iter().map(|s| String::from_utf8_lossy(s)).collect::<Vec<_>>(), vec!["google", "com"]);
    }

    #[test]
    fn test_parse_question() {
        let bytes = include_bytes!("../examples/query.google.dns");
        let question_bytes = &bytes[12..];
        let (rest, question) = parse_question(question_bytes).unwrap();
        assert!(rest.len() == 0);
        assert!(question.qtype == 1u16);
        assert!(question.qname.parts.len() == 2);
    }
}
