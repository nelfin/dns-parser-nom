use std::net::{Ipv4Addr, UdpSocket};

// parse DNS packet
// stub resolver

fn handle_query(socket: &UdpSocket) -> std::io::Result<()> {
    let mut data = [0u8; 512];
    let (n, src) = socket.recv_from(&mut data)?;
    let data = &data[..n];

    let res = dns_parser::parse_packet(data, data);
    let request: dns_parser::DnsPacket = match res {
        Ok((_, request)) => request,
        Err(e) =>  { eprintln!("error parsing: {}", e); todo!(); }
    };

    println!("{:#x?}", request);

    let mut response = dns_parser::DnsPacket::new();
    // FIXME: stop exposing this stuff publicly
    response.header.id = request.header.id;
    response.header.message_type = 1; // response
    let q = &request.questions[0];
    response.add_question(q.clone());
    response.add_answer(dns_parser::DnsRecord::from_question(q, Ipv4Addr::new(12, 34, 56, 78)));

    let mut resp_buf = [0u8; 512];
    let n = response.serialise(&mut resp_buf);
    let resp_buf = &resp_buf[..n];
    println!("{:02x?}", resp_buf);

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
