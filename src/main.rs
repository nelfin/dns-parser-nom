use std::{net::UdpSocket, default::Default};
use std::fmt::Debug;
use std::net::Ipv4Addr;

// parse DNS packet
// stub resolver

fn handle_query(socket: &UdpSocket) -> std::io::Result<()> {
    // let mut data = [0u8; 512];
    // let (n, src) = socket.recv_from(&mut data)?;
    // let data = &data[..n];

    // println!("bytes: {:?}", data);
    // let res = DnsPacket::from_bytes((data, 0));
    // let request: DnsPacket = match res {
    //     Ok((_, request)) => request,
    //     Err(e) =>  { eprintln!("error parsing: {}", e); todo!(); }
    // };

    // let data = include_bytes!("../examples/response.google.dns"); // FIXME
    // let (_, mut response) = DnsPacket::from_bytes((data, 0)).unwrap();
    // response.header.id = request.header.id;
    // response.header.message_type = 1; // response
    //let resp_buf = response.to_bytes().unwrap();

    // println!("request: {:?}", request);
    // // println!("response: {:?}", response);
    // let resp_buf = [0u8; 512];

    // socket.send_to(&resp_buf, src)?;
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
