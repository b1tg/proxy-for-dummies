use std::error::Error;
use tokio::net::TcpStream;
use tokio::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Connect to a peer
    let mut stream = TcpStream::connect("127.0.0.1:9999").await?;

    let buf0 = [0x05u8, 0x01u8, 0x00u8];
    stream.write_all(&buf0).await?;
    let mut buf01 = [0u8; 0x2];
    stream.read_exact(&mut buf01).await?;

    if buf01[0] == 0xff {
        eprintln!("none of methods listed by the client are acceptable, closing.");
        stream.shutdown(std::net::Shutdown::Both).unwrap();
    }
    assert_eq!(buf01[0], 0x05); // socks5
                                // enter a method-specific sub-negotiation

    let mut buf1_vec: Vec<u8> = vec![
        0x05, // version: socks5
        0x01, // CONNECT
        0,    // rsv
        0x03, // domain
              // ,// dest address
              // , // dest port
    ];
    let target_addr = "www.google.com";
    let target_port = 80u16;
    let target_addr_vec = target_addr.as_bytes();
    buf1_vec.push(target_addr.len() as u8);
    buf1_vec.extend_from_slice(target_addr_vec);

    let target_port_vec = [(target_port / 256) as u8, (target_port % 256) as u8];
    buf1_vec.extend_from_slice(&target_port_vec);

    stream.write_all(&buf1_vec).await?;

    let mut buf11 = [0u8; 0x4 + 0x4 + 2];
    stream.read_exact(&mut buf11).await?;

    // dbg!(buf11);
    // debug_assert_eq!(buf11, [
    //     5, // socks5
    //     0, // REP: success
    //     0, // rev
    //     1, // ATYP: ip v4
    // ]);

    // let mut buf12 = [0u8;0x4+0x2]; // ipv4 + port

    // stream.read_exact(&mut buf12).await?;

    // dbg!(buf12);

    // send HTTP request

    stream.write_all(b"GET /\n\n").await?;

    let mut buf = Vec::new();

    stream.read_to_end(&mut buf).await?;
    // dbg!(buf);

    let bufstr = String::from_utf8_lossy(&buf);
    dbg!(bufstr);

    Ok(())
}
