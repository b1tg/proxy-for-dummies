use std::error::Error;
use tokio::net::TcpStream;
use tokio::net::TcpListener;
// use tokio::prelude::*;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::io::copy;

async fn socks5_init(socket: &mut TcpStream) {
        // # 0x01: negotiation 
        let mut buf = [0u8; 3];
        socket.read_exact(&mut buf).await;
        assert_eq!(buf, [0x05, 1, 0]);

        // 0x00: NO AUTHENTICATION REQUIRED
        // 0x01: GSSAPI
        // 0x02: USERNAME/PASSWORD
        // 0x03: to X'7F' IANA ASSIGNED
        // 0x80: to X'FE' RESERVED FOR PRIVATE METHODS
        // 0xFF: NO ACCEPTABLE METHODS
        socket.write_all(&[0x05u8, 0x00u8]).await;

        // # 0x02: method-specific sub-negotiation

        // # 0x03: Requests
        // +----+-----+-------+------+----------+----------+
        // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        // +----+-----+-------+------+----------+----------+
        // | 1  |  1  | X'00' |  1   | Variable |    2     |
        // +----+-----+-------+------+----------+----------+            
        let mut buf = [0u8; 4];
        socket.read_exact(&mut buf).await;
        assert_eq!(buf[0], 0x05);
        // CONNECT X'01'
        // BIND X'02'
        // UDP ASSOCIATE X'03'            
        assert_eq!(buf[1], 0x01);
        assert_eq!(buf[2], 0x00);
        // ATYP: address type of following address
        //     IP V4 address: X'01'
        //     DOMAINNAME: X'03'
        //     IP V6 address: X'04'            
        let atyp = buf[3];
        let mut domain = "".to_owned();
        match atyp {
            0x01 => {
                let mut ip_buf = [0u8; 4];
                socket.read_exact(&mut ip_buf).await;
                let ip = format!("{}.{}.{}.{}", ip_buf[0], ip_buf[1], ip_buf[2], ip_buf[3]);
                println!("ATYP(IP): {}", ip);
            },
            0x03 => {
                let mut domain_len = [0u8];
                socket.read_exact(&mut domain_len).await;
                let domain_len = domain_len[0];
                let mut domain_buf = vec![];
                domain_buf.resize(domain_len as usize, 0);
                socket.read_exact(&mut domain_buf).await;
                domain = String::from_utf8(domain_buf).unwrap();
                println!("ATYP(DOMAIN): {}", domain);
            },
            0x04 => {
                unimplemented!();
            },
            _ => unimplemented!()
        }
        let mut port_buf = [0u8; 2];
        socket.read_exact(&mut port_buf).await;
        let port = u16::from_be_bytes(port_buf);
        println!("PORT: {}", port);
        // +----+-----+-------+------+----------+----------+
        // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        // +----+-----+-------+------+----------+----------+
        // | 1  |  1  | X'00' |  1   | Variable |    2     |
        // +----+-----+-------+------+----------+----------+            
        // - VER    protocol version: X'05'
        // - REP    Reply field:
        //    - X'00' succeeded
        //    - [...]
        // - RSV    RESERVED
        // - ATYP   address type of following address
        //     - IP V4 address: X'01'
        //     - DOMAINNAME: X'03'
        //     - IP V6 address: X'04'
        // - BND.ADDR       server bound address
        // - BND.PORT       server bound port in network octet order            
        let reply = [
            // VER, REP, RSV
            0x05, 0x00, 0x00, 
            // ATYP
            0x01,
            // TODO: is ADDR and PORT no use ?
            // BND.ADDR, BND.PORT 
            127, 0, 0, 1, 11, 11,
        ];
        socket.write_all(&reply).await;
}

// data => a ==>...=> b
async fn socks5_proxy_stream(a: &mut TcpStream, b: &mut TcpStream) {
    let (mut sr, mut sw) = a.split();
    let (mut nr, mut nw) = b.split();
    let copy1 = async {
        copy(&mut sr, &mut nw).await
    };
    let copy2 = async {
        copy(&mut nr, &mut sw).await
    };
    tokio::try_join!(copy1, copy2);    
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:7892").await?;
    loop {
        let (mut socket, _) = listener.accept().await?;
        tokio::spawn(async move {
            // 0x01: negotiation 
            let mut buf = [0u8; 3];
            socket.read_exact(&mut buf).await;
            assert_eq!(buf, [0x05, 1, 0]);

            // 0x00: NO AUTHENTICATION REQUIRED
            // 0x01: GSSAPI
            // 0x02: USERNAME/PASSWORD
            // 0x03: to X'7F' IANA ASSIGNED
            // 0x80: to X'FE' RESERVED FOR PRIVATE METHODS
            // 0xFF: NO ACCEPTABLE METHODS
            socket.write_all(&[0x05u8, 0x00u8]).await;

            // 0x02: method-specific sub-negotiation

            // 0x03: Requests
            // +----+-----+-------+------+----------+----------+
            // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
            // +----+-----+-------+------+----------+----------+
            // | 1  |  1  | X'00' |  1   | Variable |    2     |
            // +----+-----+-------+------+----------+----------+            
            let mut buf = [0u8; 4];
            socket.read_exact(&mut buf).await;
            assert_eq!(buf[0], 0x05);
            // CONNECT X'01'
            // BIND X'02'
            // UDP ASSOCIATE X'03'            
            assert_eq!(buf[1], 0x01);
            assert_eq!(buf[2], 0x00);
            // ATYP: address type of following address
            //     IP V4 address: X'01'
            //     DOMAINNAME: X'03'
            //     IP V6 address: X'04'            
            let atyp = buf[3];
            let mut domain = "".to_owned();
            match atyp {
                0x01 => {
                    let mut ip_buf = [0u8; 4];
                    socket.read_exact(&mut ip_buf).await;
                    let ip = format!("{}.{}.{}.{}", ip_buf[0], ip_buf[1], ip_buf[2], ip_buf[3]);
                    println!("ATYP(IP): {}", ip);
                },
                0x03 => {
                    let mut domain_len = [0u8];
                    socket.read_exact(&mut domain_len).await;
                    let domain_len = domain_len[0];
                    let mut domain_buf = vec![];
                    domain_buf.resize(domain_len as usize, 0);
                    socket.read_exact(&mut domain_buf).await;
                    domain = String::from_utf8(domain_buf).unwrap();
                    println!("ATYP(DOMAIN): {}", domain);
                },
                0x04 => {
                    unimplemented!();
                },
                _ => unimplemented!()
            }

            let mut port_buf = [0u8; 2];
            socket.read_exact(&mut port_buf).await;
            let port = u16::from_be_bytes(port_buf);
            println!("PORT: {}", port);
            // +----+-----+-------+------+----------+----------+
            // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
            // +----+-----+-------+------+----------+----------+
            // | 1  |  1  | X'00' |  1   | Variable |    2     |
            // +----+-----+-------+------+----------+----------+            

            // - VER    protocol version: X'05'
            // - REP    Reply field:
            //    - X'00' succeeded
            //    - X'01' general SOCKS server failure
            //    - X'02' connection not allowed by ruleset
            //    - X'03' Network unreachable
            //    - X'04' Host unreachable
            //    - X'05' Connection refused
            //    - X'06' TTL expired
            //    - X'07' Command not supported
            //    - X'08' Address type not supported
            //    - X'09' to X'FF' unassigned
            // - RSV    RESERVED
            // - ATYP   address type of following address
            //     - IP V4 address: X'01'
            //     - DOMAINNAME: X'03'
            //     - IP V6 address: X'04'
            // - BND.ADDR       server bound address
            // - BND.PORT       server bound port in network octet order            
            let reply = [
                // VER, REP, RSV
                0x05, 0x00, 0x00, 
                // ATYP
                0x01,
                // BND.ADDR, BND.PORT 
                127, 0, 0, 1, 11, 11,
            ];
            socket.write_all(&reply).await;

            println!("connecting {}:{}", domain, port);
            let mut new_socket = TcpStream::connect(format!("{}:{}", domain, port)).await.unwrap();
            println!("connected {}:{}", domain, port);
            
            let (mut sr, mut sw) = socket.split();
            let (mut nr, mut nw) = new_socket.split();
            let copy1 = async {
                copy(&mut sr, &mut nw).await
            };
            let copy2 = async {
                copy(&mut nr, &mut sw).await
            };
            tokio::try_join!(copy1, copy2);
        });
    }
}

async fn client() -> Result<(), Box<dyn Error>> {
    // Connect to a peer
    let mut stream = TcpStream::connect("127.0.0.1:9999").await?;

    let buf0 = [0x05u8, 0x01u8, 0x00u8];
    stream.write_all(&buf0).await?;
    let mut buf01 = [0u8; 0x2];
    stream.read_exact(&mut buf01).await?;

    if buf01[0] == 0xff {
        eprintln!("none of methods listed by the client are acceptable, closing.");
        stream.shutdown().await?;
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
