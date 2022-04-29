use std::error::Error;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
// use tokio::prelude::*;
use tokio::io::copy;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

mod vmess;
use vmess::*;
#[derive(Debug)]
enum CommonAddr {
    Domain(String, u16),
    Ipv4(Ipv4Addr, u16),
}

impl Default for CommonAddr {
    fn default() -> Self {
        CommonAddr::Domain("".to_string(), 0)
    }
}

impl Default for Protocal {
    fn default() -> Self {
        Protocal::Socks5(CommonAddr::default())
    }
}
impl Default for Node {
    fn default() -> Self {
        Node {
           pre: Box::new(None),
           next: Box::new(None),
           proto: Protocal::default()
        }
    }
}


#[derive(Debug)]
enum Protocal {
    Socks5(CommonAddr),
    Http(CommonAddr),
}

#[derive(Debug)]
struct Node {
    pre: Box<Option<Node>>,
    proto: Protocal,
    next: Box<Option<Node>>,
}

async fn socks5_client_init(
    stream: &mut TcpStream,
    ip: Ipv4Addr,
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let buf = [0x05u8, 0x01u8, 0x00u8];
    stream.write_all(&buf).await?;
    let mut buf = [0u8; 0x2];
    stream.read_exact(&mut buf).await?;
    assert_eq!(buf[0], 0x05); // socks5
    let mut buf: Vec<u8> = vec![
        0x05, // version: socks5
        0x01, // CONNECT
        0,    // rsv
        // 0x03, // domain
        0x01, // IPv4
              // ,// dest address
              // , // dest port
    ];
    let target_port = port;
    buf.extend_from_slice(&ip.octets());
    let port_buf = [(target_port / 256) as u8, (target_port % 256) as u8];
    buf.extend_from_slice(&port_buf);
    stream.write_all(&buf).await?;
    let mut buf = [0u8; 0x4 + 0x4 + 2];
    stream.read_exact(&mut buf).await?;
    Ok(())
}

async fn socks5_server_init(
    socket: &mut TcpStream,
) -> Result<CommonAddr, Box<dyn std::error::Error>> {
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
    let mut ip: Ipv4Addr = "127.0.0.1".parse().unwrap();
    match atyp {
        0x01 => {
            let mut ip_buf = [0u8; 4];
            socket.read_exact(&mut ip_buf).await;
            ip = format!("{}.{}.{}.{}", ip_buf[0], ip_buf[1], ip_buf[2], ip_buf[3])
                .parse()
                .unwrap();
            println!("ATYP(IP): {}", ip);
        }
        0x03 => {
            let mut domain_len = [0u8];
            socket.read_exact(&mut domain_len).await;
            let domain_len = domain_len[0];
            let mut domain_buf = vec![];
            domain_buf.resize(domain_len as usize, 0);
            socket.read_exact(&mut domain_buf).await;
            domain = String::from_utf8(domain_buf).unwrap();
            println!("ATYP(DOMAIN): {}", domain);
        }
        0x04 => {
            unimplemented!();
        }
        _ => unimplemented!(),
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
        0x05, 0x00, 0x00, // ATYP
        0x01, // TODO: is ADDR and PORT no use ?
        // BND.ADDR, BND.PORT
        127, 0, 0, 1, 11, 11,
    ];
    socket.write_all(&reply).await?;

    if atyp == 0x03 {
        ip = doh_over_socks5(&domain).await?;
        println!("DNS resolve {} => {}", domain, ip);
    }

    // Ok(CommonAddr::Domain(domain, port))
    Ok(CommonAddr::Ipv4(ip, port))
    // Ok(())
}

// data => a ==>...=> b
async fn proxy_stream(a: &mut TcpStream, b: &mut TcpStream) {
    let (mut sr, mut sw) = a.split();
    let (mut nr, mut nw) = b.split();
    let copy1 = async { copy(&mut sr, &mut nw).await };
    let copy2 = async { copy(&mut nr, &mut sw).await };
    tokio::try_join!(copy1, copy2);
}
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use serde_json::json;
// This `derive` requires the `serde` dependency.
#[derive(Deserialize)]
struct DohResponse {
    origin: String,
}

async fn doh_over_socks5(domain: &str) -> Result<Ipv4Addr, Box<dyn std::error::Error>> {
    // TODO: why need all
    let proxy = reqwest::Proxy::all("socks5://127.0.0.1:7890")?;
    let client = reqwest::ClientBuilder::new().proxy(proxy).build()?;
    let url = format!("https://dns.google/resolve?name={}&type=1", domain);
    // https://dns.google/resolve?name=www.example.com&type=A&short=1
    let res = client.get(url).send().await?;
    let json: serde_json::Value = serde_json::from_str(&res.text().await?)?;
    let ip = json
        .get("Answer").ok_or("no Answer")?
        .as_array().ok_or("not Answer array")?
        .iter()
        .find(|answer| 
            answer.get("type") == Some(&json!(1))
        ).ok_or("can not find type==1")?
        .get("data").ok_or("no Answer data")?;
    let ip = ip.as_str().ok_or("as_str error")?.trim_matches('\"');
    if let Ok(ip1) = ip.parse::<Ipv4Addr>() {
        return Ok(ip1);
    } else {
        return Err("parse ipv4 error".into());
    }
}

// gost-windows-amd64.exe -L=socks5://:7891?dns=https-chain://dns.google/dns-query -F=http://:7890
//  s54.exe -L

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    let mut cur_node = Node::default();

    cur_node.proto = Protocal::Socks5(CommonAddr::Ipv4("127.0.0.1".parse().unwrap(), 7892));
    let mut node1 = Node::default();
    let mut node2 = Node::default();

    cur_node.proto = Protocal::Socks5(CommonAddr::Ipv4("127.0.0.1".parse().unwrap(), 7890));

    cur_node.next = Box::new(Some(node1));

    let listener = TcpListener::bind("127.0.0.1:7892").await?;
    loop {
        let (mut socket, _) = listener.accept().await?;
        tokio::spawn(async move {
            let addr = socks5_server_init(&mut socket).await.unwrap();
            // // use forward proxy here
            match addr {
                CommonAddr::Ipv4(ip, port) => {
                    let mut forward = TcpStream::connect("127.0.0.1:7890").await.unwrap();
                    socks5_client_init(&mut forward, ip, port).await;
                    proxy_stream(&mut socket, &mut forward).await
                }
                _ => {
                    unreachable!()
                }
            };
        });
    }
    // Ok(())
}
