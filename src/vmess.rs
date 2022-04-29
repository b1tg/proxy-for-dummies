use crypto::mac::Mac;
use crypto::digest::Digest;
use crypto::md5::Md5;
use crypto::sha2::Sha256;
use crypto::aes_gcm::AesGcm;
use aes_gcm::{Aes256Gcm,Aes128Gcm, Key, Nonce}; // Or `Aes128Gcm`
use aes_gcm::aead::{Aead, NewAead};
use crypto::hmac::Hmac;
use std::fs;
use std::time::SystemTime;
use core::hash::{Hasher, BuildHasherDefault};
#[allow(missing_copy_implementations)]
pub struct FnvHasher(u64);

impl Default for FnvHasher {

    #[inline]
    fn default() -> FnvHasher {
        FnvHasher(0xcbf29ce484222325)
    }
}
impl FnvHasher {
    /// Create an FNV hasher starting with a state corresponding
    /// to the hash `key`.
    #[inline]
    pub fn with_key(key: u64) -> FnvHasher {
        FnvHasher(key)
    }
}

impl Hasher for FnvHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let FnvHasher(mut hash) = *self;

        for byte in bytes.iter() {
            hash = hash ^ (*byte as u64);
            hash = hash.wrapping_mul(0x100000001b3);
        }

        *self = FnvHasher(hash);
    }
}

fn fnv(input: &[u8]) -> [u8;8] {
    let mut hasher = FnvHasher::default();
    hasher.write(input);
    let res = hasher.finish();
    res.to_le_bytes()
}

fn md5(input: &[u8]) -> [u8;16] {
    let mut md5hasher = Md5::new();
    md5hasher.input(input);
    let mut res = [0u8; 16];
    md5hasher.result(&mut res);
    res
}

// fn hmac(h, k, m) {

// }

// Shake: SHA3-Shake128 函数
fn shake(input: &str) -> String {
    "".to_owned()
}

// VMess 是一个无状态协议，即客户端和服务器之间不需要握手即可直接传输数据，
// 每一次数据传输对之前和之后的其它数据传输没有影响。 VMess 的客户端发起
// 一次请求，服务器判断该请求是否来自一个合法的客户端。如验证通过，则转发
// 该请求，并把获得的响应发回给客户端。

pub fn auth() {
    // 客户端请求
    // 16 bytes 认证信息
    // X  bytes 指令部分
    // 余下部分  数据

    // #1 认证信息
    // H(散列函数) = MD5
    // K(密钥) = 用户ID（16bytes）
    // M(消息) = UTC时间，精确到秒，取值为当前时间的前后 
    //     30 秒随机值(8 字节, Big Endian)
    // Hash = HMAC(H, K, M)
    let uuid = [0u8; 16];
    let mut hmacor = Hmac::new(Md5::new(), &uuid);
    let sys_time = SystemTime::now();
    let utc_time = sys_time.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
    let utc_time_bytes = utc_time.to_be_bytes();
    hmacor.input(&utc_time_bytes);
    let hash = hmacor.result();
    println!("hmac is {}", hex::encode(hash.code()));
    // println!("hmac is {}", hex::encode(hash.code()));

    // #2. 指令部分
    // 指令部分经过 AES-128-CFB 加密：
    //   - Key: MD5(用户 ID + []byte('c48619fe-8f02-49e0-b9e9-edf763e17e21'))
    //   - IV: MD5(X + X + X + X)，X = []byte(认证信息生成的时间) (8 字节, Big Endian)
    let mut key_input: Vec<u8> = uuid.to_vec();
    key_input.extend_from_slice("c48619fe-8f02-49e0-b9e9-edf763e17e21".as_bytes());
    let key = md5(&key_input);
    let mut iv_input: Vec<u8> = utc_time_bytes.to_vec();
    iv_input.extend_from_within(..);
    iv_input.extend_from_within(..);
    dbg!(&iv_input);
    let iv = md5(&iv_input);


    let mut ins: Vec<u8> = vec![];

    // 1 版本号 Ver：始终为 1；
    ins.push(1);
    // 16 数据加密 IV：随机值；
    ins.extend_from_slice(&iv);
    // 16 数据加密 Key：随机值；
    ins.extend_from_slice(&key);
    // 1  响应认证 V：随机值；
    ins.push(0); // TODO
    // 1 选项 Opt：
    //     S (0x01)：标准格式的数据流（建议开启）；
    //     R (0x02)：客户端期待重用 TCP 连接（V2Ray 2.23+ 弃用）；
    //         只有当 S 开启时，这一项才有效；
    //     M (0x04)：开启元数据混淆（建议开启）；
    //         只有当 S 开启时，这一项才有效；
    //         当其项开启时，客户端和服务器端需要分别构造两个 Shake 实例，分别为 RequestMask = Shake(请求数据 IV), ResponseMask = Shake(响应数据 IV)。
    //     X：保留
    ins.push(0x1);
    // 4 余量 P：在校验值之前加入 P 字节的随机值；
    ins.extend_from_slice(&0xffu32.to_le_bytes());// TODO
    // 4 加密方式：指定数据部分的加密方式，可选的值有：
    //     0x00：AES-128-CFB；
    //     0x01：不加密；
    //     0x02：AES-128-GCM；
    //     0x03：ChaCha20-Poly1305；
    ins.extend_from_slice(&(0x02u32).to_le_bytes());
    // 1 resv
    ins.push(0x0);
    // 1 指令 Cmd：
    //     0x01：TCP 数据；
    //     0x02：UDP 数据；
    ins.push(0x1);
    // 2 端口 Port：Big Endian 格式的整型端口号；
    ins.extend_from_slice(&(443u16).to_le_bytes());
    // 1 地址类型 T：
    //     0x01：IPv4
    //     0x02：域名
    //     0x03：IPv6
    ins.push(0x2);
    // N 地址 A：
    //     当 T = 0x01 时，A 为 4 字节 IPv4 地址；
    //     当 T = 0x02 时，A 为 1 字节长度（L） + L 字节域名；
    //     当 T = 0x03 时，A 为 16 字节 IPv6 地址；
    let domain = "www.bing.com";
    ins.push(domain.len() as u8);
    ins.extend_from_slice(domain.as_bytes());
    // P 随机值
    // TODO
    // 4 校验 F：指令部分除 F 外所有内容的 FNV1a hash
    // TODO


    let test_data = "AAAAA".repeat(100).as_bytes();
    // AesGcm::new(key_size: KeySize, key: &[u8], nonce: &[u8], aad: &[u8])
    let cipher = Aes128Gcm::new(Key::from_slice(&key));
    // golang  
    //  gcmStandardNonceSize = 12
    // 	gcmTagSize           = 16
    let nonce_size = 12;
    let mut count: u16 = 0;
    let mut nonce_buf: Vec<u8> = iv[3..=12].to_vec();
    assert_eq!(nonce_buf.len(), 10);
    nonce_buf.insert(0, count.to_be_bytes()[1]);
    nonce_buf.insert(0, count.to_be_bytes()[0]);
    let nonce = Nonce::from_slice(&nonce_buf);
    
    let encrypted = cipher.encrypt(nonce, test_data).unwrap();


    // cipher.nonce_size;
    // cipher.g;
    // #3. 数据部分
    // 2 长度L Big Endian 格式的整型，最大值为 2^14
    // L 数据包 由指定的加密方式加密过的数据包
    //   按加密方式不同，数据包的格式如下：
    //     AES-128-CFB：整个数据部分使用 AES-128-CFB 加密
    //       4 字节：实际数据的 FNV1a hash；
    //       L-4 字节：实际数据；
    //     AES-128-GCM：
    //       16 字节：GCM 认证信息
    //       L - 16 字节：实际数据
    //       --- desc ---
    //       Key 为指令部分的 Key，
    //       IV = count (2 字节) + IV (10 字节)。 (nonce)
    //       count 从 0 开始递增，每个数据包加 1
    //       IV 为 指令部分 IV 的第 3 至第 12 字节。
    // 在传输结束之前，数据包中必须有实际数据，即除了长度和认证数据之外的数据。
    // 当传输结束时，客户端必须发送一个空的数据包，即 L = 0（不加密） 或认证数据长度（有加密），来表示传输结束。
    let mut data = vec![];
    data.extend_from_slice(&encrypted.len().to_be_bytes());
    data.extend_from_slice(&encrypted);
}


#[cfg(test)]
mod tests {

    use crate::*;
    #[test]
    fn test_auth() {
        // auth();
        
    }
}


