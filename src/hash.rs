use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Algorithm {
    Fnv32,
    Fnv64,
    Fnv128,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512_224,
    Sha512_256,
    Md5,
    Blake2b,
    Blake2b256,
    Blake2b384,
    Blake2b512,
    Blake2s,
    Blake2s256,
    Blake3,
    Crc32,
    Crc32c,
    Crc64ecma,
    Crc64iso,
    Xxh32,
    Xxh64,
    Xxh3_64,
    Xxh3_128,
}

impl Algorithm {
    pub fn all() -> Vec<Algorithm> {
        vec![
            Algorithm::Fnv32,
            Algorithm::Fnv64,
            Algorithm::Fnv128,
            Algorithm::Sha1,
            Algorithm::Sha224,
            Algorithm::Sha256,
            Algorithm::Sha384,
            Algorithm::Sha512,
            Algorithm::Sha512_224,
            Algorithm::Sha512_256,
            Algorithm::Md5,
            Algorithm::Blake2b,
            Algorithm::Blake2b256,
            Algorithm::Blake2b384,
            Algorithm::Blake2b512,
            Algorithm::Blake2s,
            Algorithm::Blake2s256,
            Algorithm::Blake3,
            Algorithm::Crc32,
            Algorithm::Crc32c,
            Algorithm::Crc64ecma,
            Algorithm::Crc64iso,
            Algorithm::Xxh32,
            Algorithm::Xxh64,
            Algorithm::Xxh3_64,
            Algorithm::Xxh3_128,
        ]
    }

    pub fn name(&self) -> &'static str {
        match self {
            Algorithm::Fnv32 => "fnv32",
            Algorithm::Fnv64 => "fnv64",
            Algorithm::Fnv128 => "fnv128",
            Algorithm::Sha1 => "sha1",
            Algorithm::Sha224 => "sha224",
            Algorithm::Sha256 => "sha256",
            Algorithm::Sha384 => "sha384",
            Algorithm::Sha512 => "sha512",
            Algorithm::Sha512_224 => "sha512-224",
            Algorithm::Sha512_256 => "sha512-256",
            Algorithm::Md5 => "md5",
            Algorithm::Blake2b => "blake2b",
            Algorithm::Blake2b256 => "blake2b-256",
            Algorithm::Blake2b384 => "blake2b-384",
            Algorithm::Blake2b512 => "blake2b-512",
            Algorithm::Blake2s => "blake2s",
            Algorithm::Blake2s256 => "blake2s-256",
            Algorithm::Blake3 => "blake3",
            Algorithm::Crc32 => "crc32",
            Algorithm::Crc32c => "crc32c",
            Algorithm::Crc64ecma => "crc64-ecma",
            Algorithm::Crc64iso => "crc64-iso",
            Algorithm::Xxh32 => "xxh32",
            Algorithm::Xxh64 => "xxh64",
            Algorithm::Xxh3_64 => "xxh3-64",
            Algorithm::Xxh3_128 => "xxh3-128",
        }
    }

    pub fn output_size(&self) -> usize {
        match self {
            Algorithm::Fnv32 => 4,
            Algorithm::Fnv64 => 8,
            Algorithm::Fnv128 => 16,
            Algorithm::Sha1 => 20,
            Algorithm::Sha224 => 28,
            Algorithm::Sha256 => 32,
            Algorithm::Sha384 => 48,
            Algorithm::Sha512 => 64,
            Algorithm::Sha512_224 => 28,
            Algorithm::Sha512_256 => 32,
            Algorithm::Md5 => 16,
            Algorithm::Blake2b => 64,
            Algorithm::Blake2b256 => 32,
            Algorithm::Blake2b384 => 48,
            Algorithm::Blake2b512 => 64,
            Algorithm::Blake2s => 32,
            Algorithm::Blake2s256 => 32,
            Algorithm::Blake3 => 32,
            Algorithm::Crc32 => 4,
            Algorithm::Crc32c => 4,
            Algorithm::Crc64ecma => 8,
            Algorithm::Crc64iso => 8,
            Algorithm::Xxh32 => 4,
            Algorithm::Xxh64 => 8,
            Algorithm::Xxh3_64 => 8,
            Algorithm::Xxh3_128 => 16,
        }
    }

    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Algorithm::Fnv32 => fnv32a::<u32>(data, 0x811c9dc5, 0x01000193).to_le_bytes().to_vec(),
            Algorithm::Fnv64 => fnv32a::<u64>(data, 0xcbf29ce484222325, 0x00000100000001B3).to_le_bytes().to_vec(),
            Algorithm::Fnv128 => {
                let lo: u64 = 0x6c62272e07bb0142;
                let hi: u64 = 0x62b821756295c58d;
                let result = fnv128a(data, hi, lo);
                result.as_slice().to_vec()
            }
            Algorithm::Sha1 => sha_digest::<sha1::Sha1>(data),
            Algorithm::Sha224 => sha_digest::<sha2::Sha224>(data),
            Algorithm::Sha256 => sha_digest::<sha2::Sha256>(data),
            Algorithm::Sha384 => sha_digest::<sha2::Sha384>(data),
            Algorithm::Sha512 => sha_digest::<sha2::Sha512>(data),
            Algorithm::Sha512_224 => sha_digest::<sha2::Sha512_224>(data),
            Algorithm::Sha512_256 => sha_digest::<sha2::Sha512_256>(data),
            Algorithm::Md5 => sha_digest::<md5::Md5>(data),
            Algorithm::Blake2b | Algorithm::Blake2b512 => {
                use digest::Digest;
                blake2::Blake2b::<digest::consts::U64>::digest(data).to_vec()
            }
            Algorithm::Blake2b256 => {
                use digest::Digest;
                blake2::Blake2b::<digest::consts::U32>::digest(data).to_vec()
            }
            Algorithm::Blake2b384 => {
                use digest::Digest;
                blake2::Blake2b::<digest::consts::U48>::digest(data).to_vec()
            }
            Algorithm::Blake2s | Algorithm::Blake2s256 => {
                use digest::Digest;
                blake2::Blake2s::<digest::consts::U32>::digest(data).to_vec()
            }
            Algorithm::Blake3 => blake3::hash(data).as_bytes().to_vec(),
            Algorithm::Crc32 => {
                let crc = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);
                crc.checksum(data).to_le_bytes().to_vec()
            }
            Algorithm::Crc32c => {
                let crc = crc::Crc::<u32>::new(&crc::CRC_32_ISCSI);
                crc.checksum(data).to_le_bytes().to_vec()
            }
            Algorithm::Crc64ecma => {
                let crc = crc::Crc::<u64>::new(&crc::CRC_64_ECMA_182);
                crc.checksum(data).to_le_bytes().to_vec()
            }
            Algorithm::Crc64iso => {
                let crc = crc::Crc::<u64>::new(&crc::CRC_64_GO_ISO);
                crc.checksum(data).to_le_bytes().to_vec()
            }
            Algorithm::Xxh32 => xxhash_rust::xxh32::xxh32(data, 0).to_le_bytes().to_vec(),
            Algorithm::Xxh64 => xxhash_rust::xxh64::xxh64(data, 0).to_le_bytes().to_vec(),
            Algorithm::Xxh3_64 => xxhash_rust::xxh3::xxh3_64(data).to_le_bytes().to_vec(),
            Algorithm::Xxh3_128 => xxhash_rust::xxh3::xxh3_128(data).to_le_bytes().to_vec(),
        }
    }
}

impl FromStr for Algorithm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim().to_lowercase();
        match s.as_str() {
            "fnv32" => Ok(Algorithm::Fnv32),
            "fnv64" => Ok(Algorithm::Fnv64),
            "fnv128" => Ok(Algorithm::Fnv128),
            "sha1" => Ok(Algorithm::Sha1),
            "sha-1" => Ok(Algorithm::Sha1),
            "sha224" => Ok(Algorithm::Sha224),
            "sha-224" => Ok(Algorithm::Sha224),
            "sha256" => Ok(Algorithm::Sha256),
            "sha-256" => Ok(Algorithm::Sha256),
            "sha384" => Ok(Algorithm::Sha384),
            "sha-384" => Ok(Algorithm::Sha384),
            "sha512" => Ok(Algorithm::Sha512),
            "sha-512" => Ok(Algorithm::Sha512),
            "sha512-224" => Ok(Algorithm::Sha512_224),
            "sha512/224" => Ok(Algorithm::Sha512_224),
            "sha512-256" => Ok(Algorithm::Sha512_256),
            "sha512/256" => Ok(Algorithm::Sha512_256),
            "md5" => Ok(Algorithm::Md5),
            "md-5" => Ok(Algorithm::Md5),
            "blake2b" => Ok(Algorithm::Blake2b),
            "blake2b-256" => Ok(Algorithm::Blake2b256),
            "blake2b-384" => Ok(Algorithm::Blake2b384),
            "blake2b-512" => Ok(Algorithm::Blake2b512),
            "blake2s" => Ok(Algorithm::Blake2s),
            "blake2s-256" => Ok(Algorithm::Blake2s256),
            "blake3" => Ok(Algorithm::Blake3),
            "blake-3" => Ok(Algorithm::Blake3),
            "crc32" => Ok(Algorithm::Crc32),
            "crc-32" => Ok(Algorithm::Crc32),
            "crc32c" => Ok(Algorithm::Crc32c),
            "crc-32c" => Ok(Algorithm::Crc32c),
            "crc64-ecma" => Ok(Algorithm::Crc64ecma),
            "crc64/ecma" => Ok(Algorithm::Crc64ecma),
            "crc64-iso" => Ok(Algorithm::Crc64iso),
            "crc64/iso" => Ok(Algorithm::Crc64iso),
            "xxh32" => Ok(Algorithm::Xxh32),
            "xxh64" => Ok(Algorithm::Xxh64),
            "xxh3-64" => Ok(Algorithm::Xxh3_64),
            "xxh3/64" => Ok(Algorithm::Xxh3_64),
            "xxh3-128" => Ok(Algorithm::Xxh3_128),
            "xxh3/128" => Ok(Algorithm::Xxh3_128),
            _ => Err(format!("unknown algorithm: {s}")),
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ---------------------------------------------------------------------------
// FNV-1a helpers
// ---------------------------------------------------------------------------

fn fnv32a<T>(data: &[u8], offset: T, prime: T) -> T
where
    T: std::ops::BitXor<Output = T>
        + std::ops::Mul<Output = T>
        + std::ops::Shl<usize, Output = T>
        + std::ops::Shr<usize, Output = T>
        + std::ops::BitOr<Output = T>
        + Copy
        + From<u8>,
{
    let mut hash = offset;
    for &byte in data {
        hash = hash ^ T::from(byte);
        hash = hash * prime;
    }
    hash
}

fn fnv128a(data: &[u8], _prime_hi: u64, _prime_lo: u64) -> [u8; 16] {
    let prime_hi: u64 = 0x0000000001000000;
    let prime_lo: u64 = 0x000000000000013B;

    let mut h_hi: u64 = 0x6c62272e07bb0142;
    let mut h_lo: u64 = 0x62b821756295c58d;

    for &byte in data {
        h_lo ^= byte as u64;
        // multiply 128-bit by prime (0x0000000001000000000000000000013B)
        // prime_lo = 0x13B, prime_hi = 0x0000000001000000
        let tmp = mul128(h_hi, h_lo, prime_hi, prime_lo);
        h_hi = tmp.0;
        h_lo = tmp.1;
    }

    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&h_lo.to_le_bytes());
    out[8..16].copy_from_slice(&h_hi.to_le_bytes());
    out
}

fn mul128(a_hi: u64, a_lo: u64, b_hi: u64, b_lo: u64) -> (u64, u64) {
    let a0 = a_lo as u128;
    let a1 = a_hi as u128;
    let b0 = b_lo as u128;
    let b1 = b_hi as u128;
    let r = (a1 << 64 | a0).wrapping_mul(b1 << 64 | b0);
    ((r >> 64) as u64, r as u64)
}

// ---------------------------------------------------------------------------
// Digest-trait helper for SHA / MD5
// ---------------------------------------------------------------------------

fn sha_digest<D: digest::Digest>(data: &[u8]) -> Vec<u8> {
    D::digest(data).to_vec()
}
