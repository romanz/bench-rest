use std::{io::Read, time::Duration};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

use bitcoin::{
    blockdata::opcodes::all::*,
    consensus::encode::{Decodable, ReadExt, VarInt},
    key::PublicKey,
    script::PushBytesBuf,
    ScriptBuf,
};

fn varint_decode<D: bitcoin::io::Read>(
    d: &mut D,
) -> std::result::Result<usize, bitcoin::consensus::encode::Error> {
    let mut n = 0usize;
    // TODO: add checks
    loop {
        let b = u8::consensus_decode(d)?;
        n = (n << 7) | (b & 0x7F) as usize;
        if b & 0x80 != 0 {
            n += 1;
        } else {
            return Ok(n);
        }
    }
}

fn decode_bytes<D: bitcoin::io::Read>(
    d: &mut D,
    len: usize,
) -> std::result::Result<Vec<u8>, bitcoin::consensus::encode::Error> {
    let mut ret = vec![0; len];
    d.read_slice(&mut ret)?;
    Ok(ret)
}

const SPECIAL_SCRIPTS: usize = 6;

fn decompress_script(script_type: u8, mut bytes: Vec<u8>) -> Result<ScriptBuf> {
    let builder = bitcoin::blockdata::script::Builder::new();
    let script = match script_type {
        0 => builder
            .push_opcode(OP_DUP)
            .push_opcode(OP_HASH160)
            .push_slice(PushBytesBuf::try_from(bytes)?)
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_CHECKSIG),
        1 => builder
            .push_opcode(OP_HASH160)
            .push_slice(PushBytesBuf::try_from(bytes)?)
            .push_opcode(OP_EQUAL),
        2 | 3 => {
            bytes.insert(0, script_type);
            builder
                .push_slice(PushBytesBuf::try_from(bytes)?)
                .push_opcode(OP_CHECKSIG)
        }
        4 | 5 => {
            bytes.insert(0, script_type - 2);
            let mut pubkey = PublicKey::from_slice(&bytes).expect("bad PublicKey");
            pubkey.compressed = false;
            builder
                .push_slice(PushBytesBuf::try_from(pubkey.to_bytes())?)
                .push_opcode(OP_CHECKSIG)
        }
        _ => unreachable!(),
    }
    .into_script();
    assert!(script.is_p2pk() || script.is_p2pkh() || script.is_p2sh());
    Ok(script)
}

fn decompress_amount(mut x: u64) -> u64 {
    // x = 0  OR  x = 1+10*(9*n + d - 1) + e  OR  x = 1+10*(n - 1) + 9
    if x == 0 {
        return 0;
    }
    x -= 1;
    // x = 10*(9*n + d - 1) + e
    let mut e = x % 10;
    x /= 10;

    let mut n = if e < 9 {
        // x = 9*n + d - 1
        let d = (x % 9) + 1;
        x /= 9;
        // x = n
        x * 10 + d
    } else {
        x + 1
    };
    while e != 0 {
        n *= 10;
        e -= 1;
    }
    n
}

#[derive(Debug, Default)]
struct Stats {
    total: u64,
    value: u128,
    by_type: [u64; 7],
}

fn script_decode<D: bitcoin::io::Read>(d: &mut D, stats: &mut Stats) -> Result<ScriptBuf> {
    let len = varint_decode(d)?;
    stats.total += 1;
    Ok(if len < SPECIAL_SCRIPTS {
        let script_type = len as u8;
        let size = match script_type {
            0 | 1 => 20,
            2..=5 => 32,
            _ => unreachable!(),
        };
        stats.by_type[len] += 1;
        let compressed = decode_bytes(d, size)?;
        decompress_script(script_type, compressed)?
    } else {
        stats.by_type[6] += 1;
        let len = len - SPECIAL_SCRIPTS;
        ScriptBuf::from(decode_bytes(d, len)?)
    })
}

fn blockundo_decode<D: bitcoin::io::Read>(d: &mut D, stats: &mut Stats) -> Result<()> {
    let tx_count = VarInt::consensus_decode(d)?.0;
    for _ in 0..tx_count {
        let txin_count = VarInt::consensus_decode(d)?.0;
        for _ in 0..txin_count {
            let _height_coinbase = varint_decode(d)?;
            assert_eq!(varint_decode(d)?, 0); // unused today
            stats.value += decompress_amount(varint_decode(d)? as u64) as u128;
            let _script = script_decode(d, stats)?;
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let agent = ureq::Agent::new_with_defaults();
    let mut data = Vec::with_capacity(10_000_000);

    let mut height = 700000;
    while height < 710000 {
        let mut duration = Duration::ZERO;
        let mut stats = Default::default();
        let chunk_size = 1000;
        let start_height = height;
        for offset in 0..chunk_size {
            data.clear();
            let url = format!(
                "http://localhost:8332/rest/blockhashbyheight/{}.hex",
                height + offset
            );
            let response = agent.get(url).call()?;
            let hash = response.into_body().read_to_string()?;

            let t = std::time::Instant::now();
            let url = format!("http://localhost:8332/rest/blockundo/{}.bin", &hash[..64]);
            let response = agent.get(url).call()?;
            response.into_body().into_reader().read_to_end(&mut data)?;
            let size = data.len() as u64;
            let mut c = bitcoin::io::Cursor::new(data);
            blockundo_decode(&mut c, &mut stats)?;
            assert_eq!(c.position(), size);
            data = c.into_inner();
            duration += t.elapsed();
            height += 1;
        }
        println!(
            "[{}..{}) {}[us/call] {:?}",
            start_height,
            height,
            duration.div_f32(chunk_size as f32).as_micros(),
            stats
        );
    }
    Ok(())
}
