use std::{cmp::min, io::Read, ops::ControlFlow};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

use bitcoin::{
    block::Header, blockdata::opcodes::all::*, consensus::encode::{Decodable, ReadExt, VarInt}, io::Cursor, key::PublicKey, script::PushBytesBuf, BlockHash, ScriptBuf, TxOut
};
use bitcoin_slices::{bsl, Visit};
use clap::{Parser, ValueEnum};

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
    count: u64,
    count_by_type: [u64; 7],
    spent: u128,  // total satoshis spent
    scripts: u64, // total decompressed script size
}

fn script_decode<D: bitcoin::io::Read>(d: &mut D, stats: &mut Stats) -> Result<ScriptBuf> {
    let len = varint_decode(d)?;
    stats.count += 1;
    Ok(if len < SPECIAL_SCRIPTS {
        let script_type = len as u8;
        let size = match script_type {
            0 | 1 => 20,
            2..=5 => 32,
            _ => unreachable!(),
        };
        stats.count_by_type[len] += 1;
        let compressed = decode_bytes(d, size)?;
        decompress_script(script_type, compressed)?
    } else {
        stats.count_by_type[6] += 1;
        let len = len - SPECIAL_SCRIPTS;
        ScriptBuf::from(decode_bytes(d, len)?)
    })
}

fn blockundo_decode(data: &[u8], stats: &mut Stats) -> Result<()> {
    let mut d = Cursor::new(data);
    let tx_count = VarInt::consensus_decode(&mut d)?.0;
    for _ in 0..tx_count {
        let txin_count = VarInt::consensus_decode(&mut d)?.0;
        for _ in 0..txin_count {
            let _height_coinbase = varint_decode(&mut d)?;
            assert_eq!(varint_decode(&mut d)?, 0); // unused today
            stats.spent += decompress_amount(varint_decode(&mut d)? as u64) as u128;
            let script = script_decode(&mut d, stats)?;
            stats.scripts += script.len() as u64;
        }
    }
    Ok(())
}

struct BlockVisitor<'a> {
    stats: &'a mut Stats,
}

impl bitcoin_slices::Visitor for BlockVisitor<'_> {
    fn visit_tx_out(&mut self, _vout: usize, tx_out: &bsl::TxOut) -> ControlFlow<()> {
        self.stats.scripts += tx_out.script_pubkey().len() as u64;
        ControlFlow::Continue(())
    }
}

fn block_decode(data: &[u8], stats: &mut Stats) -> Result<()> {
    let mut visit = BlockVisitor { stats };
    bsl::Block::visit(data, &mut visit).expect("invalid block");
    Ok(())
}

fn spenttxouts_decode(data: &[u8], stats: &mut Stats) -> Result<()> {
    let mut d = Cursor::new(data);
    let tx_count = VarInt::consensus_decode(&mut d)?.0;
    for _ in 0..tx_count {
        let txin_count = VarInt::consensus_decode(&mut d)?.0;
        for _ in 0..txin_count {
            let out = TxOut::consensus_decode_from_finite_reader(&mut d)?;
            stats.count += 1;
            stats.spent += out.value.to_sat() as u128;
            stats.scripts += out.script_pubkey.as_bytes().len() as u64;
        }
    }
    Ok(())
}

fn fetch_blockhashes(agent: &ureq::Agent, start: usize, count: usize) -> Result<Vec<BlockHash>> {
    let mut result = Vec::with_capacity(count);
    let mut height = start;
    let limit = start + count;
    while height < limit {
        let url = format!("http://localhost:8332/rest/blockhashbyheight/{}.hex", height);
        let response = agent.get(&url).call().map_err(|_| url)?;
        let hash = response.into_body().read_to_string()?;

        let url = format!(
            "http://localhost:8332/rest/headers/{}/{}.bin",
            min(2000, limit - height),
            &hash[..64]
        );
        let response = agent.get(&url).call().map_err(|_| url)?;
        let data = response.into_body().read_to_vec()?;
        let count = data.len() / Header::SIZE;
        let mut c = Cursor::new(data);
        for _ in 0..count {
            let h = Header::consensus_decode_from_finite_reader(&mut c)?;
            result.push(h.block_hash());
            height += 1;
        }
    }
    Ok(result)
}

#[derive(Clone, Debug, ValueEnum)]
enum Benchmark {
    Block,
    BlockUndo,
    SpentTxouts,
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
/// Bitcoin address indexer
struct Args {
    #[arg(value_enum, long = "start")]
    start: usize,

    #[arg(value_enum, long = "count")]
    count: usize,

    #[arg(value_enum, long = "type")]
    bench: Benchmark,
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    let chunk_size = 1_000;

    let agent = ureq::Agent::new_with_defaults();
    let hashes = fetch_blockhashes(&agent, args.start, args.count)?;
    log::info!("fetching {} blocks", hashes.len());
    let mut data = Vec::with_capacity(10_000_000);

    let url_prefix = match args.bench {
        Benchmark::Block => "http://localhost:8332/rest/block/",
        Benchmark::BlockUndo => "http://localhost:8332/rest/blockundo/",
        Benchmark::SpentTxouts => "http://localhost:8332/rest/spenttxouts/",
    };

    let mut height = args.start;
    for chunk in hashes.chunks(chunk_size) {
        let mut stats = Stats::default();
        let t = std::time::Instant::now();
        for hash in chunk {
            let url = match args.bench {
                Benchmark::Block => format!("{}{}.bin", url_prefix, hash),
                Benchmark::BlockUndo => format!("{}{}.bin", url_prefix, hash),
                Benchmark::SpentTxouts => format!("{}{}.bin", url_prefix, hash),
            };
            let response = agent.get(&url).call().map_err(|_| url)?;
            data.clear();
            response.into_body().into_reader().read_to_end(&mut data)?;

            match args.bench {
                Benchmark::Block => block_decode(&data, &mut stats)?,
                Benchmark::BlockUndo => blockundo_decode(&data, &mut stats)?,
                Benchmark::SpentTxouts => spenttxouts_decode(&data, &mut stats)?,
            };

            height += 1;
        }
        let duration = t.elapsed();
        log::info!(
            "{:?} @{} {}[us/call] {:?}",
            args.bench,
            height,
            duration.div_f32(chunk.len() as f32).as_micros(),
            stats,
        );
    }
    Ok(())
}
