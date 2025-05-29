use std::{io::Read, time::Duration};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

use bitcoin::{
    consensus::encode::{Decodable, VarInt},
    TxOut,
};

#[derive(Debug, Default)]
struct Stats{
    total: u64,
    value: u128,
}

fn spenttxouts_decode<D: bitcoin::io::Read>(d: &mut D, stats: &mut Stats) -> Result<()> {
    let tx_count = VarInt::consensus_decode(d)?.0;
    for _ in 0..tx_count {
        let txin_count = VarInt::consensus_decode(d)?.0;
        for _ in 0..txin_count {
            let out = TxOut::consensus_decode_from_finite_reader(d)?;
            stats.total += 1;
            stats.value += out.value.to_sat() as u128;
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
            let url = format!("http://localhost:8332/rest/blockhashbyheight/{}.hex", height + offset);
            let response = agent.get(url).call()?;
            let hash = response.into_body().read_to_string()?;

            let t = std::time::Instant::now();
            let url = format!("http://localhost:8332/rest/spenttxouts/{}.bin", &hash[..64]);
            let response = agent.get(url).call()?;
            response.into_body().into_reader().read_to_end(&mut data)?;
            let size = data.len() as u64;
            let mut c = bitcoin::io::Cursor::new(data);
            spenttxouts_decode(&mut c, &mut stats)?;
            assert_eq!(c.position(), size);
            data = c.into_inner();
            duration += t.elapsed();
            height += 1;
        }
        println!("[{}..{}) {}[us/call] {:?}", start_height, height, duration.div_f32(chunk_size as f32).as_micros(), stats);
    }
    Ok(())
}
