use std::path::PathBuf;

use clap::Parser;

mod storage;

#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Args {
    #[arg(long)]
    db_path: Option<PathBuf>,

    #[arg(long, default_value_t = 0)]
    chain_id: u8,
}

fn main() {
    let args = Args::parse();
    println!("Hello, world!");
}
