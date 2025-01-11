use arrayvec::ArrayVec;
use clap::{Args, Parser};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};

const CHUNK_SIZE: usize = 512;
const MAX_PAYLOAD_SIZE: usize = 476;

#[derive(Parser)]
enum ClifArgs {
    Combine(CombineArgs),
    Generate(GenerateArgs),
}

#[derive(Args)]
struct CombineArgs {
    #[arg(short, long)]
    output: String,
    inputs: Vec<String>,
}

#[derive(Args)]
struct GenerateArgs {
    #[arg(short, long)]
    input: String,
    #[arg(short, long)]
    output: String,
    #[arg(short, long, default_value_t = 1)]
    page_size: u32,
    #[arg(short, long)]
    family: Option<u32>,
}

struct UF2Block {
    flags: u32,
    target_addr: u32,
    payload_size: u32,
    block_no: u32,
    num_blocks: u32,
    file_size: u32,
    data: [u8; MAX_PAYLOAD_SIZE],
}

impl UF2Block {
    const FAMILY_FLAG: u32 = 0x0000_2000;

    pub fn new(payload_size: u32, len: u32) -> Self {
        Self {
            flags: 0,
            target_addr: 0,
            payload_size,
            block_no: 0,
            num_blocks: (len + 1) / payload_size,
            file_size: len,
            data: [0; MAX_PAYLOAD_SIZE],
        }
    }

    pub fn set_family(&mut self, family: u32) {
        self.flags |= Self::FAMILY_FLAG;
        self.file_size = family;
    }

    pub fn as_chunk(&self) -> [u8; CHUNK_SIZE] {
        const MAGIC_START_0: u32 = 0x0A324655;
        const MAGIC_START_1: u32 = 0x9E5D5157;
        const MAGIC_END: u32 = 0x0AB16F30;

        let mut vec = ArrayVec::new();
        vec.extend(MAGIC_START_0.to_le_bytes());
        vec.extend(MAGIC_START_1.to_le_bytes());
        vec.extend(self.flags.to_le_bytes());
        vec.extend(self.target_addr.to_le_bytes());
        vec.extend(self.payload_size.to_le_bytes());
        vec.extend(self.block_no.to_le_bytes());
        vec.extend(self.num_blocks.to_le_bytes());
        vec.extend(self.file_size.to_le_bytes());
        vec.extend(self.data);
        vec.extend(MAGIC_END.to_le_bytes());
        vec.into_inner().unwrap()
    }
}

fn combine(args: CombineArgs) -> anyhow::Result<()> {
    let mut output = BufWriter::new(File::create(args.output)?);
    let mut buf = [0; CHUNK_SIZE];
    for file in args.inputs {
        let mut input = BufReader::new(File::open(file)?);
        input.read_exact(&mut buf)?;
        output.write_all(&buf)?;
    }
    Ok(())
}

fn generate(mut args: GenerateArgs) -> anyhow::Result<()> {
    let mut input = BufReader::new(File::open(args.input)?);
    let mut len = input.get_ref().metadata()?.len().try_into()?;
    if args.page_size > MAX_PAYLOAD_SIZE as u32 {
        args.page_size = 1;
    }
    if len % args.page_size != 0 {
        return anyhow::Result::Err(anyhow::Error::msg(format!(
            "Cannot write binary of len: {len} to device with page size: {}",
            args.page_size
        )));
    }
    let payload_size = args.page_size * (MAX_PAYLOAD_SIZE as u32 / args.page_size);
    let mut block = UF2Block::new(payload_size, len);
    if let Some(family) = args.family {
        block.set_family(family);
    }
    let mut output = BufWriter::new(File::create(args.output)?);
    while len > 0 {
        if len < payload_size {
            block.payload_size = len;
        }
        len -= block.payload_size;
        input.read_exact(&mut block.data[..block.payload_size as usize])?;
        output.write_all(&block.as_chunk())?;
        block.block_no += 1;
        block.target_addr += block.payload_size;
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    match ClifArgs::parse() {
        ClifArgs::Combine(args) => combine(args),
        ClifArgs::Generate(args) => generate(args),
    }
}
