use arrayvec::ArrayVec;
use clap::{Args, Parser};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::num::ParseIntError;
use std::ops::Range;

use anyhow::{ensure, Context as _};

use crate::families::FAMILY_MAP;

mod families;

const CHUNK_SIZE: usize = 512;
const MAX_PAYLOAD_SIZE: usize = 476;

/// Simple tool for working with uf2 files
#[derive(Parser)]
enum ClifArgs {
    Combine(CombineArgs),
    Generate(GenerateArgs),
    Read(ReadArgs),
    Extract(ExtractArgs),
}

/// Combine multiple uf2 files into one
#[derive(Args)]
struct CombineArgs {
    #[arg(short, long)]
    output: String,
    inputs: Vec<String>,
}

/// Generate a uf2 from an arbitrary binary file
#[derive(Args)]
struct GenerateArgs {
    #[arg(short, long)]
    input: String,
    #[arg(short, long)]
    output: String,
    #[arg(short, long, default_value_t = 1, value_parser=parse_multibase_u32)]
    page_size: u32,
    #[arg(short, long, value_parser=parse_multibase_u32)]
    family: Option<u32>,
    #[arg(short, long, default_value_t = 0, value_parser=parse_multibase_u32)]
    target_addr_start: u32,
}

/// Read uf2 block metadata
#[derive(Args)]
struct ReadArgs {
    input: String,
    #[arg(short, long)]
    verbose: bool,
}

/// Extract binary data from uf2 files
#[derive(Args)]
struct ExtractArgs {
    #[arg(short, long)]
    input: String,
    #[arg(short, long)]
    output: String,
    #[arg(short, long, value_parser=parse_multibase_u32)]
    start_addr: u32,
    #[arg(short, long, value_parser=parse_multibase_u32)]
    end_addr: u32,
    #[arg(short, long, default_value_t = 0, value_parser=parse_multibase_u8)]
    /// Default value used if uf2 does not specify a value for this address
    fill_value: u8,
}

pub const fn split_radix(s: &str) -> (&str, u32) {
    let Some((prefix, val)) = s.split_at_checked(2) else {
        return (s, 10);
    };
    if prefix.eq_ignore_ascii_case("0x") {
        (val, 16)
    } else if prefix.eq_ignore_ascii_case("0o") {
        (val, 8)
    } else if prefix.eq_ignore_ascii_case("0b") {
        (val, 2)
    } else {
        (s, 10)
    }
}

pub const fn parse_multibase_u32(s: &str) -> Result<u32, ParseIntError> {
    let (val, radix) = split_radix(s);
    u32::from_str_radix(val, radix)
}

pub const fn parse_multibase_u8(s: &str) -> Result<u8, ParseIntError> {
    let (val, radix) = split_radix(s);
    u8::from_str_radix(val, radix)
}

#[derive(Clone, Debug)]
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
    const MAGIC_START_0: u32 = 0x0A324655;
    const MAGIC_START_1: u32 = 0x9E5D5157;
    const MAGIC_END: u32 = 0x0AB16F30;

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
        let mut vec = ArrayVec::new();
        vec.extend(Self::MAGIC_START_0.to_le_bytes());
        vec.extend(Self::MAGIC_START_1.to_le_bytes());
        vec.extend(self.flags.to_le_bytes());
        vec.extend(self.target_addr.to_le_bytes());
        vec.extend(self.payload_size.to_le_bytes());
        vec.extend(self.block_no.to_le_bytes());
        vec.extend(self.num_blocks.to_le_bytes());
        vec.extend(self.file_size.to_le_bytes());
        vec.extend(self.data);
        vec.extend(Self::MAGIC_END.to_le_bytes());
        vec.into_inner().unwrap()
    }

    pub fn read(block: &[u8; CHUNK_SIZE]) -> anyhow::Result<Self> {
        let magic_start_0 = u32::from_le_bytes(block[..4].try_into().unwrap());
        let magic_start_1 = u32::from_le_bytes(block[4..8].try_into().unwrap());
        let magic_end = u32::from_le_bytes(block[CHUNK_SIZE - 4..].try_into().unwrap());
        ensure!(
            magic_start_0 == Self::MAGIC_START_0,
            "Incorrect magic start 0 (expected 0x{:08X}, found 0x{magic_start_0:08X})",
            Self::MAGIC_START_0
        );
        ensure!(
            magic_start_1 == Self::MAGIC_START_1,
            "Incorrect magic start 1 (expected 0x{:08X}, found 0x{magic_start_1:08X})",
            Self::MAGIC_START_1
        );
        ensure!(
            magic_end == Self::MAGIC_END,
            "Incorrect magic end (expected 0x{:08X}, found 0x{magic_end:08X})",
            Self::MAGIC_END
        );
        Ok(Self {
            flags: u32::from_le_bytes(block[8..12].try_into().unwrap()),
            target_addr: u32::from_le_bytes(block[12..16].try_into().unwrap()),
            payload_size: u32::from_le_bytes(block[16..20].try_into().unwrap()),
            block_no: u32::from_le_bytes(block[20..24].try_into().unwrap()),
            num_blocks: u32::from_le_bytes(block[24..28].try_into().unwrap()),
            file_size: u32::from_le_bytes(block[28..32].try_into().unwrap()),
            data: block[32..CHUNK_SIZE - 4].try_into().unwrap(),
        })
    }

    fn payload(&self) -> &[u8] {
        &self.data[..self.payload_size as usize]
    }
}

fn display_block(
    block: UF2Block,
    w: &mut impl std::io::Write,
    verbose: bool,
) -> std::io::Result<()> {
    let not_main_flash = block.flags & 0x0000_0001 != 0;
    let file_container = block.flags & 0x0000_1000 != 0;
    let family_id = block.flags & 0x0000_2000 != 0;
    let md5_checksum = block.flags & 0x0000_4000 != 0;
    let extension_tags = block.flags & 0x0000_8000 != 0;

    let mut flags = ArrayVec::<_, 5>::new();
    if not_main_flash {
        let _ = flags.push("not main flash");
    }
    if file_container {
        let _ = flags.push("file container");
    }
    if family_id {
        let _ = flags.push("family id");
    }
    if md5_checksum {
        let _ = flags.push("md5 checksum");
    }
    if extension_tags {
        let _ = flags.push("extension tags");
    }
    let flags = flags.join(", ");
    writeln!(w, "flags: 0x{:08X} ({flags})", block.flags)?;
    writeln!(w, "target address: 0x{:08X}", block.target_addr)?;
    writeln!(w, "payload size: {}", block.payload_size)?;
    writeln!(w, "block number: {}", block.block_no)?;
    writeln!(w, "number of blocks: {}", block.num_blocks)?;
    if family_id {
        write!(w, "family id: 0x{:08X}", block.file_size)?;
        if let Some(family) = FAMILY_MAP.get(&block.file_size) {
            write!(w, " ({}", family.short_name)?;
            if verbose {
                write!(w, ": {}", family.description)?;
            }
            write!(w, ")")?;
        }
        writeln!(w)?;
    } else {
        writeln!(w, "file size: {}", block.file_size)?;
    }
    if file_container {
        'file_container: {
            if block.payload_size as usize > MAX_PAYLOAD_SIZE {
                if verbose {
                    write!(
                        w,
                        "Block's payload size {} exceeds max payload size {MAX_PAYLOAD_SIZE}, \
                        so the file name cannot be determined \
                        (this block has the \"file container\" flag set)",
                        block.payload_size,
                    )?;
                }
                break 'file_container;
            }
            let file_name_buf = &block.data[block.payload_size as usize..];
            if let Ok(file_name) = std::ffi::CStr::from_bytes_until_nul(file_name_buf) {
                writeln!(w, "file name: {}", file_name.to_string_lossy())?;
            } else if verbose {
                write!(
                    w,
                    "Expected block data from payload size to be a null-terminated \
                    file name because the \"file container\" flag is set, \
                    but no null byte found in the block"
                )?;
            }
        }
    }
    if md5_checksum {
        let md5_data = &block.data[MAX_PAYLOAD_SIZE - 24..];
        let region_start = u32::from_le_bytes(md5_data[..4].try_into().unwrap());
        let region_length = u32::from_le_bytes(md5_data[4..8].try_into().unwrap());
        let checksum_0 = u64::from_le_bytes(md5_data[8..16].try_into().unwrap());
        let checksum_1 = u64::from_le_bytes(md5_data[16..24].try_into().unwrap());
        writeln!(w, "md5 checksum region start: {region_start}")?;
        writeln!(w, "md5 checksum region length: {region_length}")?;
        writeln!(w, "md5 checksum: {checksum_0:08X}{checksum_1:08X}")?;
    }
    if extension_tags {
        'extension_tags: {
            writeln!(w, "extension tags: ")?;
            let mut head = (block.payload_size as usize).next_multiple_of(size_of::<u32>());
            while head <= MAX_PAYLOAD_SIZE - 4 {
                let rem = &block.data[head..];
                let ext_len = rem[0] as usize;
                if ext_len > rem.len() {
                    if verbose {
                        write!(
                            w,
                            "Extension length {ext_len} exceeds length of the data buffer"
                        )?;
                    }
                    break 'extension_tags;
                }
                let ext_type = u32::from_le_bytes(rem[..4].try_into().unwrap()) & 0x00_FF_FF_FF;

                if ext_len == 0 && ext_type == 0 {
                    break 'extension_tags;
                }

                let ext_data = &rem[..ext_len];
                write!(w, "    ")?;
                write_extension(w, ext_type, ext_data)?;
                head = (head + ext_len).next_multiple_of(size_of::<u32>());
            }
        }
    }
    if verbose {
        writeln!(
            w,
            "block data (hex): {:02X?}",
            &block.data[..block.payload_size as usize]
        )?;
    }
    writeln!(w)?;
    Ok(())
}

fn write_extension(
    w: &mut impl std::io::Write,
    ext_type: u32,
    ext_data: &[u8],
) -> std::io::Result<()> {
    match ext_type {
        0x9F_C7_BC => {
            writeln!(w, "version: {}", String::from_utf8_lossy(ext_data))
        }
        0x65_0D_9D => {
            writeln!(
                w,
                "device description: {}",
                String::from_utf8_lossy(ext_data)
            )
        }
        0x0B_E9_F7 => {
            write!(w, "target device page size: ")?;
            if let Ok(buf) = ext_data.try_into() {
                writeln!(w, "{}", u32::from_le_bytes(buf))
            } else {
                writeln!(w, "{ext_data:?}")
            }
        }
        0xB4_6D_B0 => {
            writeln!(w, "SHA-2 firmware checksum: {ext_data:?}")
        }
        0xC8_A7_29 => {
            write!(w, "device type identifier: ")?;
            if let Ok(buf) = ext_data.try_into() {
                writeln!(w, "0x{:016X}", u64::from_le_bytes(buf))
            } else if let Ok(buf) = ext_data.try_into() {
                writeln!(w, "0x{:08X}", u32::from_le_bytes(buf))
            } else {
                writeln!(w, "{ext_data:?}")
            }
        }
        _ => {
            writeln!(w, "extension type 0x{ext_type:06X}: {ext_data:?}")
        }
    }
}

fn combine(args: CombineArgs) -> anyhow::Result<()> {
    let mut output =
        BufWriter::new(File::create(args.output).context("Failed to create output file")?);
    for file in args.inputs {
        let mut input = BufReader::new(
            File::open(&file).with_context(|| format!("Failed to open input file {file}"))?,
        );
        std::io::copy(&mut input, &mut output).with_context(|| {
            format!("Failed to copy data from input file {file} to output file")
        })?;
    }
    Ok(())
}

fn generate(mut args: GenerateArgs) -> anyhow::Result<()> {
    let mut input = BufReader::new(File::open(args.input).context("Failed to open input file")?);
    let mut len: u32 = input
        .get_ref()
        .metadata()
        .context("Failed to get input file metadata")?
        .len()
        .try_into()?;
    if args.page_size > MAX_PAYLOAD_SIZE as u32 {
        args.page_size = 1;
    }
    ensure!(
        len.is_multiple_of(args.page_size),
        "Cannot write binary of len: {len} to device with page size: {}",
        args.page_size
    );
    let payload_size = args.page_size * (MAX_PAYLOAD_SIZE as u32 / args.page_size);
    let mut block = UF2Block::new(payload_size, len);
    if let Some(family) = args.family {
        block.set_family(family);
    }
    block.target_addr = args.target_addr_start;
    let mut output =
        BufWriter::new(File::create(args.output).context("Failed to create output file")?);
    while len > 0 {
        if len < payload_size {
            block.payload_size = len;
        }
        len -= block.payload_size;
        input
            .read_exact(&mut block.data[..block.payload_size as usize])
            .context("Failed to read UF2 Block data from input")?;
        output
            .write_all(&block.as_chunk())
            .context("Failed to write UF2 block to output")?;
        block.block_no += 1;
        block.target_addr += block.payload_size;
    }
    Ok(())
}

fn read(args: ReadArgs) -> anyhow::Result<()> {
    let mut input = BufReader::new(File::open(&args.input).context("Failed to open input file")?);
    let len: usize = input
        .get_ref()
        .metadata()
        .context("Failed to get metadata for input file")?
        .len()
        .try_into()?;
    ensure!(
        len.is_multiple_of(CHUNK_SIZE),
        "Cannot read {} of len {len}. Must be a multiple of {CHUNK_SIZE}",
        args.input
    );
    let mut buf = [0u8; CHUNK_SIZE];
    while let Ok(()) = input.read_exact(&mut buf) {
        let block = UF2Block::read(&buf).context("Failed to parse UF2 Block")?;
        display_block(block, &mut std::io::stdout(), args.verbose)
            .context("Failed to write to stdout")?;
    }
    Ok(())
}

fn range_add(mut range: Range<u32>, offset: u32) -> Range<u32> {
    range.start += offset;
    range.end += offset;
    range
}

fn range_sub(mut range: Range<u32>, offset: u32) -> Range<u32> {
    range.start -= offset;
    range.end -= offset;
    range
}

fn range_intersect(a: Range<u32>, b: Range<u32>) -> Range<u32> {
    u32::max(a.start, b.start)..u32::min(a.end, b.end)
}

fn range_index(r: Range<u32>) -> Range<usize> {
    r.start as usize..r.end as usize
}

fn extract(args: ExtractArgs) -> anyhow::Result<()> {
    let mut input = BufReader::new(File::open(&args.input).context("Failed to open input file")?);
    let len: usize = input
        .get_ref()
        .metadata()
        .context("Failed to get metadata for input file")?
        .len()
        .try_into()?;
    ensure!(
        len.is_multiple_of(CHUNK_SIZE),
        "Cannot read {} of len {len}. Must be a multiple of {CHUNK_SIZE}",
        args.input
    );
    let output_range = args.start_addr..args.end_addr;
    let mut input_buf = [0u8; CHUNK_SIZE];
    let mut output_buf = vec![args.fill_value; output_range.len()];
    while let Ok(()) = input.read_exact(&mut input_buf) {
        let block = UF2Block::read(&input_buf).context("Failed to parse UF2 block")?;
        let block_range = range_add(0..block.payload_size, block.target_addr);
        let intersect_range = range_intersect(output_range.clone(), block_range);
        if intersect_range.is_empty() {
            continue;
        }
        let block_rel_intersection = range_sub(intersect_range.clone(), block.target_addr);
        let output_rel_intersection = range_sub(intersect_range.clone(), args.start_addr);
        output_buf[range_index(output_rel_intersection)]
            .copy_from_slice(&block.payload()[range_index(block_rel_intersection)]);
    }
    let mut output = File::create(&args.output).context("Failed to create output file")?;
    output
        .write_all(&output_buf)
        .context("Failed to write to output file")?;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    match ClifArgs::parse() {
        ClifArgs::Combine(args) => combine(args),
        ClifArgs::Generate(args) => generate(args),
        ClifArgs::Read(args) => read(args),
        ClifArgs::Extract(args) => extract(args),
    }
}
