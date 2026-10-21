use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use chrono::Local;
use clap::{Args as ClapArgs, Parser, Subcommand};
use futures::StreamExt;
use kcp::Kcp;
use pktmon::filter::{PktMonFilter, TransportProtocol};
use pktmon::{Capture, PacketPayload};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::time;
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

mod session_pad;
mod single_pad;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Passive UDP capture scout for Zenless Zone Zero drive-disc research"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    #[command(flatten)]
    capture: CaptureArgs,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Analyze a capture run directory produced by this tool.
    Analyze(AnalyzeArgs),
    /// Extract and reassemble the largest miHoYo KCP-like conversation.
    Extract(ExtractArgs),
    /// Parse reassembled game-message envelopes and report command IDs.
    Commands(CommandsArgs),
    /// Scan command bodies for plausible decrypted protobuf wire data.
    CryptoScan(CryptoScanArgs),
    /// Recover the 4096-byte MT19937-64 session XOR pads from two captures.
    PadCrack(PadCrackArgs),
    /// Parse the version-specific GetEquipDataScRsp from decrypted command bodies.
    DecodeEquip(DecodeEquipArgs),
    /// Report known-plaintext recovery hints for PlayerGetTokenCsReq.
    PadRecover(PadRecoverArgs),
    /// Read the current dispatch version and seed from a local game install.
    DispatchScan(DispatchScanArgs),
}

#[derive(ClapArgs, Debug)]
struct AnalyzeArgs {
    /// Capture run directory, e.g. captures/zzz-capture-YYYYMMDD-HHMMSS.
    run_dir: PathBuf,

    /// Number of top rows to print per section.
    #[arg(long, default_value_t = 20)]
    top: usize,
}

#[derive(ClapArgs, Debug)]
struct ExtractArgs {
    /// Capture run directory, e.g. captures/zzz-capture-YYYYMMDD-HHMMSS.
    run_dir: PathBuf,

    /// Replace an existing extracted directory.
    #[arg(long)]
    force: bool,
}

#[derive(ClapArgs, Debug)]
struct CommandsArgs {
    /// Capture run directory containing extracted/messages.jsonl.
    run_dir: PathBuf,

    /// Replace existing command output files.
    #[arg(long)]
    force: bool,
}

#[derive(ClapArgs, Debug)]
struct CryptoScanArgs {
    /// Capture run directory containing extracted/commands/commands.jsonl.
    run_dir: PathBuf,

    /// Raw 4096-byte initial XOR pad file.
    #[arg(long)]
    xorpad: Option<PathBuf>,

    /// Number of highest-scoring rows to print.
    #[arg(long, default_value_t = 40)]
    top: usize,
}

#[derive(ClapArgs, Debug)]
struct DecodeEquipArgs {
    /// Capture run directory containing extracted/commands/commands.jsonl.
    run_dir: PathBuf,

    /// Raw 4096-byte XOR pad to apply before parsing.
    #[arg(long)]
    xorpad: Option<PathBuf>,

    /// Output JSON path. Defaults to extracted/commands/equip.json.
    #[arg(long)]
    output: Option<PathBuf>,

    /// Replace an existing output file.
    #[arg(long)]
    force: bool,
}

#[derive(ClapArgs, Debug)]
struct PadCrackArgs {
    /// First capture run directory.
    run_a: PathBuf,

    /// Second capture run directory, same account and game version, inventory unchanged.
    run_b: PathBuf,

    /// Directory to write the recovered pads and seed metadata into.
    #[arg(long, default_value = "tools")]
    out_dir: PathBuf,

    /// Smallest shared body length to consider as known plaintext.
    #[arg(long, default_value_t = 8192)]
    min_body_len: usize,
}

#[derive(ClapArgs, Debug)]
struct PadRecoverArgs {
    /// Capture run directories containing extracted/commands/commands.jsonl.
    run_dirs: Vec<PathBuf>,

    /// Number of stable prefix bytes to print.
    #[arg(long, default_value_t = 64)]
    preview: usize,
}

#[derive(ClapArgs, Debug)]
struct DispatchScanArgs {
    /// Zenless Zone Zero game directory containing version_info and resources.assets.
    game_dir: PathBuf,
}

#[derive(ClapArgs, Debug)]
struct CaptureArgs {
    /// Capture duration in seconds. Use 0 to run until Ctrl+C.
    #[arg(short, long, default_value_t = 180)]
    seconds: u64,

    /// Output directory for this run.
    #[arg(short, long, default_value = "captures")]
    output: PathBuf,

    /// Keep only packets where either UDP port is in this inclusive range, e.g. 20000-30000.
    #[arg(long)]
    port_range: Option<String>,

    /// Keep only packets where either UDP port equals this value. Can be repeated.
    #[arg(long)]
    port: Vec<u16>,

    /// Write every kept UDP payload to an individual .bin file.
    #[arg(long, default_value_t = true)]
    dump_payloads: bool,

    /// Minimum UDP payload length to dump.
    #[arg(long, default_value_t = 16)]
    min_dump_len: usize,
}

#[derive(Debug, Clone, Copy)]
struct PortRange {
    start: u16,
    end: u16,
}

#[derive(Debug)]
struct UdpPacket {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    payload: Vec<u8>,
}

#[derive(Debug, Default)]
struct PortStats {
    packets: u64,
    bytes: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    if let Some(command) = cli.command {
        match command {
            Command::Analyze(args) => analyze_capture(args)?,
            Command::Extract(args) => extract_capture(args)?,
            Command::Commands(args) => parse_commands(args)?,
            Command::CryptoScan(args) => crypto_scan(args)?,
            Command::PadCrack(args) => pad_crack(args)?,
            Command::DecodeEquip(args) => decode_equip(args)?,
            Command::PadRecover(args) => pad_recover(args)?,
            Command::DispatchScan(args) => dispatch_scan(args)?,
        }
        return Ok(());
    }

    capture(cli.capture).await
}

async fn capture(args: CaptureArgs) -> Result<()> {
    let port_range = args
        .port_range
        .as_deref()
        .map(parse_port_range)
        .transpose()?;

    let run_dir = args
        .output
        .join(Local::now().format("zzz-capture-%Y%m%d-%H%M%S").to_string());
    let payload_dir = run_dir.join("payloads");
    fs::create_dir_all(&payload_dir)
        .with_context(|| format!("creating {}", payload_dir.display()))?;

    let metadata_path = run_dir.join("packets.jsonl");
    let mut metadata = BufWriter::new(File::create(&metadata_path)?);

    info!("starting UDP capture");
    info!("output: {}", run_dir.display());
    if let Some(range) = port_range {
        info!("post-filtering ports {}-{}", range.start, range.end);
    }
    for port in &args.port {
        info!("post-filtering port {}", port);
    }

    let mut capture =
        Capture::new().context("creating pktmon capture; try running as administrator")?;
    capture
        .add_filter(PktMonFilter {
            name: "UDP".to_string(),
            transport_protocol: Some(TransportProtocol::UDP),
            ..PktMonFilter::default()
        })
        .context("adding pktmon UDP filter")?;

    let mut stream = capture.stream().context("opening pktmon stream")?;
    let deadline = if args.seconds == 0 {
        None
    } else {
        Some(Instant::now() + Duration::from_secs(args.seconds))
    };

    let mut packet_index = 0_u64;
    let mut kept_index = 0_u64;
    let mut stats: BTreeMap<u16, PortStats> = BTreeMap::new();

    loop {
        let next_packet = stream.next();

        let packet = if let Some(deadline) = deadline {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            match time::timeout(deadline - now, next_packet).await {
                Ok(Some(packet)) => packet,
                Ok(None) => break,
                Err(_) => break,
            }
        } else {
            tokio::select! {
                packet = next_packet => {
                    let Some(packet) = packet else { break };
                    packet
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("received Ctrl+C");
                    break;
                }
            }
        };

        packet_index += 1;
        let PacketPayload::Ethernet(frame) = packet.payload else {
            debug!("ignored non-ethernet packet");
            continue;
        };
        let Some(udp) = parse_ethernet_udp(&frame) else {
            continue;
        };
        if !port_allowed(&udp, port_range, &args.port) {
            continue;
        }

        kept_index += 1;
        stats
            .entry(udp.src_port)
            .and_modify(|s| {
                s.packets += 1;
                s.bytes += udp.payload.len() as u64;
            })
            .or_insert(PortStats {
                packets: 1,
                bytes: udp.payload.len() as u64,
            });
        stats
            .entry(udp.dst_port)
            .and_modify(|s| {
                s.packets += 1;
                s.bytes += udp.payload.len() as u64;
            })
            .or_insert(PortStats {
                packets: 1,
                bytes: udp.payload.len() as u64,
            });

        let payload_file = if args.dump_payloads && udp.payload.len() >= args.min_dump_len {
            let file_name = format!("{kept_index:08}_{}-{}.bin", udp.src_port, udp.dst_port);
            let path = payload_dir.join(file_name);
            fs::write(&path, &udp.payload)?;
            Some(path.file_name().unwrap().to_string_lossy().to_string())
        } else {
            None
        };

        let preview_len = udp.payload.len().min(16);
        let row = json!({
            "index": kept_index,
            "source_index": packet_index,
            "src_ip": udp.src_ip.to_string(),
            "dst_ip": udp.dst_ip.to_string(),
            "src_port": udp.src_port,
            "dst_port": udp.dst_port,
            "payload_len": udp.payload.len(),
            "payload_preview_hex": hex::encode(&udp.payload[..preview_len]),
            "payload_file": payload_file,
        });
        writeln!(metadata, "{row}")?;
    }

    metadata.flush()?;
    write_summary(&run_dir, kept_index, &stats)?;
    info!(
        "captured {} packets, kept {} UDP packets",
        packet_index, kept_index
    );
    info!("metadata: {}", metadata_path.display());
    Ok(())
}

#[derive(Debug, Default)]
struct ConversationStats {
    packets: u64,
    bytes: u64,
    kcp_like: u64,
    lengths: BTreeMap<usize, u64>,
    first_preview_hex: Option<String>,
    push_packets: u64,
    fragmented_push_packets: u64,
    min_sn: Option<u32>,
    max_sn: Option<u32>,
}

#[derive(Debug)]
struct PacketRow {
    index: u64,
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    payload_len: usize,
    payload_preview_hex: String,
    payload_file: Option<String>,
}

fn analyze_capture(args: AnalyzeArgs) -> Result<()> {
    let metadata_path = args.run_dir.join("packets.jsonl");
    let payload_dir = args.run_dir.join("payloads");
    let rows = read_packet_rows(&metadata_path)?;

    let mut total_packets = 0_u64;
    let mut total_bytes = 0_u64;
    let mut ports: BTreeMap<u16, PortStats> = BTreeMap::new();
    let mut conversations: BTreeMap<String, ConversationStats> = BTreeMap::new();

    for row in rows {
        total_packets += 1;
        total_bytes += row.payload_len as u64;
        bump_port(&mut ports, row.src_port, row.payload_len);
        bump_port(&mut ports, row.dst_port, row.payload_len);

        let key = conversation_key(&row);
        let payload = row
            .payload_file
            .as_ref()
            .and_then(|name| fs::read(payload_dir.join(name)).ok());
        let kcp_like = payload.as_deref().is_some_and(is_mhy_kcp_like);

        let stats = conversations.entry(key).or_default();
        stats.packets += 1;
        stats.bytes += row.payload_len as u64;
        stats.kcp_like += u64::from(kcp_like);
        *stats.lengths.entry(row.payload_len).or_insert(0) += 1;
        if stats.first_preview_hex.is_none() {
            stats.first_preview_hex = Some(row.payload_preview_hex);
        }
        if let Some(payload) = payload.as_deref() {
            for segment in parse_mhy_segments(payload).unwrap_or_default() {
                if segment.cmd == 0x51 {
                    stats.push_packets += 1;
                    stats.fragmented_push_packets += u64::from(segment.frg > 0);
                    stats.min_sn = Some(stats.min_sn.map_or(segment.sn, |sn| sn.min(segment.sn)));
                    stats.max_sn = Some(stats.max_sn.map_or(segment.sn, |sn| sn.max(segment.sn)));
                }
            }
        }
    }

    let mut report = String::new();
    push_line(
        &mut report,
        format!(
            "Capture: {}\nPackets: {}\nBytes: {}\n",
            args.run_dir.display(),
            total_packets,
            total_bytes
        ),
    );

    push_line(&mut report, "Top ports by bytes:");
    let mut port_rows: Vec<_> = ports.iter().collect();
    port_rows.sort_by_key(|(_, stat)| std::cmp::Reverse(stat.bytes));
    for (port, stat) in port_rows.into_iter().take(args.top) {
        push_line(
            &mut report,
            format!("  {port}: packets={} bytes={}", stat.packets, stat.bytes),
        );
    }

    push_line(&mut report, "\nTop conversations by bytes:");
    let mut conv_rows: Vec<_> = conversations.iter().collect();
    conv_rows.sort_by_key(|(_, stat)| std::cmp::Reverse(stat.bytes));
    for (key, stat) in conv_rows.iter().take(args.top) {
        let ratio = if stat.packets == 0 {
            0.0
        } else {
            stat.kcp_like as f64 / stat.packets as f64
        };
        push_line(
            &mut report,
            format!(
                "  {key}: packets={} bytes={} mhy_kcp_like={:.1}% first={}",
                stat.packets,
                stat.bytes,
                ratio * 100.0,
                stat.first_preview_hex.as_deref().unwrap_or("")
            ),
        );
        if stat.push_packets > 0 {
            push_line(
                &mut report,
                format!(
                    "    push={} fragmented={} sn={}..{}",
                    stat.push_packets,
                    stat.fragmented_push_packets,
                    stat.min_sn.unwrap_or(0),
                    stat.max_sn.unwrap_or(0)
                ),
            );
        }
    }

    if let Some((key, stat)) = conv_rows.first() {
        push_line(
            &mut report,
            format!("\nPayload lengths for largest conversation ({key}):"),
        );
        let mut length_rows: Vec<_> = stat.lengths.iter().collect();
        length_rows.sort_by_key(|(_, count)| std::cmp::Reverse(**count));
        for (len, count) in length_rows.into_iter().take(args.top) {
            push_line(&mut report, format!("  {len}: {count}"));
        }
    }

    let report_path = args.run_dir.join("analysis.txt");
    fs::write(&report_path, &report)?;
    print!("{report}");
    info!("analysis written to {}", report_path.display());
    Ok(())
}

struct KcpReceiver {
    kcp: Kcp<Vec<u8>>,
    base_sn: u32,
    max_normalized_sn: u32,
    frg_at_max_sn: u8,
}

fn extract_capture(args: ExtractArgs) -> Result<()> {
    let metadata_path = args.run_dir.join("packets.jsonl");
    let payload_dir = args.run_dir.join("payloads");
    let rows = read_packet_rows(&metadata_path)?;

    let mut candidates: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for row in &rows {
        let Some(payload) = read_row_payload(&payload_dir, row)? else {
            continue;
        };
        if is_mhy_kcp_like(&payload) {
            let stats = candidates.entry(conversation_key(row)).or_default();
            stats.0 += 1;
            stats.1 += payload.len() as u64;
        }
    }
    let (selected, (packet_count, byte_count)) = candidates
        .into_iter()
        .max_by_key(|(_, (_, bytes))| *bytes)
        .context("no miHoYo KCP-like conversation found")?;

    let output_dir = args.run_dir.join("extracted");
    if output_dir.exists() {
        if !args.force {
            bail!(
                "{} already exists; pass --force to replace it",
                output_dir.display()
            );
        }
        fs::remove_dir_all(&output_dir)?;
    }
    fs::create_dir_all(&output_dir)?;
    let mut manifest = BufWriter::new(File::create(output_dir.join("messages.jsonl"))?);
    let mut receivers: BTreeMap<(String, u32), KcpReceiver> = BTreeMap::new();
    let mut direction_counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut message_index = 0_u64;
    let mut segment_count = 0_u64;
    let mut parse_errors = 0_u64;
    let mut input_errors = 0_u64;
    let mut discarded_partial_messages = 0_u64;

    for row in rows.iter().filter(|row| conversation_key(row) == selected) {
        let Some(payload) = read_row_payload(&payload_dir, row)? else {
            continue;
        };
        let segments = match parse_mhy_segments(&payload) {
            Ok(segments) => segments,
            Err(_) => {
                parse_errors += 1;
                continue;
            }
        };
        let direction = format!("{}-{}", row.src_port, row.dst_port);
        for segment in segments {
            segment_count += 1;
            if segment.cmd != 0x51 {
                continue;
            }
            let conv = segment.conv;
            let receiver = receivers
                .entry((direction.clone(), conv))
                .or_insert_with(|| {
                    let mut kcp = Kcp::new(conv, Vec::new());
                    kcp.set_wndsize(1024, 1024);
                    KcpReceiver {
                        kcp,
                        base_sn: segment.sn,
                        max_normalized_sn: 0,
                        frg_at_max_sn: segment.frg,
                    }
                });
            let mut normalized = segment.standard;
            let normalized_sn = segment.sn.wrapping_sub(receiver.base_sn);
            if normalized_sn > receiver.max_normalized_sn {
                receiver.max_normalized_sn = normalized_sn;
                receiver.frg_at_max_sn = segment.frg;
            }
            normalized[12..16].copy_from_slice(&normalized_sn.to_le_bytes());
            if receiver.kcp.input(&normalized).is_err() {
                input_errors += 1;
                continue;
            }
            while let Ok(size) = receiver.kcp.peeksize() {
                let mut message = vec![0_u8; size];
                if receiver.kcp.recv(&mut message).is_err() {
                    break;
                }
                if parse_game_envelope(&message).is_err() {
                    discarded_partial_messages += 1;
                    continue;
                }
                message_index += 1;
                let count = direction_counts.entry(direction.clone()).or_default();
                *count += 1;
                let file_name = format!("message-{message_index:06}_{direction}_{count:06}.bin");
                fs::write(output_dir.join(&file_name), &message)?;
                writeln!(
                    manifest,
                    "{}",
                    json!({
                        "message_index": message_index,
                        "capture_packet_index": row.index,
                        "direction": direction,
                        "src_ip": row.src_ip,
                        "src_port": row.src_port,
                        "dst_ip": row.dst_ip,
                        "dst_port": row.dst_port,
                        "conv": conv,
                        "length": message.len(),
                        "file": file_name,
                        "preview_hex": hex::encode(&message[..message.len().min(32)]),
                    })
                )?;
            }
        }
    }
    manifest.flush()?;

    let unfinished_tails: Vec<_> = receivers
        .iter()
        .filter(|(_, receiver)| receiver.frg_at_max_sn > 0)
        .collect();
    let mut summary = format!(
        "Conversation: {selected}\nInput KCP-like packets: {packet_count}\nInput bytes: {byte_count}\nParsed segments: {segment_count}\nReassembled messages: {message_index}\nDiscarded partial messages: {discarded_partial_messages}\nUnfinished fragmented tails: {}\nParse errors: {parse_errors}\nKCP input errors: {input_errors}\n",
        unfinished_tails.len()
    );
    for ((direction, conv), receiver) in unfinished_tails {
        push_line(
            &mut summary,
            format!(
                "  {direction} conv=0x{conv:08X}: highest_sn={} frg={} (at least {} fragments missing)",
                receiver.base_sn.wrapping_add(receiver.max_normalized_sn),
                receiver.frg_at_max_sn,
                receiver.frg_at_max_sn
            ),
        );
    }
    fs::write(output_dir.join("summary.txt"), &summary)?;
    print!("{summary}");
    info!("extracted messages written to {}", output_dir.display());
    Ok(())
}

#[derive(Debug)]
struct MessageManifestRow {
    message_index: u64,
    direction: String,
    file: String,
}

#[derive(Debug)]
struct GameEnvelope<'a> {
    command_id: u16,
    metadata: &'a [u8],
    body: &'a [u8],
}

#[derive(Debug, Default)]
struct CommandStats {
    count: u64,
    total_body_bytes: u64,
    min_body_len: usize,
    max_body_len: usize,
}

#[derive(Debug, Clone)]
struct CommandManifestRow {
    message_index: u64,
    direction: String,
    command_id: u16,
    metadata_len: usize,
    body_len: usize,
    body_file: String,
}

#[derive(Debug)]
struct ProtoScan {
    valid: bool,
    fields: usize,
    varints: usize,
    fixed32: usize,
    fixed64: usize,
    len_delimited: usize,
    utf8_strings: usize,
    max_field_number: u64,
    first_fields: Vec<String>,
    error: Option<String>,
}

#[derive(Debug)]
struct CryptoScanHit {
    score: i64,
    variant: &'static str,
    row: CommandManifestRow,
    scan: ProtoScan,
    preview_hex: String,
}

struct LoadedXorpad {
    source: String,
    pad: [u8; 4096],
}

#[derive(Debug, Serialize)]
struct EquipDecodeOutput {
    source: String,
    schema: String,
    command_id_hex: String,
    message_index: u64,
    direction: String,
    body_len: usize,
    xorpad: Option<String>,
    suit_ids: Vec<u32>,
    equip_count: usize,
    equip_list: Vec<EquipInfoDecoded>,
}

/// A decoded drive disc. Field locations are selected by the capture's schema.
#[derive(Debug, Default, Serialize)]
struct EquipInfoDecoded {
    uid: u32,
    id: u32,
    suit_id: u32,
    rarity: u32,
    slot: u32,
    level: u32,
    star: u32,
    lock: bool,
    marked: bool,
    /// A version-specific scalar whose semantic name and XOR constant are unresolved.
    unresolved_scalar_field: u32,
    unresolved_scalar_raw: Option<u64>,
    /// Present boolean fields whose semantics have not yet been verified.
    unresolved_bool_fields: BTreeMap<u32, bool>,
    main_property: Option<EquipPropertyDecoded>,
    sub_properties: Vec<EquipPropertyDecoded>,
    unknown_fields: Vec<String>,
}

#[derive(Debug, Default, Serialize)]
struct EquipPropertyDecoded {
    key: u32,
    base_value: u32,
    count: u32,
    /// `base_value * count`, the value the game shows for a substat.
    total_value: u32,
    unknown_fields: Vec<String>,
}

#[derive(Debug, Default)]
struct GetEquipDataDecoded {
    suit_ids: Vec<u32>,
    equip_list: Vec<EquipInfoDecoded>,
}

struct ProtoReader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> ProtoReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn is_empty(&self) -> bool {
        self.offset >= self.data.len()
    }

    fn position(&self) -> usize {
        self.offset
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.offset)
    }

    fn read_varint(&mut self) -> Result<u64> {
        let start = self.offset;
        let Some((value, len)) = read_varint(&self.data[self.offset..]) else {
            bail!("bad protobuf varint at offset {start}");
        };
        self.offset += len;
        Ok(value)
    }

    fn read_key(&mut self) -> Result<(u32, u8)> {
        let start = self.offset;
        let key = self.read_varint()?;
        if key == 0 {
            bail!("zero protobuf key at offset {start}");
        }
        let field_number = (key >> 3) as u32;
        let wire_type = (key & 0x07) as u8;
        if field_number == 0 {
            bail!("zero protobuf field number at offset {start}");
        }
        Ok((field_number, wire_type))
    }

    fn read_len_bytes(&mut self) -> Result<&'a [u8]> {
        let len = self.read_varint()? as usize;
        if self.remaining() < len {
            bail!(
                "truncated protobuf length-delimited field at offset {}, need {len} bytes, have {}",
                self.offset,
                self.remaining()
            );
        }
        let start = self.offset;
        self.offset += len;
        Ok(&self.data[start..self.offset])
    }

    fn skip_field_value(&mut self, wire_type: u8) -> Result<()> {
        match wire_type {
            0 => {
                self.read_varint()?;
            }
            1 => self.skip_bytes(8)?,
            2 => {
                self.read_len_bytes()?;
            }
            5 => self.skip_bytes(4)?,
            _ => bail!(
                "unsupported protobuf wire type {wire_type} at offset {}",
                self.offset
            ),
        }
        Ok(())
    }

    fn skip_bytes(&mut self, len: usize) -> Result<()> {
        if self.remaining() < len {
            bail!(
                "truncated protobuf fixed-width field at offset {}, need {len} bytes, have {}",
                self.offset,
                self.remaining()
            );
        }
        self.offset += len;
        Ok(())
    }
}

fn pad_crack(args: PadCrackArgs) -> Result<()> {
    let rows_a = read_command_manifest_rows(
        &args
            .run_a
            .join("extracted")
            .join("commands")
            .join("commands.jsonl"),
    )?;
    let rows_b = read_command_manifest_rows(
        &args
            .run_b
            .join("extracted")
            .join("commands")
            .join("commands.jsonl"),
    )?;
    println!(
        "{}: {} commands\n{}: {} commands",
        args.run_a.display(),
        rows_a.len(),
        args.run_b.display(),
        rows_b.len()
    );

    let (row_a, row_b, diff) = find_shared_pad_difference(
        &args.run_a,
        &rows_a,
        &args.run_b,
        &rows_b,
        args.min_body_len,
    )?;
    println!(
        "\nshared body: cmd 0x{:04X}, {} bytes (msg {} vs msg {})",
        row_a.command_id, row_a.body_len, row_a.message_index, row_b.message_index
    );
    println!(
        "  difference is exactly {}-periodic; first 16 bytes: {}",
        session_pad::PAD_LEN,
        hex_prefix(&diff, 16)
    );

    let check = session_pad::check_recurrence(&diff, true);
    println!(
        "  MT19937-64 recurrence check (big-endian): {}/{}",
        check.hits, check.total
    );
    if check.hits != check.total {
        let le = session_pad::check_recurrence(&diff, false);
        bail!(
            "the pad difference does not obey the MT19937-64 recurrence \
             (big-endian {}/{}, little-endian {}/{}); the pad generator may have changed \
             in this game version",
            check.hits,
            check.total,
            le.hits,
            le.total
        );
    }
    let init_diff = check
        .init_diff
        .context("recurrence matched but the twist could not be inverted")?;

    let mut verified = Vec::new();
    for (seed_a, seed_b) in session_pad::recover_seeds(&init_diff) {
        let pad_a = session_pad::generate_xorpad(seed_a, true);
        let pad_b = session_pad::generate_xorpad(seed_b, true);
        if (0..session_pad::PAD_LEN).all(|i| pad_a[i] ^ pad_b[i] == diff[i]) {
            verified.push((seed_a, seed_b, pad_a, pad_b));
        }
    }
    let (mut seed_a, mut seed_b, mut pad_a, mut pad_b) = verified
        .into_iter()
        .next()
        .context("no recovered seed pair reproduces the observed pad difference")?;

    let own_a = score_pad_against(&args.run_a, &rows_a, &pad_a)?;
    let cross_a = score_pad_against(&args.run_a, &rows_a, &pad_b)?;
    if cross_a.ok > own_a.ok {
        std::mem::swap(&mut seed_a, &mut seed_b);
        std::mem::swap(&mut pad_a, &mut pad_b);
    }
    let own_a = score_pad_against(&args.run_a, &rows_a, &pad_a)?;
    let cross_a = score_pad_against(&args.run_a, &rows_a, &pad_b)?;
    let own_b = score_pad_against(&args.run_b, &rows_b, &pad_b)?;
    let cross_b = score_pad_against(&args.run_b, &rows_b, &pad_a)?;

    println!("\nrecovered seeds: {seed_a:#018x} and {seed_b:#018x}");
    println!("\nstrict protobuf validation (own pad vs the other session's pad):");
    println!(
        "  {}: {}/{} own, {}/{} cross",
        args.run_a.display(),
        own_a.ok,
        own_a.total,
        cross_a.ok,
        cross_a.total
    );
    println!(
        "  {}: {}/{} own, {}/{} cross",
        args.run_b.display(),
        own_b.ok,
        own_b.total,
        cross_b.ok,
        cross_b.total
    );
    println!(
        "  failures under the own pad (first capture): {}",
        format_pad_failures(&own_a)
    );
    println!(
        "  failures under the own pad (second capture): {}",
        format_pad_failures(&own_b)
    );
    let failed_ids_a = pad_failure_command_ids(&own_a);
    if !failed_ids_a.is_empty() && failed_ids_a == pad_failure_command_ids(&own_b) {
        println!(
            "  commands consistently bypassing the session pad: {} (the login-token pair uses RSA)",
            failed_ids_a
                .iter()
                .map(|command_id| format!("0x{command_id:04X}"))
                .collect::<Vec<_>>()
                .join(" / ")
        );
    }

    if !pad_validation_is_strong(&own_a, &cross_a, &own_b, &cross_b) {
        bail!(
            "pad validation is too weak to accept: first own {}/{}, cross {}/{}; second own {}/{}, cross {}/{}",
            own_a.ok,
            own_a.total,
            cross_a.ok,
            cross_a.total,
            own_b.ok,
            own_b.total,
            cross_b.ok,
            cross_b.total
        );
    }

    fs::create_dir_all(&args.out_dir)
        .with_context(|| format!("creating {}", args.out_dir.display()))?;
    let name_a = run_dir_name(&args.run_a);
    let name_b = run_dir_name(&args.run_b);
    let path_a = args.out_dir.join(format!("session_xorpad_{name_a}.bin"));
    let path_b = args.out_dir.join(format!("session_xorpad_{name_b}.bin"));
    fs::write(&path_a, pad_a)?;
    fs::write(&path_b, pad_b)?;
    let meta_path = args.out_dir.join("session_seeds.json");
    fs::write(
        &meta_path,
        serde_json::to_string_pretty(&json!({
            name_a: format!("{seed_a:#018x}"),
            name_b: format!("{seed_b:#018x}"),
            "pad_endianness": "big",
            "pad_len": session_pad::PAD_LEN,
            "note": "version-specific; do not reuse across game versions",
        }))?,
    )?;
    println!(
        "\nwrote {}\n      {}\n      {}",
        path_a.display(),
        path_b.display(),
        meta_path.display()
    );
    Ok(())
}

fn run_dir_name(run_dir: &Path) -> String {
    run_dir
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "capture".to_string())
}

/// Find a command present in both runs with the same body length whose ciphertext
/// difference is exactly `PAD_LEN`-periodic, which proves both plaintexts are equal.
fn find_shared_pad_difference(
    run_a: &Path,
    rows_a: &[CommandManifestRow],
    run_b: &Path,
    rows_b: &[CommandManifestRow],
    min_body_len: usize,
) -> Result<(
    CommandManifestRow,
    CommandManifestRow,
    [u8; session_pad::PAD_LEN],
)> {
    let dir_a = run_a.join("extracted").join("commands");
    let dir_b = run_b.join("extracted").join("commands");
    let min_body_len = min_body_len.max(2 * session_pad::PAD_LEN);

    let mut index_b: BTreeMap<(u16, usize), &CommandManifestRow> = BTreeMap::new();
    for row in rows_b.iter().filter(|r| r.body_len >= min_body_len) {
        index_b.entry((row.command_id, row.body_len)).or_insert(row);
    }

    let mut candidates: Vec<(&CommandManifestRow, &CommandManifestRow)> = rows_a
        .iter()
        .filter(|r| r.body_len >= min_body_len)
        .filter_map(|a| index_b.get(&(a.command_id, a.body_len)).map(|b| (a, *b)))
        .collect();
    candidates.sort_by_key(|(a, _)| std::cmp::Reverse(a.body_len));

    for (a, b) in candidates {
        let body_a = fs::read(dir_a.join(&a.body_file))?;
        let body_b = fs::read(dir_b.join(&b.body_file))?;
        let blocks = body_a.len() / session_pad::PAD_LEN;
        if blocks < 2 {
            continue;
        }
        let mut diff = [0_u8; session_pad::PAD_LEN];
        for i in 0..session_pad::PAD_LEN {
            diff[i] = body_a[i] ^ body_b[i];
        }
        let periodic = (1..blocks).all(|block| {
            let base = block * session_pad::PAD_LEN;
            (0..session_pad::PAD_LEN).all(|i| body_a[base + i] ^ body_b[base + i] == diff[i])
        });
        if periodic {
            return Ok((a.clone(), b.clone(), diff));
        }
    }

    bail!(
        "no shared same-length body with a {}-periodic difference was found; the two captures \
         must be the same account on the same game version with the drive-disc inventory \
         unchanged between them",
        session_pad::PAD_LEN
    )
}

struct PadScore {
    ok: usize,
    total: usize,
    failures: Vec<PadFailure>,
}

struct PadFailure {
    message_index: u64,
    command_id: u16,
}

fn score_pad_against(
    run_dir: &Path,
    rows: &[CommandManifestRow],
    pad: &[u8; session_pad::PAD_LEN],
) -> Result<PadScore> {
    let dir = run_dir.join("extracted").join("commands");
    let mut score = PadScore {
        ok: 0,
        total: 0,
        failures: Vec::new(),
    };
    for row in rows.iter().filter(|r| r.body_len > 0) {
        score.total += 1;
        let mut body = fs::read(dir.join(&row.body_file))?;
        session_pad::xor_in_place(&mut body, pad);
        if strict_protobuf_ok(&body) {
            score.ok += 1;
        } else if score.failures.len() < 8 {
            score.failures.push(PadFailure {
                message_index: row.message_index,
                command_id: row.command_id,
            });
        }
    }
    Ok(score)
}

fn format_pad_failures(score: &PadScore) -> String {
    if score.failures.is_empty() {
        return "none".to_string();
    }
    score
        .failures
        .iter()
        .map(|failure| format!("msg{} 0x{:04X}", failure.message_index, failure.command_id))
        .collect::<Vec<_>>()
        .join(", ")
}

fn pad_failure_command_ids(score: &PadScore) -> Vec<u16> {
    let mut ids: Vec<_> = score
        .failures
        .iter()
        .map(|failure| failure.command_id)
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

fn pad_validation_is_strong(
    own_a: &PadScore,
    cross_a: &PadScore,
    own_b: &PadScore,
    cross_b: &PadScore,
) -> bool {
    let separated =
        own_a.ok >= 3 && own_b.ok >= 3 && cross_a.ok * 4 <= own_a.ok && cross_b.ok * 4 <= own_b.ok;
    let mostly_valid = own_a.ok * 10 >= own_a.total * 9 && own_b.ok * 10 >= own_b.total * 9;
    let failed_a = own_a.total - own_a.ok;
    let failed_b = own_b.total - own_b.ok;
    let consistent_small_failure_set = failed_a <= 2
        && failed_b <= 2
        && own_a.failures.len() == failed_a
        && own_b.failures.len() == failed_b
        && pad_failure_command_ids(own_a) == pad_failure_command_ids(own_b);

    separated && (mostly_valid || consistent_small_failure_set)
}

/// Whole-buffer protobuf walk. Any leftover byte or illegal wire type rejects the
/// candidate, which is what makes this a usable pad oracle.
fn strict_protobuf_ok(data: &[u8]) -> bool {
    let mut offset = 0_usize;
    while offset < data.len() {
        let Some((tag, len)) = read_varint(&data[offset..]) else {
            return false;
        };
        offset += len;
        let field_number = tag >> 3;
        let wire_type = tag & 7;
        if field_number == 0 || matches!(wire_type, 3 | 4 | 6 | 7) {
            return false;
        }
        match wire_type {
            0 => match read_varint(&data[offset..]) {
                Some((_, len)) => offset += len,
                None => return false,
            },
            1 => offset += 8,
            5 => offset += 4,
            2 => match read_varint(&data[offset..]) {
                Some((payload_len, len)) => {
                    offset += len;
                    match offset.checked_add(payload_len as usize) {
                        Some(end) => offset = end,
                        None => return false,
                    }
                }
                None => return false,
            },
            _ => return false,
        }
        if offset > data.len() {
            return false;
        }
    }
    true
}

fn decode_equip(args: DecodeEquipArgs) -> Result<()> {
    let commands_dir = args.run_dir.join("extracted").join("commands");
    let manifest_path = commands_dir.join("commands.jsonl");
    let rows = read_command_manifest_rows(&manifest_path)?;
    let mut candidate: Option<(EquipSchema, CommandManifestRow)> = None;
    for schema in EQUIP_SCHEMAS {
        let Some(row) = rows
            .iter()
            .filter(|row| row.command_id == schema.command_id)
            .max_by_key(|row| row.body_len)
        else {
            continue;
        };
        if candidate
            .as_ref()
            .is_none_or(|(_, current)| row.body_len > current.body_len)
        {
            candidate = Some((schema, row.clone()));
        }
    }
    let (schema, row) = candidate.context(
        "no supported GetEquipDataScRsp candidate found (known: CN 3.0.0 0x1E40, CN 3.1.0 0x11B0)",
    )?;

    let mut body = fs::read(commands_dir.join(&row.body_file))
        .with_context(|| format!("reading {}", row.body_file))?;
    let xorpad_source = if let Some(path) = args.xorpad.as_ref() {
        let pad = load_raw_xorpad(path)?;
        body = xor_with_pad(&body, &pad);
        Some(path.display().to_string())
    } else {
        None
    };

    let parsed = parse_get_equip_data_sc_rsp(&body, &schema).with_context(|| {
        format!(
            "parsing msg={} cmd=0x{:04X} body_len={}; body is likely still encrypted or the wrong XOR pad was supplied",
            row.message_index, row.command_id, row.body_len
        )
    })?;
    if parsed.equip_list.is_empty() {
        bail!(
            "decoded command 0x{:04X} as protobuf, but equip_list is empty; this is not accepted as a drive-disc parse",
            row.command_id
        );
    }
    validate_equip_decode(&parsed, &schema)?;

    let output_path = args
        .output
        .unwrap_or_else(|| commands_dir.join("equip.json"));
    if output_path.exists() && !args.force {
        bail!(
            "{} already exists; pass --force to replace it",
            output_path.display()
        );
    }
    let output = EquipDecodeOutput {
        source: args.run_dir.display().to_string(),
        schema: schema.name.to_string(),
        command_id_hex: format!("0x{:04X}", row.command_id),
        message_index: row.message_index,
        direction: row.direction,
        body_len: row.body_len,
        xorpad: xorpad_source,
        suit_ids: parsed.suit_ids,
        equip_count: parsed.equip_list.len(),
        equip_list: parsed.equip_list,
    };
    let json = serde_json::to_string_pretty(&output)?;
    fs::write(&output_path, json)?;

    let mut slots = BTreeMap::new();
    let mut levels = BTreeMap::new();
    for equip in &output.equip_list {
        *slots.entry(equip.slot).or_insert(0_usize) += 1;
        *levels.entry(equip.level).or_insert(0_usize) += 1;
    }
    println!(
        "decoded {} drive discs using {} from msg={} to {}",
        output.equip_count,
        output.schema,
        output.message_index,
        output_path.display()
    );
    println!("  suit ids: {}", output.suit_ids.len());
    println!("  per slot: {slots:?}");
    println!("  per level: {levels:?}");
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct EquipSchema {
    name: &'static str,
    command_id: u16,
    equip_list_field: u32,
    suit_ids_field: u32,
    fallback_suit_ids_field: u32,
    star_field: u32,
    level_field: u32,
    item_id_field: u32,
    uid_field: u32,
    uid_xor: u64,
    lock_field: u32,
    marked_field: Option<u32>,
    unresolved_scalar_field: u32,
    unresolved_bool_fields: &'static [u32],
    main_property_field: u32,
    sub_property_field: u32,
    property_key_field: u32,
    property_base_field: u32,
    property_count_field: u32,
    star_xor: u64,
    level_xor: u64,
    item_id_xor: u64,
    property_key_xor: u64,
    property_base_xor: u64,
    property_count_xor: u64,
}

const EQUIP_SCHEMAS: [EquipSchema; 4] = [
    EquipSchema {
        name: "CNPRODWin3.0.0",
        command_id: 0x1E40,
        equip_list_field: 1,
        suit_ids_field: 12,
        fallback_suit_ids_field: 3,
        star_field: 4,
        level_field: 12,
        item_id_field: 13,
        uid_field: 6,
        uid_xor: 0,
        lock_field: 10,
        marked_field: Some(15),
        unresolved_scalar_field: 7,
        unresolved_bool_fields: &[],
        main_property_field: 11,
        sub_property_field: 5,
        property_key_field: 10,
        property_base_field: 7,
        property_count_field: 14,
        star_xor: 2652,
        level_xor: 14887,
        item_id_xor: 2843,
        property_key_xor: 5,
        property_base_xor: 853,
        property_count_xor: 6931,
    },
    EquipSchema {
        name: "CNPRODWin3.1.0",
        command_id: 0x11B0,
        equip_list_field: 10,
        suit_ids_field: 2,
        fallback_suit_ids_field: 6,
        star_field: 11,
        level_field: 1,
        item_id_field: 3,
        uid_field: 6,
        uid_xor: 0,
        lock_field: 4,
        marked_field: None,
        unresolved_scalar_field: 10,
        unresolved_bool_fields: &[7, 15],
        main_property_field: 9,
        sub_property_field: 5,
        property_key_field: 14,
        property_base_field: 11,
        property_count_field: 6,
        star_xor: 6831,
        level_xor: 15226,
        item_id_xor: 7331,
        property_key_xor: 8130,
        property_base_xor: 529,
        property_count_xor: 14928,
    },
    EquipSchema {
        name: "CNPRODWin3.2.0",
        command_id: 0x0F5D,
        equip_list_field: 5,
        suit_ids_field: 3,
        fallback_suit_ids_field: 11,
        star_field: 15,
        level_field: 1,
        item_id_field: 6,
        uid_field: 14,
        uid_xor: 0,
        lock_field: 7,
        marked_field: None,
        unresolved_scalar_field: 5,
        unresolved_bool_fields: &[],
        main_property_field: 9,
        sub_property_field: 4,
        property_key_field: 3,
        property_base_field: 13,
        property_count_field: 7,
        star_xor: 975,
        level_xor: 14782,
        item_id_xor: 10045,
        property_key_xor: 3263,
        property_base_xor: 2174,
        property_count_xor: 16373,
    },
    EquipSchema {
        name: "CNPRODWin3.3.0",
        command_id: 0x06D0,
        equip_list_field: 12,
        suit_ids_field: 9,
        fallback_suit_ids_field: 8,
        star_field: 7,
        level_field: 14,
        item_id_field: 1,
        uid_field: 9,
        uid_xor: 1216,
        lock_field: 12,
        marked_field: None,
        unresolved_scalar_field: 10,
        unresolved_bool_fields: &[5],
        main_property_field: 4,
        sub_property_field: 8,
        property_key_field: 15,
        property_base_field: 11,
        property_count_field: 6,
        star_xor: 7223,
        level_xor: 15335,
        item_id_xor: 16056,
        property_key_xor: 11012,
        property_base_xor: 576,
        property_count_xor: 8102,
    },
];

fn parse_get_equip_data_sc_rsp(data: &[u8], schema: &EquipSchema) -> Result<GetEquipDataDecoded> {
    let mut reader = ProtoReader::new(data);
    let mut out = GetEquipDataDecoded::default();
    while !reader.is_empty() {
        let field_offset = reader.position();
        let (field_number, wire_type) = reader.read_key()?;
        if field_number == schema.equip_list_field && wire_type == 2 {
            out.equip_list
                .push(parse_equip_info(reader.read_len_bytes()?, schema)?);
        } else if field_number == schema.suit_ids_field && wire_type == 2 {
            out.suit_ids = read_packed_varints(reader.read_len_bytes()?)?;
        } else if field_number == schema.fallback_suit_ids_field && wire_type == 2 {
            let ids = read_packed_varints(reader.read_len_bytes()?)?;
            if out.suit_ids.is_empty() {
                out.suit_ids = ids;
            }
        } else {
            reader.skip_field_value(wire_type).with_context(|| {
                format!("skipping GetEquipDataScRsp field {field_number} at {field_offset}")
            })?;
        }
    }
    Ok(out)
}

fn read_packed_varints(data: &[u8]) -> Result<Vec<u32>> {
    let mut reader = ProtoReader::new(data);
    let mut out = Vec::new();
    while !reader.is_empty() {
        out.push(reader.read_varint()? as u32);
    }
    Ok(out)
}

fn parse_equip_info(data: &[u8], schema: &EquipSchema) -> Result<EquipInfoDecoded> {
    let mut reader = ProtoReader::new(data);
    let mut out = EquipInfoDecoded {
        unresolved_scalar_field: schema.unresolved_scalar_field,
        ..EquipInfoDecoded::default()
    };
    while !reader.is_empty() {
        let field_offset = reader.position();
        let (field_number, wire_type) = reader.read_key()?;
        if field_number == schema.star_field && wire_type == 0 {
            out.star = (reader.read_varint()? ^ schema.star_xor) as u32;
        } else if field_number == schema.sub_property_field && wire_type == 2 {
            out.sub_properties
                .push(parse_equip_property(reader.read_len_bytes()?, schema)?);
        } else if field_number == schema.uid_field && wire_type == 0 {
            out.uid = (reader.read_varint()? ^ schema.uid_xor) as u32;
        } else if field_number == schema.unresolved_scalar_field && wire_type == 0 {
            out.unresolved_scalar_raw = Some(reader.read_varint()?);
        } else if field_number == schema.lock_field && wire_type == 0 {
            out.lock = reader.read_varint()? != 0;
        } else if schema.marked_field == Some(field_number) && wire_type == 0 {
            out.marked = reader.read_varint()? != 0;
        } else if schema.unresolved_bool_fields.contains(&field_number) && wire_type == 0 {
            out.unresolved_bool_fields
                .insert(field_number, reader.read_varint()? != 0);
        } else if field_number == schema.main_property_field && wire_type == 2 {
            out.main_property = Some(parse_equip_property(reader.read_len_bytes()?, schema)?);
        } else if field_number == schema.level_field && wire_type == 0 {
            out.level = (reader.read_varint()? ^ schema.level_xor) as u32;
        } else if field_number == schema.item_id_field && wire_type == 0 {
            out.id = (reader.read_varint()? ^ schema.item_id_xor) as u32;
            out.suit_id = out.id / 100 * 100;
            out.rarity = (out.id % 100) / 10;
            out.slot = out.id % 10;
        } else {
            out.unknown_fields
                .push(format!("{field_number}:{wire_type}@{field_offset}"));
            reader.skip_field_value(wire_type).with_context(|| {
                format!("skipping EquipInfo field {field_number} at {field_offset}")
            })?;
        }
    }
    Ok(out)
}

fn parse_equip_property(data: &[u8], schema: &EquipSchema) -> Result<EquipPropertyDecoded> {
    let mut reader = ProtoReader::new(data);
    let mut out = EquipPropertyDecoded::default();
    while !reader.is_empty() {
        let field_offset = reader.position();
        let (field_number, wire_type) = reader.read_key()?;
        if field_number == schema.property_base_field && wire_type == 0 {
            out.base_value = (reader.read_varint()? ^ schema.property_base_xor) as u32;
        } else if field_number == schema.property_key_field && wire_type == 0 {
            out.key = (reader.read_varint()? ^ schema.property_key_xor) as u32;
        } else if field_number == schema.property_count_field && wire_type == 0 {
            out.count = (reader.read_varint()? ^ schema.property_count_xor) as u32;
        } else {
            out.unknown_fields
                .push(format!("{field_number}:{wire_type}@{field_offset}"));
            reader.skip_field_value(wire_type).with_context(|| {
                format!("skipping EquipProperty field {field_number} at {field_offset}")
            })?;
        }
    }
    out.total_value = out.base_value.saturating_mul(out.count);
    Ok(out)
}

fn validate_equip_decode(parsed: &GetEquipDataDecoded, schema: &EquipSchema) -> Result<()> {
    if parsed.suit_ids.is_empty() {
        bail!("{} decode has no suit IDs", schema.name);
    }
    let known_suits: BTreeSet<_> = parsed.suit_ids.iter().copied().collect();
    let mut uids = BTreeSet::new();
    for equip in &parsed.equip_list {
        if equip.uid == 0 || !uids.insert(equip.uid) {
            bail!(
                "{} decode has a zero or duplicate UID {}",
                schema.name,
                equip.uid
            );
        }
        if !known_suits.contains(&equip.suit_id) {
            bail!(
                "{} decode produced item {} with suit {} absent from the response's suit list",
                schema.name,
                equip.id,
                equip.suit_id
            );
        }
        if !(1..=6).contains(&equip.slot) || !(2..=4).contains(&equip.rarity) {
            bail!(
                "{} decode produced invalid item {} (rarity {}, slot {})",
                schema.name,
                equip.id,
                equip.rarity,
                equip.slot
            );
        }
        if equip.level > 15 || equip.star != equip.level / 3 {
            bail!(
                "{} decode produced invalid level/star pair {}/{} for UID {}",
                schema.name,
                equip.level,
                equip.star,
                equip.uid
            );
        }
        let main = equip.main_property.as_ref().with_context(|| {
            format!(
                "{} decode has no main property for UID {}",
                schema.name, equip.uid
            )
        })?;
        validate_equip_property(main, true, schema, equip.uid)?;
        if equip.sub_properties.is_empty() || equip.sub_properties.len() > 4 {
            bail!(
                "{} decode produced {} sub-properties for UID {}",
                schema.name,
                equip.sub_properties.len(),
                equip.uid
            );
        }
        for property in &equip.sub_properties {
            validate_equip_property(property, false, schema, equip.uid)?;
        }
    }
    Ok(())
}

fn validate_equip_property(
    property: &EquipPropertyDecoded,
    main: bool,
    schema: &EquipSchema,
    uid: u32,
) -> Result<()> {
    if !(10_000..40_000).contains(&property.key) || property.base_value == 0 {
        bail!(
            "{} decode produced invalid property key/base {}/{} for UID {}",
            schema.name,
            property.key,
            property.base_value,
            uid
        );
    }
    if (main && property.count != 1) || (!main && !(1..=6).contains(&property.count)) {
        bail!(
            "{} decode produced invalid property count {} for UID {}",
            schema.name,
            property.count,
            uid
        );
    }
    Ok(())
}

fn pad_recover(args: PadRecoverArgs) -> Result<()> {
    if args.run_dirs.is_empty() {
        bail!("pass at least one capture run directory");
    }
    let mut samples = Vec::new();
    for run_dir in &args.run_dirs {
        samples.extend(load_command_bodies(run_dir, 0x1D5E)?);
    }
    if samples.len() < 2 {
        bail!("need at least two PlayerGetTokenCsReq samples to prove a stable prefix");
    }

    let sample_bodies: Vec<&[u8]> = samples.iter().map(|(_, body)| body.as_slice()).collect();
    let stable_prefix_len = common_prefix_len(sample_bodies.iter().copied());
    let stable_suffix_start = common_suffix_start(&sample_bodies);
    let variable_spans = differing_spans(&sample_bodies);
    let first_body = &samples[0].1;
    let stable_prefix = &first_body[..stable_prefix_len];
    let known_fields = known_player_get_token_fields();
    let commands_dir = args.run_dirs[0].join("extracted").join("commands");
    let report_path = commands_dir.join("pad-recover.txt");

    let mut report = String::new();
    push_line(
        &mut report,
        "PlayerGetTokenCsReq known-plaintext recovery report",
    );
    push_line(&mut report, format!("Samples: {}", samples.len()));
    for (source, body) in &samples {
        push_line(
            &mut report,
            format!(
                "  {} body_len={} first32={}",
                source,
                body.len(),
                hex_prefix(body, 32)
            ),
        );
    }
    push_line(
        &mut report,
        format!(
            "\nStable prefix: {} bytes\n{}",
            stable_prefix_len,
            hex_prefix(stable_prefix, args.preview)
        ),
    );
    push_line(
        &mut report,
        format!(
            "\nStable suffix starts at offset {} ({} bytes)",
            stable_suffix_start,
            first_body.len().saturating_sub(stable_suffix_start)
        ),
    );
    push_line(&mut report, "Differing spans across samples:");
    for (start, end) in &variable_spans {
        push_line(
            &mut report,
            format!("  {start}..{end} ({} bytes)", end - start),
        );
    }
    if let Some(hypothesis) = infer_client_rand_key_layout(first_body, stable_suffix_start) {
        push_line(
            &mut report,
            "\nLikely client_rand_key layout from a 172-byte base64 RSA block:",
        );
        push_line(
            &mut report,
            format!(
                "  field 15 tag+len offset={} wire={} cipher={} recovered_pad={}",
                hypothesis.tag_offset,
                hex::encode(&hypothesis.tag_len_wire),
                hex::encode(&first_body[hypothesis.tag_offset..hypothesis.payload_offset]),
                hex::encode(&hypothesis.recovered_pad)
            ),
        );
        push_line(
            &mut report,
            format!(
                "  payload offset={} length={} stable_suffix_offset={}",
                hypothesis.payload_offset, hypothesis.payload_len, stable_suffix_start
            ),
        );
    }
    push_line(
        &mut report,
        "\nKnown plaintext field encodings from remielle schema:",
    );
    for field in &known_fields {
        push_line(
            &mut report,
            format!(
                "  {} field={} value={} wire={}",
                field.name,
                field.field_number,
                field.value,
                hex::encode(&field.wire)
            ),
        );
    }
    push_line(
        &mut report,
        "\nCandidate pad fragments if a known field starts at the given stable-prefix offset:",
    );
    for field in &known_fields {
        if stable_prefix_len < field.wire.len() {
            continue;
        }
        push_line(&mut report, format!("  [{}]", field.name));
        for offset in 0..=stable_prefix_len - field.wire.len() {
            let fragment: Vec<u8> = stable_prefix[offset..offset + field.wire.len()]
                .iter()
                .zip(field.wire.iter())
                .map(|(cipher, plain)| cipher ^ plain)
                .collect();
            push_line(
                &mut report,
                format!("    offset={offset:03} pad={}", hex::encode(fragment)),
            );
        }
    }
    push_line(
        &mut report,
        "\nThis report intentionally does not claim a complete initial pad. Offsets must be confirmed by recovering more protobuf structure or by obtaining the retail client_secret_key.",
    );
    fs::write(&report_path, &report)?;
    print!("{report}");
    info!("pad recovery report written to {}", report_path.display());
    Ok(())
}

fn dispatch_scan(args: DispatchScanArgs) -> Result<()> {
    let version_path = args.game_dir.join("version_info");
    let config_path = args.game_dir.join("config.ini");
    let resources_path = args
        .game_dir
        .join("ZenlessZoneZero_Data")
        .join("resources.assets");

    let version_info = fs::read_to_string(&version_path)
        .with_context(|| format!("reading {}", version_path.display()))?;
    let config = fs::read_to_string(&config_path)
        .with_context(|| format!("reading {}", config_path.display()))?;
    let resources = fs::read(&resources_path)
        .with_context(|| format!("reading {}", resources_path.display()))?;

    let dispatch_version = extract_embedded_json_string(&resources, "DispatchVersion")
        .context("DispatchVersion was not found in resources.assets")?;
    let dispatch_seed = extract_embedded_json_string(&resources, "DispatchSeed")
        .context("DispatchSeed was not found in resources.assets")?;
    let application_version = extract_embedded_json_string(&resources, "ApplicationVersion")
        .context("ApplicationVersion was not found in resources.assets")?;

    println!("Game directory: {}", args.game_dir.display());
    println!("version_info: {}", version_info.trim());
    println!("ApplicationVersion: {application_version}");
    println!("DispatchVersion: {dispatch_version}");
    println!("DispatchSeed: {dispatch_seed}");
    for key in ["channel", "sub_channel", "game_version"] {
        if let Some(value) = ini_value(&config, key) {
            println!("{key}: {value}");
        }
    }
    Ok(())
}

fn extract_embedded_json_string(data: &[u8], key: &str) -> Option<String> {
    let marker = format!("\"{key}\"");
    let marker_offset = data
        .windows(marker.len())
        .position(|window| window == marker.as_bytes())?;
    let mut cursor = marker_offset + marker.len();
    while data
        .get(cursor)
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        cursor += 1;
    }
    if data.get(cursor) != Some(&b':') {
        return None;
    }
    cursor += 1;
    while data
        .get(cursor)
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        cursor += 1;
    }
    if data.get(cursor) != Some(&b'"') {
        return None;
    }
    cursor += 1;
    let end = data[cursor..].iter().position(|byte| *byte == b'"')? + cursor;
    std::str::from_utf8(&data[cursor..end])
        .ok()
        .map(ToOwned::to_owned)
}

fn ini_value<'a>(config: &'a str, key: &str) -> Option<&'a str> {
    config.lines().find_map(|line| {
        let (candidate, value) = line.split_once('=')?;
        (candidate.trim() == key).then(|| value.trim())
    })
}

struct KnownField {
    name: &'static str,
    field_number: u32,
    value: u64,
    wire: Vec<u8>,
}

struct ClientRandKeyHypothesis {
    tag_offset: usize,
    payload_offset: usize,
    payload_len: usize,
    tag_len_wire: Vec<u8>,
    recovered_pad: Vec<u8>,
}

fn infer_client_rand_key_layout(
    first_body: &[u8],
    stable_suffix_start: usize,
) -> Option<ClientRandKeyHypothesis> {
    let payload_len = 172_usize;
    let payload_offset = stable_suffix_start.checked_sub(payload_len)?;
    let mut tag_len_wire = encode_varint((15 << 3) | 2);
    tag_len_wire.extend(encode_varint(payload_len as u64));
    let tag_offset = payload_offset.checked_sub(tag_len_wire.len())?;
    let cipher = first_body.get(tag_offset..payload_offset)?;
    let recovered_pad = cipher
        .iter()
        .zip(tag_len_wire.iter())
        .map(|(cipher, plain)| cipher ^ plain)
        .collect();
    Some(ClientRandKeyHypothesis {
        tag_offset,
        payload_offset,
        payload_len,
        tag_len_wire,
        recovered_pad,
    })
}

fn known_player_get_token_fields() -> Vec<KnownField> {
    vec![
        known_varint_field("channel_id", 5, 1, 14771),
        known_varint_field("platform_type", 9, 3, 7134),
        known_varint_field("rsa_ver", 11, 3, 8067),
    ]
}

fn known_varint_field(name: &'static str, field_number: u32, value: u64, xor: u64) -> KnownField {
    let mut wire = encode_varint(u64::from(field_number) << 3);
    wire.extend(encode_varint(value ^ xor));
    KnownField {
        name,
        field_number,
        value,
        wire,
    }
}

fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}

fn load_command_bodies(run_dir: &Path, command_id: u16) -> Result<Vec<(String, Vec<u8>)>> {
    let commands_dir = run_dir.join("extracted").join("commands");
    let manifest_path = commands_dir.join("commands.jsonl");
    let rows = read_command_manifest_rows(&manifest_path)?;
    let mut bodies = Vec::new();
    for row in rows.into_iter().filter(|row| row.command_id == command_id) {
        let body = fs::read(commands_dir.join(&row.body_file))
            .with_context(|| format!("reading {}", row.body_file))?;
        bodies.push((
            format!("{} msg={}", run_dir.display(), row.message_index),
            body,
        ));
    }
    Ok(bodies)
}

fn read_command_manifest_rows(path: &Path) -> Result<Vec<CommandManifestRow>> {
    let input =
        BufReader::new(File::open(path).with_context(|| format!("opening {}", path.display()))?);
    let mut rows = Vec::new();
    for line in input.lines() {
        let line = line?;
        if !line.trim().is_empty() {
            rows.push(parse_command_manifest_row(&line)?);
        }
    }
    Ok(rows)
}

fn common_prefix_len<'a>(mut bodies: impl Iterator<Item = &'a [u8]>) -> usize {
    let Some(first) = bodies.next() else {
        return 0;
    };
    let mut len = first.len();
    for body in bodies {
        len = len.min(body.len());
        for i in 0..len {
            if first[i] != body[i] {
                len = i;
                break;
            }
        }
    }
    len
}

fn common_suffix_start(bodies: &[&[u8]]) -> usize {
    let Some(first) = bodies.first().copied() else {
        return 0;
    };
    let min_len = bodies.iter().map(|body| body.len()).min().unwrap_or(0);
    for offset_from_end in 0..min_len {
        let index = first.len() - 1 - offset_from_end;
        let byte = first[index];
        if !bodies.iter().copied().all(|body| {
            let body_index = body.len() - 1 - offset_from_end;
            body[body_index] == byte
        }) {
            return index + 1;
        }
    }
    first.len().saturating_sub(min_len)
}

fn differing_spans(bodies: &[&[u8]]) -> Vec<(usize, usize)> {
    let Some(first) = bodies.first().copied() else {
        return Vec::new();
    };
    let min_len = bodies.iter().map(|body| body.len()).min().unwrap_or(0);
    let mut spans = Vec::new();
    let mut start = None;
    for index in 0..min_len {
        let byte = first[index];
        let differs = !bodies.iter().copied().all(|body| body[index] == byte);
        if differs && start.is_none() {
            start = Some(index);
        } else if !differs && start.is_some() {
            spans.push((start.take().unwrap(), index));
        }
    }
    if let Some(start) = start {
        spans.push((start, min_len));
    }
    spans
}

fn hex_prefix(data: &[u8], len: usize) -> String {
    hex::encode(&data[..data.len().min(len)])
}

fn parse_commands(args: CommandsArgs) -> Result<()> {
    let extracted_dir = args.run_dir.join("extracted");
    let manifest_path = extracted_dir.join("messages.jsonl");
    let output_dir = extracted_dir.join("commands");
    if output_dir.exists() {
        if !args.force {
            bail!(
                "{} already exists; pass --force to replace it",
                output_dir.display()
            );
        }
        fs::remove_dir_all(&output_dir)?;
    }
    let metadata_dir = output_dir.join("metadata");
    let body_dir = output_dir.join("bodies");
    fs::create_dir_all(&metadata_dir)?;
    fs::create_dir_all(&body_dir)?;

    let input = BufReader::new(
        File::open(&manifest_path)
            .with_context(|| format!("opening {}", manifest_path.display()))?,
    );
    let mut output = BufWriter::new(File::create(output_dir.join("commands.jsonl"))?);
    let mut stats: BTreeMap<(String, u16), CommandStats> = BTreeMap::new();
    let mut parsed_count = 0_u64;

    for line in input.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let row = parse_message_manifest_row(&line)?;
        let message = fs::read(extracted_dir.join(&row.file))?;
        let envelope = parse_game_envelope(&message)
            .with_context(|| format!("parsing reassembled message {}", row.message_index))?;
        parsed_count += 1;

        let stem = format!(
            "command-{:06}_{:04x}_{}",
            row.message_index, envelope.command_id, row.direction
        );
        let metadata_file = format!("{stem}.bin");
        let body_file = format!("{stem}.bin");
        fs::write(metadata_dir.join(&metadata_file), envelope.metadata)?;
        fs::write(body_dir.join(&body_file), envelope.body)?;
        writeln!(
            output,
            "{}",
            json!({
                "message_index": row.message_index,
                "direction": row.direction,
                "command_id": envelope.command_id,
                "command_id_hex": format!("0x{:04X}", envelope.command_id),
                "metadata_len": envelope.metadata.len(),
                "body_len": envelope.body.len(),
                "metadata_file": format!("metadata/{metadata_file}"),
                "body_file": format!("bodies/{body_file}"),
                "body_preview_hex": hex::encode(&envelope.body[..envelope.body.len().min(32)]),
            })
        )?;

        let command_stats = stats
            .entry((row.direction, envelope.command_id))
            .or_default();
        command_stats.count += 1;
        command_stats.total_body_bytes += envelope.body.len() as u64;
        if command_stats.count == 1 {
            command_stats.min_body_len = envelope.body.len();
        } else {
            command_stats.min_body_len = command_stats.min_body_len.min(envelope.body.len());
        }
        command_stats.max_body_len = command_stats.max_body_len.max(envelope.body.len());
    }
    output.flush()?;

    let mut rows: Vec<_> = stats.iter().collect();
    rows.sort_by_key(|(_, stat)| std::cmp::Reverse((stat.count, stat.total_body_bytes)));
    let mut report = format!(
        "Capture: {}\nParsed messages: {}\nDistinct directional commands: {}\n\nCommands by frequency:\n",
        args.run_dir.display(),
        parsed_count,
        rows.len()
    );
    for ((direction, command_id), stat) in rows {
        push_line(
            &mut report,
            format!(
                "  {direction} 0x{command_id:04X} ({command_id}): count={} body_bytes={} body_len={}..{}",
                stat.count, stat.total_body_bytes, stat.min_body_len, stat.max_body_len
            ),
        );
    }
    fs::write(output_dir.join("report.txt"), &report)?;
    print!("{report}");
    info!("command outputs written to {}", output_dir.display());
    Ok(())
}

fn crypto_scan(args: CryptoScanArgs) -> Result<()> {
    let commands_dir = args.run_dir.join("extracted").join("commands");
    let manifest_path = commands_dir.join("commands.jsonl");
    let input = BufReader::new(
        File::open(&manifest_path)
            .with_context(|| format!("opening {}", manifest_path.display()))?,
    );

    let initial_xorpad = load_crypto_scan_xorpad(&args)?;
    let mut hits = Vec::new();
    let mut rows_seen = 0_u64;

    for line in input.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let row = parse_command_manifest_row(&line)?;
        rows_seen += 1;
        let body = fs::read(commands_dir.join(&row.body_file))
            .with_context(|| format!("reading {}", row.body_file))?;

        collect_crypto_scan_hit(&mut hits, &row, "raw", &body);
        if let Some(xorpad) = initial_xorpad.as_ref() {
            let decrypted = xor_with_pad(&body, &xorpad.pad);
            collect_crypto_scan_hit(&mut hits, &row, "initial_xorpad", &decrypted);
        }
    }

    hits.sort_by_key(|hit| std::cmp::Reverse(hit.score));

    let mut report = String::new();
    push_line(
        &mut report,
        format!(
            "Capture: {}\nRows scanned: {}\nInitial XOR pad: {}\n",
            args.run_dir.display(),
            rows_seen,
            initial_xorpad
                .as_ref()
                .map(|xorpad| xorpad.source.as_str())
                .unwrap_or("not loaded")
        ),
    );
    push_line(&mut report, "Top protobuf-wire candidates:");
    for hit in hits.iter().take(args.top) {
        push_line(
            &mut report,
            format!(
                "  score={} {} msg={} dir={} cmd=0x{:04X} meta={} body={} fields={} len={} str={} max_field={} preview={} first={}",
                hit.score,
                hit.variant,
                hit.row.message_index,
                hit.row.direction,
                hit.row.command_id,
                hit.row.metadata_len,
                hit.row.body_len,
                hit.scan.fields,
                hit.scan.len_delimited,
                hit.scan.utf8_strings,
                hit.scan.max_field_number,
                hit.preview_hex,
                hit.scan.first_fields.join(",")
            ),
        );
    }

    let report_path = commands_dir.join("crypto-scan.txt");
    fs::write(&report_path, &report)?;
    print!("{report}");
    info!("crypto scan written to {}", report_path.display());
    Ok(())
}

fn load_crypto_scan_xorpad(args: &CryptoScanArgs) -> Result<Option<LoadedXorpad>> {
    if let Some(path) = args.xorpad.as_ref() {
        return Ok(Some(LoadedXorpad {
            source: path.display().to_string(),
            pad: load_raw_xorpad(path)?,
        }));
    }

    Ok(None)
}

fn load_raw_xorpad(path: &Path) -> Result<[u8; 4096]> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    xorpad_from_bytes(path.display().to_string(), &bytes)
}

fn xorpad_from_bytes(source: impl AsRef<str>, bytes: &[u8]) -> Result<[u8; 4096]> {
    if bytes.len() != 4096 {
        bail!(
            "{} must contain exactly 4096 bytes, got {}",
            source.as_ref(),
            bytes.len()
        );
    }

    let mut pad = [0_u8; 4096];
    pad.copy_from_slice(bytes);
    Ok(pad)
}

fn collect_crypto_scan_hit(
    hits: &mut Vec<CryptoScanHit>,
    row: &CommandManifestRow,
    variant: &'static str,
    body: &[u8],
) {
    let scan = scan_protobuf_wire(body);
    if !scan.valid || scan.fields == 0 {
        return;
    }
    let score = protobuf_candidate_score(&scan, body.len());
    if score <= 0 {
        return;
    }
    hits.push(CryptoScanHit {
        score,
        variant,
        row: CommandManifestRow {
            message_index: row.message_index,
            direction: row.direction.clone(),
            command_id: row.command_id,
            metadata_len: row.metadata_len,
            body_len: row.body_len,
            body_file: row.body_file.clone(),
        },
        scan,
        preview_hex: hex::encode(&body[..body.len().min(24)]),
    });
}

fn protobuf_candidate_score(scan: &ProtoScan, body_len: usize) -> i64 {
    let structure = (scan.fields as i64 * 8)
        + (scan.len_delimited as i64 * 4)
        + (scan.utf8_strings as i64 * 10)
        + ((scan.varints + scan.fixed32 + scan.fixed64) as i64 * 2);
    let size_penalty = (body_len / 8192) as i64;
    structure - size_penalty
}

fn xor_with_pad(body: &[u8], pad: &[u8; 4096]) -> Vec<u8> {
    body.iter()
        .zip(pad.iter().cycle())
        .map(|(a, b)| a ^ b)
        .collect()
}

fn scan_protobuf_wire(data: &[u8]) -> ProtoScan {
    let mut offset = 0_usize;
    let mut scan = ProtoScan {
        valid: true,
        fields: 0,
        varints: 0,
        fixed32: 0,
        fixed64: 0,
        len_delimited: 0,
        utf8_strings: 0,
        max_field_number: 0,
        first_fields: Vec::new(),
        error: None,
    };

    while offset < data.len() {
        let key_offset = offset;
        let Some((key, key_len)) = read_varint(&data[offset..]) else {
            return invalid_proto_scan(scan, format!("bad varint key at {offset}"));
        };
        offset += key_len;
        if key == 0 {
            return invalid_proto_scan(scan, format!("zero field key at {key_offset}"));
        }

        let field_number = key >> 3;
        let wire_type = key & 0x07;
        if field_number == 0 {
            return invalid_proto_scan(scan, format!("zero field number at {key_offset}"));
        }

        scan.fields += 1;
        scan.max_field_number = scan.max_field_number.max(field_number);
        if scan.first_fields.len() < 12 {
            scan.first_fields
                .push(format!("{field_number}:{wire_type}"));
        }

        match wire_type {
            0 => {
                let Some((_, len)) = read_varint(&data[offset..]) else {
                    return invalid_proto_scan(scan, format!("bad varint value at {offset}"));
                };
                offset += len;
                scan.varints += 1;
            }
            1 => {
                if data.len().saturating_sub(offset) < 8 {
                    return invalid_proto_scan(scan, format!("truncated fixed64 at {offset}"));
                }
                offset += 8;
                scan.fixed64 += 1;
            }
            2 => {
                let Some((len, len_len)) = read_varint(&data[offset..]) else {
                    return invalid_proto_scan(scan, format!("bad length at {offset}"));
                };
                offset += len_len;
                let len = len as usize;
                if data.len().saturating_sub(offset) < len {
                    return invalid_proto_scan(
                        scan,
                        format!("truncated length-delimited at {offset}"),
                    );
                }
                let value = &data[offset..offset + len];
                if is_printable_utf8(value) {
                    scan.utf8_strings += 1;
                }
                offset += len;
                scan.len_delimited += 1;
            }
            5 => {
                if data.len().saturating_sub(offset) < 4 {
                    return invalid_proto_scan(scan, format!("truncated fixed32 at {offset}"));
                }
                offset += 4;
                scan.fixed32 += 1;
            }
            _ => {
                return invalid_proto_scan(
                    scan,
                    format!("unsupported wire type {wire_type} at {key_offset}"),
                );
            }
        }
    }

    scan
}

fn invalid_proto_scan(mut scan: ProtoScan, error: String) -> ProtoScan {
    scan.valid = false;
    scan.error = Some(error);
    scan
}

fn read_varint(data: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0_u64;
    for (i, byte) in data.iter().copied().take(10).enumerate() {
        value |= u64::from(byte & 0x7f) << (i * 7);
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

fn is_printable_utf8(data: &[u8]) -> bool {
    if data.is_empty() || data.len() > 512 {
        return false;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return false;
    };
    text.chars()
        .all(|ch| ch == '\n' || ch == '\r' || ch == '\t' || !ch.is_control())
}

fn parse_message_manifest_row(line: &str) -> Result<MessageManifestRow> {
    let value: Value = serde_json::from_str(line)?;
    Ok(MessageManifestRow {
        message_index: required_u64(&value, "message_index")?,
        direction: required_str(&value, "direction")?.to_string(),
        file: required_str(&value, "file")?.to_string(),
    })
}

fn parse_command_manifest_row(line: &str) -> Result<CommandManifestRow> {
    let value: Value = serde_json::from_str(line)?;
    Ok(CommandManifestRow {
        message_index: required_u64(&value, "message_index")?,
        direction: required_str(&value, "direction")?.to_string(),
        command_id: required_u64(&value, "command_id")? as u16,
        metadata_len: required_u64(&value, "metadata_len")? as usize,
        body_len: required_u64(&value, "body_len")? as usize,
        body_file: required_str(&value, "body_file")?.to_string(),
    })
}

fn parse_game_envelope(message: &[u8]) -> Result<GameEnvelope<'_>> {
    const HEADER_MAGIC: [u8; 4] = [0x01, 0x23, 0x45, 0x67];
    const TAIL_MAGIC: [u8; 4] = [0x89, 0xab, 0xcd, 0xef];
    if message.len() < 16 {
        bail!("game message is shorter than the 16-byte envelope");
    }
    if message[..4] != HEADER_MAGIC {
        bail!("invalid game-message header magic");
    }
    if message[message.len() - 4..] != TAIL_MAGIC {
        bail!("invalid game-message tail magic");
    }
    let command_id = u16::from_be_bytes(message[4..6].try_into()?);
    let metadata_len = u16::from_be_bytes(message[6..8].try_into()?) as usize;
    let body_len = u32::from_be_bytes(message[8..12].try_into()?) as usize;
    let expected_len = 16_usize
        .checked_add(metadata_len)
        .and_then(|len| len.checked_add(body_len))
        .context("game-message envelope length overflow")?;
    if message.len() != expected_len {
        bail!(
            "envelope declares {expected_len} bytes but message has {}",
            message.len()
        );
    }
    let metadata_end = 12 + metadata_len;
    let body_end = metadata_end + body_len;
    Ok(GameEnvelope {
        command_id,
        metadata: &message[12..metadata_end],
        body: &message[metadata_end..body_end],
    })
}

fn read_packet_rows(path: &Path) -> Result<Vec<PacketRow>> {
    let mut input =
        BufReader::new(File::open(path).with_context(|| format!("opening {}", path.display()))?);
    let mut rows = Vec::new();
    let mut line = String::new();
    let mut line_number = 0_u64;
    loop {
        line.clear();
        let byte_count = input.read_line(&mut line)?;
        if byte_count == 0 {
            break;
        }
        line_number += 1;
        if line.trim().is_empty() {
            continue;
        }
        match parse_packet_row(&line) {
            Ok(row) => rows.push(row),
            Err(error) if !line.ends_with('\n') => {
                warn!(
                    path = %path.display(),
                    line = line_number,
                    %error,
                    "ignoring incomplete trailing packets.jsonl record"
                );
                break;
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("parsing {} line {line_number}", path.display()));
            }
        }
    }
    Ok(rows)
}

fn read_row_payload(payload_dir: &Path, row: &PacketRow) -> Result<Option<Vec<u8>>> {
    row.payload_file
        .as_ref()
        .map(|name| fs::read(payload_dir.join(name)).map_err(Into::into))
        .transpose()
}

fn parse_packet_row(line: &str) -> Result<PacketRow> {
    let value: Value = serde_json::from_str(line)?;
    Ok(PacketRow {
        index: required_u64(&value, "index")?,
        src_ip: required_str(&value, "src_ip")?.to_string(),
        dst_ip: required_str(&value, "dst_ip")?.to_string(),
        src_port: required_u64(&value, "src_port")? as u16,
        dst_port: required_u64(&value, "dst_port")? as u16,
        payload_len: required_u64(&value, "payload_len")? as usize,
        payload_preview_hex: required_str(&value, "payload_preview_hex")?.to_string(),
        payload_file: value
            .get("payload_file")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
    })
}

fn required_str<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("missing string field {key}"))
}

fn required_u64(value: &Value, key: &str) -> Result<u64> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .with_context(|| format!("missing integer field {key}"))
}

fn bump_port(ports: &mut BTreeMap<u16, PortStats>, port: u16, payload_len: usize) {
    ports
        .entry(port)
        .and_modify(|s| {
            s.packets += 1;
            s.bytes += payload_len as u64;
        })
        .or_insert(PortStats {
            packets: 1,
            bytes: payload_len as u64,
        });
}

fn conversation_key(row: &PacketRow) -> String {
    let a = format!("{}:{}", row.src_ip, row.src_port);
    let b = format!("{}:{}", row.dst_ip, row.dst_port);
    if a <= b {
        format!("{a} <-> {b}")
    } else {
        format!("{b} <-> {a}")
    }
}

#[derive(Debug)]
struct MhySegment {
    conv: u32,
    cmd: u8,
    frg: u8,
    sn: u32,
    standard: Vec<u8>,
}

fn parse_mhy_segments(payload: &[u8]) -> Result<Vec<MhySegment>> {
    let mut offset = 0_usize;
    let mut segments = Vec::new();
    while offset < payload.len() {
        if payload.len() - offset < 28 {
            bail!("truncated miHoYo KCP header at offset {offset}");
        }
        let header = &payload[offset..offset + 28];
        let cmd = header[8];
        if !matches!(cmd, 0x51..=0x54) {
            bail!("unknown KCP command 0x{cmd:02x} at offset {offset}");
        }
        let conv = u32::from_le_bytes(header[0..4].try_into()?);
        let frg = header[9];
        let sn = u32::from_le_bytes(header[16..20].try_into()?);
        let data_len = u32::from_le_bytes(header[24..28].try_into()?) as usize;
        let body_offset = offset + 28;
        let end = body_offset
            .checked_add(data_len)
            .context("miHoYo KCP segment length overflow")?;
        if end > payload.len() {
            bail!("truncated miHoYo KCP body at offset {offset}");
        }

        let mut standard = Vec::with_capacity(24 + data_len);
        standard.extend_from_slice(&header[0..4]);
        standard.extend_from_slice(&header[8..28]);
        standard.extend_from_slice(&payload[body_offset..end]);
        segments.push(MhySegment {
            conv,
            cmd,
            frg,
            sn,
            standard,
        });
        offset = end;
    }
    if segments.is_empty() {
        bail!("empty payload");
    }
    Ok(segments)
}

fn is_mhy_kcp_like(payload: &[u8]) -> bool {
    parse_mhy_segments(payload).is_ok()
}

fn push_line(out: &mut String, line: impl AsRef<str>) {
    out.push_str(line.as_ref());
    out.push('\n');
}

fn parse_port_range(input: &str) -> Result<PortRange> {
    let Some((start, end)) = input.split_once('-') else {
        bail!("port range must be START-END");
    };
    let start = start.parse::<u16>().context("invalid range start")?;
    let end = end.parse::<u16>().context("invalid range end")?;
    if start > end {
        bail!("port range start must be <= end");
    }
    Ok(PortRange { start, end })
}

fn port_allowed(packet: &UdpPacket, range: Option<PortRange>, ports: &[u16]) -> bool {
    if range.is_none() && ports.is_empty() {
        return true;
    }
    let in_range = |port: u16| range.is_some_and(|r| port >= r.start && port <= r.end);
    ports.contains(&packet.src_port)
        || ports.contains(&packet.dst_port)
        || in_range(packet.src_port)
        || in_range(packet.dst_port)
}

fn parse_ethernet_udp(frame: &[u8]) -> Option<UdpPacket> {
    if frame.len() < 14 {
        return None;
    }
    let ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    match ether_type {
        0x0800 => parse_ipv4_udp(&frame[14..]),
        0x86dd => parse_ipv6_udp(&frame[14..]),
        _ => None,
    }
}

fn parse_ipv4_udp(packet: &[u8]) -> Option<UdpPacket> {
    if packet.len() < 20 {
        return None;
    }
    let version = packet[0] >> 4;
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if version != 4 || ihl < 20 || packet.len() < ihl + 8 || packet[9] != 17 {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < ihl + 8 || packet.len() < total_len {
        return None;
    }
    let src_ip = IpAddr::V4(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ));
    parse_udp(src_ip, dst_ip, &packet[ihl..total_len])
}

fn parse_ipv6_udp(packet: &[u8]) -> Option<UdpPacket> {
    if packet.len() < 48 || packet[0] >> 4 != 6 || packet[6] != 17 {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    if packet.len() < 40 + payload_len || payload_len < 8 {
        return None;
    }
    let src_ip = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?));
    let dst_ip = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?));
    parse_udp(src_ip, dst_ip, &packet[40..40 + payload_len])
}

fn parse_udp(src_ip: IpAddr, dst_ip: IpAddr, packet: &[u8]) -> Option<UdpPacket> {
    if packet.len() < 8 {
        return None;
    }
    let src_port = u16::from_be_bytes([packet[0], packet[1]]);
    let dst_port = u16::from_be_bytes([packet[2], packet[3]]);
    let udp_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    if udp_len < 8 || packet.len() < udp_len {
        return None;
    }
    Some(UdpPacket {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        payload: packet[8..udp_len].to_vec(),
    })
}

fn write_summary(
    run_dir: &Path,
    kept_packets: u64,
    stats: &BTreeMap<u16, PortStats>,
) -> Result<()> {
    let mut out = BufWriter::new(File::create(run_dir.join("summary.csv"))?);
    writeln!(out, "port,packets,bytes")?;
    for (port, stat) in stats {
        writeln!(out, "{},{},{}", port, stat.packets, stat.bytes)?;
    }
    out.flush()?;

    let mut readme = BufWriter::new(File::create(run_dir.join("README.txt"))?);
    writeln!(readme, "Kept UDP packets: {kept_packets}")?;
    writeln!(readme, "Inspect summary.csv for active ports.")?;
    writeln!(
        readme,
        "Inspect packets.jsonl for per-packet metadata and payload file names."
    )?;
    writeln!(
        readme,
        "Payloads are raw UDP payload bytes, not decrypted game commands."
    )?;
    readme.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn mhy_segment(conv: u32, cmd: u8, frg: u8, sn: u32, body: &[u8]) -> Vec<u8> {
        let mut segment = Vec::new();
        segment.extend_from_slice(&conv.to_le_bytes());
        segment.extend_from_slice(&0x1122_3344_u32.to_le_bytes());
        segment.push(cmd);
        segment.push(frg);
        segment.extend_from_slice(&1024_u16.to_le_bytes());
        segment.extend_from_slice(&7_u32.to_le_bytes());
        segment.extend_from_slice(&sn.to_le_bytes());
        segment.extend_from_slice(&0_u32.to_le_bytes());
        segment.extend_from_slice(&(body.len() as u32).to_le_bytes());
        segment.extend_from_slice(body);
        segment
    }

    fn encode_varint(mut value: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            bytes.push(byte);
            if value == 0 {
                return bytes;
            }
        }
    }

    fn push_varint_field(message: &mut Vec<u8>, field: u32, value: u64) {
        message.extend(encode_varint(u64::from(field) << 3));
        message.extend(encode_varint(value));
    }

    fn push_len_field(message: &mut Vec<u8>, field: u32, value: &[u8]) {
        message.extend(encode_varint((u64::from(field) << 3) | 2));
        message.extend(encode_varint(value.len() as u64));
        message.extend(value);
    }

    fn cn31_property(key: u64, base: u64, count: u64) -> Vec<u8> {
        let schema = EQUIP_SCHEMAS[1];
        let mut property = Vec::new();
        push_varint_field(
            &mut property,
            schema.property_count_field,
            count ^ schema.property_count_xor,
        );
        push_varint_field(
            &mut property,
            schema.property_base_field,
            base ^ schema.property_base_xor,
        );
        push_varint_field(
            &mut property,
            schema.property_key_field,
            key ^ schema.property_key_xor,
        );
        property
    }

    #[test]
    fn parses_cn31_drive_disc_schema() {
        let schema = EQUIP_SCHEMAS[1];
        let mut equip = Vec::new();
        push_varint_field(&mut equip, schema.level_field, 15 ^ schema.level_xor);
        push_varint_field(&mut equip, schema.item_id_field, 34145 ^ schema.item_id_xor);
        push_varint_field(&mut equip, schema.lock_field, 1);
        push_len_field(
            &mut equip,
            schema.sub_property_field,
            &cn31_property(11103, 300, 2),
        );
        push_varint_field(&mut equip, schema.uid_field, 42);
        push_len_field(
            &mut equip,
            schema.main_property_field,
            &cn31_property(20103, 480, 1),
        );
        push_varint_field(&mut equip, schema.unresolved_scalar_field, 671);
        push_varint_field(&mut equip, schema.star_field, 5 ^ schema.star_xor);
        push_varint_field(&mut equip, 15, 1);

        let mut body = Vec::new();
        push_len_field(&mut body, schema.suit_ids_field, &encode_varint(34100));
        push_len_field(&mut body, schema.equip_list_field, &equip);

        let parsed = parse_get_equip_data_sc_rsp(&body, &schema).unwrap();
        validate_equip_decode(&parsed, &schema).unwrap();
        assert_eq!(parsed.suit_ids, vec![34100]);
        assert_eq!(parsed.equip_list.len(), 1);
        let decoded = &parsed.equip_list[0];
        assert_eq!(decoded.uid, 42);
        assert_eq!(decoded.id, 34145);
        assert_eq!(decoded.level, 15);
        assert_eq!(decoded.star, 5);
        assert!(decoded.lock);
        assert_eq!(decoded.unresolved_scalar_field, 10);
        assert_eq!(decoded.unresolved_scalar_raw, Some(671));
        assert_eq!(decoded.unresolved_bool_fields.get(&15), Some(&true));
        assert_eq!(decoded.main_property.as_ref().unwrap().key, 20103);
        assert_eq!(decoded.sub_properties[0].total_value, 600);
    }

    #[test]
    fn parses_concatenated_mhy_kcp_segments() {
        let mut datagram = mhy_segment(42, 0x52, 0, 10, &[]);
        datagram.extend(mhy_segment(42, 0x51, 2, 11, b"payload"));

        let segments = parse_mhy_segments(&datagram).unwrap();
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[1].conv, 42);
        assert_eq!(segments[1].frg, 2);
        assert_eq!(segments[1].sn, 11);
        assert_eq!(segments[1].standard.len(), 24 + 7);
        assert_eq!(&segments[1].standard[24..], b"payload");
    }

    #[test]
    fn rejects_truncated_mhy_kcp_body() {
        let mut segment = mhy_segment(42, 0x51, 0, 1, b"payload");
        segment.pop();
        assert!(parse_mhy_segments(&segment).is_err());
    }

    #[test]
    fn parses_game_message_envelope() {
        let mut message = vec![0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0, 2, 0, 0, 0, 3];
        message.extend_from_slice(b"mh");
        message.extend_from_slice(b"abc");
        message.extend_from_slice(&[0x89, 0xab, 0xcd, 0xef]);

        let envelope = parse_game_envelope(&message).unwrap();
        assert_eq!(envelope.command_id, 0x1234);
        assert_eq!(envelope.metadata, b"mh");
        assert_eq!(envelope.body, b"abc");
    }

    #[test]
    fn rejects_incorrect_game_message_length() {
        let message = [
            0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0, 0, 0, 0, 0, 1, 0x89, 0xab, 0xcd, 0xef,
        ];
        assert!(parse_game_envelope(&message).is_err());
    }

    #[test]
    fn accepts_exact_raw_xorpad_size() {
        let bytes = vec![0xa5; 4096];
        let pad = xorpad_from_bytes("test", &bytes).unwrap();
        assert_eq!(pad[0], 0xa5);
        assert_eq!(pad[4095], 0xa5);
    }

    #[test]
    fn rejects_incorrect_raw_xorpad_size() {
        let bytes = vec![0; 4095];
        assert!(xorpad_from_bytes("test", &bytes).is_err());
    }

    #[test]
    fn extracts_dispatch_values_from_embedded_json() {
        let bytes = br#"prefix{"ApplicationVersion":"3.0.0", "DispatchVersion": "CNPRODWin3.0.0", "DispatchSeed": "76400c67cad01e75"}suffix"#;
        assert_eq!(
            extract_embedded_json_string(bytes, "DispatchVersion").as_deref(),
            Some("CNPRODWin3.0.0")
        );
        assert_eq!(
            extract_embedded_json_string(bytes, "DispatchSeed").as_deref(),
            Some("76400c67cad01e75")
        );
        assert_eq!(extract_embedded_json_string(bytes, "missing"), None);
    }

    #[test]
    fn reads_exact_ini_key() {
        let config = "[general]\nchannel=1\nsub_channel=2\n";
        assert_eq!(ini_value(config, "channel"), Some("1"));
        assert_eq!(ini_value(config, "sub_channel"), Some("2"));
    }

    #[test]
    fn ignores_incomplete_trailing_packet_record() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "zzz-drive-sniffer-packets-{}-{unique}.jsonl",
            std::process::id()
        ));
        let complete = json!({
            "index": 7,
            "src_ip": "127.0.0.1",
            "dst_ip": "127.0.0.2",
            "src_port": 1000,
            "dst_port": 2000,
            "payload_len": 3,
            "payload_preview_hex": "010203",
            "payload_file": "packet-000007.bin",
        });
        fs::write(&path, format!("{complete}\n{{\"index\":")).unwrap();

        let rows = read_packet_rows(&path).unwrap();
        fs::remove_file(&path).unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].index, 7);
    }

    fn pad_score(ok: usize, total: usize, failure_ids: &[u16]) -> PadScore {
        PadScore {
            ok,
            total,
            failures: failure_ids
                .iter()
                .enumerate()
                .map(|(index, command_id)| PadFailure {
                    message_index: index as u64,
                    command_id: *command_id,
                })
                .collect(),
        }
    }

    #[test]
    fn accepts_two_consistent_session_pad_bypasses() {
        let own_a = pad_score(9, 11, &[0x169f, 0x221d]);
        let own_b = pad_score(9, 11, &[0x221d, 0x169f]);
        let cross_a = pad_score(0, 11, &[]);
        let cross_b = pad_score(0, 11, &[]);

        assert!(pad_validation_is_strong(&own_a, &cross_a, &own_b, &cross_b));
    }

    #[test]
    fn rejects_inconsistent_session_pad_failures() {
        let own_a = pad_score(9, 11, &[0x169f, 0x221d]);
        let own_b = pad_score(9, 11, &[0x169f, 0x9999]);
        let cross_a = pad_score(0, 11, &[]);
        let cross_b = pad_score(0, 11, &[]);

        assert!(!pad_validation_is_strong(
            &own_a, &cross_a, &own_b, &cross_b
        ));
    }
}
