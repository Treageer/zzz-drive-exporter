#[derive(Debug)]
pub enum ExporterOutcome {
    Exported {
        capture: PathBuf,
        baseline: PathBuf,
        equip_json: PathBuf,
        zood_json: PathBuf,
        disc_count: usize,
    },
    NeedsSecondSession {
        capture: PathBuf,
        attempted_baselines: usize,
    },
}

const ZZZ_GAME_PORT: u16 = 20501;

/// Capture UDP until the current GetEquipDataScRsp has been completely reassembled.
/// The encrypted command envelope is plaintext, so this stop condition does not need
/// the per-session XOR pad.
pub async fn capture_until_current_equip(output_root: &Path) -> Result<PathBuf> {
    let schema = EQUIP_SCHEMAS
        .last()
        .copied()
        .context("no current equipment schema is configured")?;
    let run_dir = output_root.join(
        Local::now()
            .format("zzz-exporter-capture-%Y%m%d-%H%M%S-%3f")
            .to_string(),
    );
    let extracted_dir = run_dir.join("extracted");
    fs::create_dir_all(&extracted_dir)
        .with_context(|| format!("creating {}", extracted_dir.display()))?;
    let mut message_manifest = BufWriter::new(File::create(extracted_dir.join("messages.jsonl"))?);
    let mut capture =
        Capture::new().context("creating pktmon capture; run this executable as administrator")?;
    capture
        .add_filter(PktMonFilter {
            name: "ZZZ UDP".to_string(),
            transport_protocol: Some(TransportProtocol::UDP),
            port: ZZZ_GAME_PORT.into(),
            ..PktMonFilter::default()
        })
        .context("adding pktmon ZZZ UDP filter")?;

    info!("starting continuous UDP capture");
    info!("capture directory: {}", run_dir.display());
    info!(
        "waiting for complete drive-disc response command 0x{:04X}",
        schema.command_id
    );

    let mut stream = capture.stream().context("opening pktmon stream")?;
    let (packet_tx, mut packet_rx) = tokio::sync::mpsc::unbounded_channel();
    let capture_task = tokio::spawn(async move {
        while let Some(packet) = stream.next().await {
            if packet_tx.send(packet).is_err() {
                break;
            }
        }
    });
    let mut packet_index = 0_u64;
    let mut kept_index = 0_u64;
    let mut kept_bytes = 0_u64;
    let mut receivers: BTreeMap<(String, u32), KcpReceiver> = BTreeMap::new();
    let mut direction_counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut message_index = 0_u64;
    let mut target_seen = false;

    'capture: loop {
        let packet = tokio::select! {
            packet = packet_rx.recv() => {
                let Some(packet) = packet else { break };
                packet
            }
            _ = tokio::signal::ctrl_c() => {
                warn!("capture interrupted before automatic completion");
                break;
            }
        };

        packet_index += 1;
        let PacketPayload::Ethernet(frame) = packet.payload else {
            continue;
        };
        let Some(udp) = parse_ethernet_udp(&frame) else {
            continue;
        };

        kept_index += 1;
        kept_bytes += udp.payload.len() as u64;

        let packet_row = PacketRow {
            index: kept_index,
            src_ip: udp.src_ip.to_string(),
            dst_ip: udp.dst_ip.to_string(),
            src_port: udp.src_port,
            dst_port: udp.dst_port,
            payload_len: udp.payload.len(),
            payload_preview_hex: String::new(),
            payload_file: None,
        };
        let conversation = conversation_key(&packet_row);
        let direction = format!("{}-{}", udp.src_port, udp.dst_port);
        let Ok(segments) = parse_mhy_segments(&udp.payload) else {
            continue;
        };
        for segment in segments.into_iter().filter(|segment| segment.cmd == 0x51) {
            let conv = segment.conv;
            let receiver = receivers
                .entry((format!("{conversation}|{direction}"), conv))
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
                continue;
            }
            while let Ok(size) = receiver.kcp.peeksize() {
                let mut message = vec![0_u8; size];
                if receiver.kcp.recv(&mut message).is_err() {
                    break;
                }
                let Ok(envelope) = parse_game_envelope(&message) else {
                    continue;
                };
                message_index += 1;
                let direction_index = direction_counts.entry(direction.clone()).or_default();
                *direction_index += 1;
                let file_name =
                    format!("message-{message_index:06}_{direction}_{direction_index:06}.bin");
                fs::write(extracted_dir.join(&file_name), &message)?;
                writeln!(
                    message_manifest,
                    "{}",
                    json!({
                        "message_index": message_index,
                        "capture_packet_index": kept_index,
                        "direction": direction,
                        "src_ip": udp.src_ip.to_string(),
                        "src_port": udp.src_port,
                        "dst_ip": udp.dst_ip.to_string(),
                        "dst_port": udp.dst_port,
                        "conv": conv,
                        "length": message.len(),
                        "file": file_name,
                        "preview_hex": hex::encode(&message[..message.len().min(32)]),
                    })
                )?;
                if envelope.command_id == schema.command_id && envelope.body.len() >= 8192 {
                    target_seen = true;
                    info!(
                        "complete drive-disc response detected: command=0x{:04X}, encrypted_body={} bytes",
                        envelope.command_id,
                        envelope.body.len()
                    );
                    break 'capture;
                }
            }
        }
    }

    message_manifest.flush()?;
    drop(packet_rx);
    capture_task.abort();
    let _ = capture_task.await;
    fs::write(
        extracted_dir.join("summary.txt"),
        format!(
            "Direct live KCP reassembly\nCaptured packets: {packet_index}\nKept ZZZ UDP packets: {kept_index}\nKept ZZZ UDP bytes: {kept_bytes}\nReassembled messages: {message_index}\nTarget command: 0x{:04X}\nTarget complete: {target_seen}\n",
            schema.command_id
        ),
    )?;
    fs::write(
        run_dir.join("README.txt"),
        "This exporter stores complete reassembled game messages instead of per-packet payload files to prevent capture queue overflow.\n",
    )?;
    info!(
        "captured {} packets, kept {} ZZZ UDP packets, reassembled {} messages",
        packet_index, kept_index, message_index
    );

    if !target_seen {
        bail!(
            "capture ended before a complete drive-disc response was detected; retained reassembled messages at {}",
            run_dir.display()
        );
    }
    Ok(run_dir)
}

/// Ensure an existing capture has the same offline products that the research CLI
/// would create with `extract` followed by `commands`.
pub fn prepare_exporter_capture(run_dir: &Path) -> Result<()> {
    let extracted = run_dir.join("extracted");
    let messages = extracted.join("messages.jsonl");
    if !messages.exists() {
        extract_capture(ExtractArgs {
            run_dir: run_dir.to_path_buf(),
            force: extracted.exists(),
        })?;
    }

    let commands_dir = extracted.join("commands");
    let commands = commands_dir.join("commands.jsonl");
    if !commands.exists() {
        parse_commands(CommandsArgs {
            run_dir: run_dir.to_path_buf(),
            force: commands_dir.exists(),
        })?;
    }
    Ok(())
}

/// Recover the current session pad from a compatible earlier session, decode the
/// equipment response, and write a strict ZOOD v1 document.
pub fn process_exporter_capture(
    run_dir: &Path,
    capture_root: &Path,
    explicit_baseline: Option<&Path>,
    zood_output: &Path,
    force: bool,
) -> Result<ExporterOutcome> {
    prepare_exporter_capture(run_dir)?;
    let candidates = baseline_candidates(run_dir, capture_root, explicit_baseline)?;
    let attempted_baselines = candidates.len();

    for baseline in candidates {
        if explicit_baseline.is_some() {
            prepare_exporter_capture(&baseline)
                .with_context(|| format!("preparing explicit baseline {}", baseline.display()))?;
        }
        let baseline_manifest = baseline
            .join("extracted")
            .join("commands")
            .join("commands.jsonl");
        if !baseline_manifest.exists() {
            continue;
        }

        let rows_a = match read_command_manifest_rows(&baseline_manifest) {
            Ok(rows) => rows,
            Err(error) => {
                debug!(baseline = %baseline.display(), %error, "skipping unreadable baseline");
                continue;
            }
        };
        let rows_b = read_command_manifest_rows(
            &run_dir
                .join("extracted")
                .join("commands")
                .join("commands.jsonl"),
        )?;
        if find_shared_pad_difference(&baseline, &rows_a, run_dir, &rows_b, 8192).is_err() {
            continue;
        }

        let pad_dir = run_dir.join("extracted").join("exporter-pads");
        let crack = pad_crack(PadCrackArgs {
            run_a: baseline.clone(),
            run_b: run_dir.to_path_buf(),
            out_dir: pad_dir.clone(),
            min_body_len: 8192,
        });
        if let Err(error) = crack {
            debug!(baseline = %baseline.display(), %error, "candidate baseline failed pad validation");
            continue;
        }

        let pad_path = pad_dir.join(format!("session_xorpad_{}.bin", run_dir_name(run_dir)));
        let equip_json = run_dir
            .join("extracted")
            .join("commands")
            .join("equip.json");
        decode_equip(DecodeEquipArgs {
            run_dir: run_dir.to_path_buf(),
            xorpad: Some(pad_path),
            output: Some(equip_json.clone()),
            force: true,
        })?;
        let disc_count = export_zood_from_equip(&equip_json, zood_output, force)?;
        return Ok(ExporterOutcome::Exported {
            capture: run_dir.to_path_buf(),
            baseline,
            equip_json,
            zood_json: zood_output.to_path_buf(),
            disc_count,
        });
    }

    Ok(ExporterOutcome::NeedsSecondSession {
        capture: run_dir.to_path_buf(),
        attempted_baselines,
    })
}

fn baseline_candidates(
    current: &Path,
    capture_root: &Path,
    explicit: Option<&Path>,
) -> Result<Vec<PathBuf>> {
    if let Some(path) = explicit {
        if path == current {
            bail!("baseline and current capture must be different sessions");
        }
        return Ok(vec![path.to_path_buf()]);
    }
    if !capture_root.exists() {
        return Ok(Vec::new());
    }
    let current_name = current.file_name();
    let mut candidates = Vec::new();
    for entry in fs::read_dir(capture_root)? {
        let entry = entry?;
        let path = entry.path();
        if !entry.file_type()?.is_dir() || path.file_name() == current_name {
            continue;
        }
        if path
            .join("extracted")
            .join("commands")
            .join("commands.jsonl")
            .exists()
        {
            candidates.push(path);
        }
    }
    candidates.sort_by(|a, b| b.file_name().cmp(&a.file_name()));
    Ok(candidates)
}

pub fn export_zood_from_equip(equip_json: &Path, output: &Path, force: bool) -> Result<usize> {
    if output.exists() && !force {
        bail!(
            "{} already exists; pass --force to replace it",
            output.display()
        );
    }
    let data: Value = serde_json::from_slice(
        &fs::read(equip_json).with_context(|| format!("reading {}", equip_json.display()))?,
    )?;
    let records = data
        .get("equip_list")
        .and_then(Value::as_array)
        .context("equip.json has no equip_list array")?;
    if records.is_empty() {
        bail!("equip.json contains no drive discs");
    }

    let set_map: Value =
        serde_json::from_str(include_str!("../resources/zzz_cn31_disc_sets.json"))?;
    let mut ids = BTreeSet::new();
    let mut discs = Vec::with_capacity(records.len());
    for record in records {
        let uid = json_u64(record, "uid")?;
        if uid == 0 || !ids.insert(uid) {
            bail!("zero or duplicate drive-disc UID {uid}");
        }
        let suit_id = json_u64(record, "suit_id")?;
        let set_key = set_map
            .get(suit_id.to_string())
            .and_then(|entry| entry.get("setKey"))
            .and_then(Value::as_str)
            .with_context(|| format!("no optimizer setKey mapping for suit {suit_id}"))?;
        let rarity = match json_u64(record, "rarity")? {
            4 => "S",
            3 => "A",
            2 => "B",
            value => bail!("unsupported drive-disc rarity {value} for UID {uid}"),
        };
        let main = record
            .get("main_property")
            .and_then(Value::as_object)
            .with_context(|| format!("UID {uid} has no main_property"))?;
        let main_key_raw = main
            .get("key")
            .and_then(Value::as_u64)
            .with_context(|| format!("UID {uid} main_property has no key"))?;
        let main_key = optimizer_property_key(main_key_raw)?;

        let mut substats = Vec::new();
        for substat in record
            .get("sub_properties")
            .and_then(Value::as_array)
            .with_context(|| format!("UID {uid} has no sub_properties array"))?
        {
            let key = optimizer_property_key(json_u64(substat, "key")?)?;
            let upgrades = json_u64(substat, "count")?;
            if !(1..=6).contains(&upgrades) {
                bail!("UID {uid} has invalid substat roll count {upgrades}");
            }
            substats.push(json!({ "key": key, "upgrades": upgrades }));
        }

        discs.push(json!({
            "id": uid.to_string(),
            "setKey": set_key,
            "slotKey": json_u64(record, "slot")?.to_string(),
            "level": json_u64(record, "level")?,
            "rarity": rarity,
            "mainStatKey": main_key,
            "substats": substats,
            "location": "",
            "lock": record.get("lock").and_then(Value::as_bool).unwrap_or(false),
            "trash": false,
        }));
    }

    let result = json!({
        "format": "ZOOD",
        "version": 1,
        "source": "zzz-drive-exporter",
        "discs": discs,
    });
    if let Some(parent) = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let mut encoded = serde_json::to_string_pretty(&result)?;
    encoded.push('\n');
    fs::write(output, encoded)?;
    Ok(records.len())
}

fn json_u64(value: &Value, key: &str) -> Result<u64> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .with_context(|| format!("missing integer field {key}"))
}

fn optimizer_property_key(key: u64) -> Result<&'static str> {
    match key {
        11102 => Ok("hp_"),
        11103 => Ok("hp"),
        12102 => Ok("atk_"),
        12103 => Ok("atk"),
        12202 => Ok("impact_"),
        13102 => Ok("def_"),
        13103 => Ok("def"),
        20103 => Ok("crit_"),
        21103 => Ok("crit_dmg_"),
        23103 => Ok("pen_"),
        23203 => Ok("pen"),
        30402 => Ok("anomMas_"),
        30502 => Ok("enerRegen_"),
        31203 => Ok("anomProf"),
        31402 => Ok("physical_dmg_"),
        31503 => Ok("fire_dmg_"),
        31603 | 31903 => Ok("ice_dmg_"),
        31703 => Ok("electric_dmg_"),
        31803 | 32303 => Ok("ether_dmg_"),
        _ => bail!("unknown optimizer property key {key}"),
    }
}

#[cfg(test)]
mod exporter_tests {
    use super::*;

    #[test]
    fn maps_current_property_keys() {
        assert_eq!(optimizer_property_key(20103).unwrap(), "crit_");
        assert_eq!(optimizer_property_key(31903).unwrap(), "ice_dmg_");
        assert!(optimizer_property_key(99999).is_err());
    }
}
