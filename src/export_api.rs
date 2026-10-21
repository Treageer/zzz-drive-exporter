#[derive(Debug)]
pub enum ExporterOutcome {
    ExportedSingleSession {
        capture: PathBuf,
        equip_json: PathBuf,
        zood_json: PathBuf,
        calculator_json: PathBuf,
        disc_count: usize,
    },
    ExportedPaired {
        capture: PathBuf,
        baseline: PathBuf,
        equip_json: PathBuf,
        zood_json: PathBuf,
        calculator_json: PathBuf,
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
        "waiting for {} drive-disc response command 0x{:04X}",
        schema.name,
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
                // Keep completed messages usable even if the user interrupts a stale capture.
                message_manifest.flush()?;
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
/// equipment response, and write strict ZOOD v1 and zzz_calculator v1 documents.
pub fn process_exporter_capture(
    run_dir: &Path,
    capture_root: &Path,
    explicit_baseline: Option<&Path>,
    zood_output: &Path,
    calculator_output: &Path,
    replace_zood: bool,
    replace_calculator: bool,
) -> Result<ExporterOutcome> {
    prepare_exporter_capture(run_dir)?;
    if explicit_baseline.is_none() {
        match single_session_export(
            run_dir,
            zood_output,
            calculator_output,
            replace_zood,
            replace_calculator,
        ) {
            Ok((_pad_path, equip_json, disc_count)) => {
                return Ok(ExporterOutcome::ExportedSingleSession {
                    capture: run_dir.to_path_buf(),
                    equip_json,
                    zood_json: zood_output.to_path_buf(),
                    calculator_json: calculator_output.to_path_buf(),
                    disc_count,
                });
            }
            Err(error) => warn!("single-session export did not complete: {error:#}"),
        }
    }
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
        let disc_count = export_formats_from_equip(
            &equip_json,
            zood_output,
            calculator_output,
            replace_zood,
            replace_calculator,
        )?;
        return Ok(ExporterOutcome::ExportedPaired {
            capture: run_dir.to_path_buf(),
            baseline,
            equip_json,
            zood_json: zood_output.to_path_buf(),
            calculator_json: calculator_output.to_path_buf(),
            disc_count,
        });
    }

    Ok(ExporterOutcome::NeedsSecondSession {
        capture: run_dir.to_path_buf(),
        attempted_baselines,
    })
}

fn single_session_export(
    run_dir: &Path,
    zood_output: &Path,
    calculator_output: &Path,
    replace_zood: bool,
    replace_calculator: bool,
) -> Result<(PathBuf, PathBuf, usize)> {
    let commands_dir = run_dir.join("extracted").join("commands");
    let manifest = commands_dir.join("commands.jsonl");
    let rows = read_command_manifest_rows(&manifest)?;
    let pad_dir = run_dir.join("extracted").join("exporter-pads");
    let pad_path = pad_dir.join(format!("session_xorpad_{}.bin", run_dir_name(run_dir)));
    let mut recovered = false;
    for (prior, command, schema) in [
        (single_pad::EquipPrior::cn30(), 0x1E40_u16, EQUIP_SCHEMAS[0]),
        (single_pad::EquipPrior::cn31(), 0x11B0_u16, EQUIP_SCHEMAS[1]),
        (single_pad::EquipPrior::cn32(), 0x0F5D_u16, EQUIP_SCHEMAS[2]),
        (single_pad::EquipPrior::cn33(), 0x06D0_u16, EQUIP_SCHEMAS[3]),
    ] {
        let Some(row) = rows
            .iter()
            .filter(|row| row.command_id == command && row.body_len >= 8192)
            .max_by_key(|row| row.body_len)
        else {
            continue;
        };
        let cipher = fs::read(commands_dir.join(&row.body_file))?;
        let evidence = match single_pad::recover_single_pad(&cipher, &prior, 4) {
            Ok(evidence) => evidence,
            Err(_) => continue,
        };
        let recurrence = session_pad::check_pad_recurrence(&evidence.pad, true);
        if recurrence.hits != recurrence.total {
            continue;
        }
        let plain = xor_with_pad(&cipher, &evidence.pad);
        let parsed = match parse_get_equip_data_sc_rsp(&plain, &schema) {
            Ok(parsed) if !parsed.equip_list.is_empty() => parsed,
            _ => continue,
        };
        if let Err(error) = validate_equip_decode(&parsed, &schema) {
            warn!("{} inventory validation rejected the candidate: {error:#}", schema.name);
            continue;
        }
        info!(
            "single-session {} pad MT recurrence {}/{}; inventory {} discs validated",
            schema.name, recurrence.hits, recurrence.total, parsed.equip_list.len()
        );
        fs::create_dir_all(&pad_dir)?;
        fs::write(&pad_path, evidence.pad)?;
        recovered = true;
        break;
    }
    if !recovered {
        bail!("single-session statistical recovery did not validate");
    }
    let equip_json = commands_dir.join("equip.json");
    decode_equip(DecodeEquipArgs {
        run_dir: run_dir.to_path_buf(),
        xorpad: Some(pad_path.clone()),
        output: Some(equip_json.clone()),
        force: true,
    })?;
    let disc_count = export_formats_from_equip(
        &equip_json,
        zood_output,
        calculator_output,
        replace_zood,
        replace_calculator,
    )?;
    Ok((pad_path, equip_json, disc_count))
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

pub fn export_formats_from_equip(
    equip_json: &Path,
    zood_output: &Path,
    calculator_output: &Path,
    replace_zood: bool,
    replace_calculator: bool,
) -> Result<usize> {
    if zood_output == calculator_output {
        bail!("ZOOD and zzz_calculator outputs must use different paths");
    }
    ensure_output_available(zood_output, replace_zood)?;
    ensure_output_available(calculator_output, replace_calculator)?;

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
    validate_record_ids(records)?;
    let zood = build_zood(records, &set_map)?;
    let calculator = build_zzz_calculator(records, &set_map)?;
    write_pretty_json(zood_output, &zood)?;
    write_pretty_json(calculator_output, &calculator)?;
    Ok(records.len())
}

pub fn export_zood_from_equip(equip_json: &Path, output: &Path, force: bool) -> Result<usize> {
    ensure_output_available(output, force)?;
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
    validate_record_ids(records)?;
    let zood = build_zood(records, &set_map)?;
    write_pretty_json(output, &zood)?;
    Ok(records.len())
}

fn ensure_output_available(output: &Path, force: bool) -> Result<()> {
    if output.exists() && !force {
        bail!(
            "{} already exists; pass --force to replace it",
            output.display()
        );
    }
    Ok(())
}

fn validate_record_ids(records: &[Value]) -> Result<()> {
    let mut ids = BTreeSet::new();
    for record in records {
        let uid = json_u64(record, "uid")?;
        if uid == 0 || !ids.insert(uid) {
            bail!("zero or duplicate drive-disc UID {uid}");
        }
    }
    Ok(())
}

fn build_zood(records: &[Value], set_map: &Value) -> Result<Value> {
    let mut discs = Vec::with_capacity(records.len());
    for record in records {
        let uid = json_u64(record, "uid")?;
        let suit_id = json_u64(record, "suit_id")?;
        let set_key = set_entry(set_map, suit_id)?
            .and_then(|entry| entry.get("setKey"))
            .and_then(Value::as_str)
            .with_context(|| format!("no optimizer setKey mapping for suit {suit_id}"))?;
        let (rarity, _) = calculator_rarity(json_u64(record, "rarity")?, uid)?;
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
    Ok(result)
}

fn build_zzz_calculator(records: &[Value], set_map: &Value) -> Result<Value> {
    let mut discs = Vec::with_capacity(records.len());
    for record in records {
        let uid = json_u64(record, "uid")?;
        let suit_id = json_u64(record, "suit_id")?;
        let set = set_entry(set_map, suit_id)?;
        let set_name = set
            .and_then(|entry| entry.get("nameZh"))
            .and_then(Value::as_str)
            .with_context(|| format!("no Chinese set-name mapping for suit {suit_id}"))?;
        let set_id = set
            .and_then(|entry| entry.get("calculatorSetId"))
            .and_then(Value::as_str)
            .with_context(|| format!("no zzz_calculator set ID mapping for suit {suit_id}"))?;
        let rarity_raw = json_u64(record, "rarity")?;
        let (rarity, max_level) = calculator_rarity(rarity_raw, uid)?;
        let level = json_u64(record, "level")?;
        if level > max_level {
            bail!("drive-disc UID {uid} level {level} exceeds {rarity}-rank maximum {max_level}");
        }
        let main = record
            .get("main_property")
            .and_then(Value::as_object)
            .with_context(|| format!("UID {uid} has no main_property"))?;
        let main_key = main
            .get("key")
            .and_then(Value::as_u64)
            .with_context(|| format!("UID {uid} main_property has no key"))?;
        let (main_stat, main_mode, main_is_percent) = calculator_property(main_key)?;
        let main_base = main
            .get("base_value")
            .and_then(Value::as_u64)
            .with_context(|| format!("UID {uid} main_property has no base_value"))?;
        let main_raw = scaled_main_value(main_base, level, max_level)?;

        let mut substats = Vec::new();
        for substat in record
            .get("sub_properties")
            .and_then(Value::as_array)
            .with_context(|| format!("UID {uid} has no sub_properties array"))?
        {
            let key = json_u64(substat, "key")?;
            let (stat, mode, is_percent) = calculator_property(key)?;
            let base = json_u64(substat, "base_value")?;
            let count = json_u64(substat, "count")?;
            if !(1..=6).contains(&count) {
                bail!("UID {uid} has invalid substat roll count {count}");
            }
            let raw = base
                .checked_mul(count)
                .with_context(|| format!("UID {uid} substat value overflow"))?;
            substats.push(json!({
                "stat": stat,
                "mode": mode,
                "value": calculator_value(raw, is_percent),
            }));
        }

        discs.push(json!({
            "id": uid.to_string(),
            "setId": set_id,
            "setName": set_name,
            "partition": json_u64(record, "slot")?,
            "rarity": rarity,
            "level": level,
            "maxLevel": max_level,
            "locked": record.get("lock").and_then(Value::as_bool).unwrap_or(false),
            "equippedBy": Value::Null,
            "mainStat": {
                "stat": main_stat,
                "mode": main_mode,
                "value": calculator_value(main_raw, main_is_percent),
            },
            "subStats": substats,
        }));
    }

    Ok(json!({
        "format": "zzz-calculator-drive-disc-export",
        "version": 1,
        "exportedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "sourceAccount": { "label": "zzz-drive-exporter" },
        "driveDiscs": discs,
    }))
}

fn set_entry(set_map: &Value, suit_id: u64) -> Result<Option<&Value>> {
    Ok(set_map.get(suit_id.to_string()))
}

fn calculator_rarity(rarity: u64, uid: u64) -> Result<(&'static str, u64)> {
    match rarity {
        4 => Ok(("S", 15)),
        3 => Ok(("A", 12)),
        2 => Ok(("B", 9)),
        value => bail!("unsupported drive-disc rarity {value} for UID {uid}"),
    }
}

fn scaled_main_value(base: u64, level: u64, max_level: u64) -> Result<u64> {
    let rate = level
        .checked_mul(30_000)
        .and_then(|value| value.checked_add(max_level / 2))
        .context("main-stat level rate overflow")?
        / max_level;
    base.checked_mul(10_000 + rate)
        .context("main-stat value overflow")
        .map(|value| value / 10_000)
}

fn calculator_value(raw: u64, is_percent: bool) -> Value {
    if !is_percent {
        return json!(raw);
    }
    if raw.is_multiple_of(100) {
        return json!(raw / 100);
    }
    json!(raw as f64 / 100.0)
}

fn write_pretty_json(output: &Path, value: &Value) -> Result<()> {
    if let Some(parent) = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let mut encoded = serde_json::to_string_pretty(value)?;
    encoded.push('\n');
    fs::write(output, encoded).with_context(|| format!("writing {}", output.display()))?;
    Ok(())
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
        30502 => Ok("enerRegen_"),
        31203 => Ok("anomProf"),
        31402 => Ok("anomMas_"),
        31503 => Ok("physical_dmg_"),
        31603 => Ok("fire_dmg_"),
        31703 => Ok("ice_dmg_"),
        31803 => Ok("electric_dmg_"),
        31903 => Ok("ether_dmg_"),
        32303 => Ok("wind_dmg_"),
        _ => bail!("unknown optimizer property key {key}"),
    }
}

fn calculator_property(key: u64) -> Result<(&'static str, &'static str, bool)> {
    match key {
        11102 => Ok(("hpPct", "pct", true)),
        11103 => Ok(("hpFlat", "flat", false)),
        12102 => Ok(("atkPct", "pct", true)),
        12103 => Ok(("atkFlat", "flat", false)),
        12202 => Ok(("impact", "pct", true)),
        13102 => Ok(("defPct", "pct", true)),
        13103 => Ok(("defFlat", "flat", false)),
        20103 => Ok(("critRate", "pct", true)),
        21103 => Ok(("critDmg", "pct", true)),
        23103 => Ok(("penRatio", "pct", true)),
        23203 => Ok(("penFlat", "flat", false)),
        30502 => Ok(("energyRegen", "pct", true)),
        31203 => Ok(("anomalyProficiency", "flat", false)),
        31402 => Ok(("anomalyMastery", "pct", true)),
        31503 => Ok(("physicalDmg", "pct", true)),
        31603 => Ok(("fireDmg", "pct", true)),
        31703 => Ok(("iceDmg", "pct", true)),
        31803 => Ok(("electricDmg", "pct", true)),
        31903 => Ok(("etherDmg", "pct", true)),
        32303 => Ok(("windDmg", "pct", true)),
        _ => bail!("unknown zzz_calculator property key {key}"),
    }
}

#[cfg(test)]
mod exporter_tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn maps_current_property_keys() {
        assert_eq!(optimizer_property_key(20103).unwrap(), "crit_");
        assert_eq!(optimizer_property_key(31402).unwrap(), "anomMas_");
        assert_eq!(optimizer_property_key(31503).unwrap(), "physical_dmg_");
        assert_eq!(optimizer_property_key(31903).unwrap(), "ether_dmg_");
        assert_eq!(optimizer_property_key(32303).unwrap(), "wind_dmg_");
        assert!(optimizer_property_key(99999).is_err());
    }

    #[test]
    fn converts_calculator_stats_and_main_stat_growth() {
        assert_eq!(calculator_property(31402).unwrap(), ("anomalyMastery", "pct", true));
        assert_eq!(calculator_property(32303).unwrap(), ("windDmg", "pct", true));
        assert_eq!(scaled_main_value(550, 15, 15).unwrap(), 2200);
        assert_eq!(scaled_main_value(79, 15, 15).unwrap(), 316);
        assert_eq!(scaled_main_value(46, 4, 15).unwrap(), 82);
        assert_eq!(calculator_value(480, true), json!(4.8));
        assert_eq!(calculator_value(38, false), json!(38));
    }

    #[test]
    fn exports_zood_and_zzz_calculator_documents_together() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!(
            "zzz-drive-exporter-dual-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let equip_path = temp_dir.join("equip.json");
        let zood_path = temp_dir.join("zzz-drives-zood-v1.json");
        let calculator_path = temp_dir.join("zzz-drives-zzz-calculator-v1.json");
        let equip = json!({
            "equip_list": [
                {
                    "uid": 42,
                    "suit_id": 34100,
                    "rarity": 4,
                    "slot": 6,
                    "level": 15,
                    "lock": true,
                    "main_property": { "key": 31402, "base_value": 750, "count": 1 },
                    "sub_properties": [
                        { "key": 20103, "base_value": 240, "count": 2 }
                    ]
                },
                {
                    "uid": 43,
                    "suit_id": 34200,
                    "rarity": 4,
                    "slot": 5,
                    "level": 0,
                    "lock": false,
                    "main_property": { "key": 32303, "base_value": 750, "count": 1 },
                    "sub_properties": [
                        { "key": 12103, "base_value": 19, "count": 2 }
                    ]
                }
            ]
        });
        fs::write(&equip_path, serde_json::to_vec(&equip).unwrap()).unwrap();

        let count = export_formats_from_equip(
            &equip_path,
            &zood_path,
            &calculator_path,
            false,
            false,
        )
        .unwrap();
        let zood: Value = serde_json::from_slice(&fs::read(&zood_path).unwrap()).unwrap();
        let calculator: Value =
            serde_json::from_slice(&fs::read(&calculator_path).unwrap()).unwrap();

        assert_eq!(count, 2);
        assert_eq!(zood["format"], "ZOOD");
        assert_eq!(zood["version"], 1);
        assert_eq!(zood["discs"][0]["mainStatKey"], "anomMas_");
        assert_eq!(zood["discs"][1]["mainStatKey"], "wind_dmg_");
        assert_eq!(calculator["format"], "zzz-calculator-drive-disc-export");
        assert_eq!(calculator["version"], 1);
        assert_eq!(calculator["driveDiscs"][0]["setName"], "谶羽之誓");
        assert_eq!(calculator["driveDiscs"][0]["setId"], "zzz_wiki_2116");
        assert_eq!(calculator["driveDiscs"][0]["mainStat"]["stat"], "anomalyMastery");
        assert_eq!(calculator["driveDiscs"][0]["mainStat"]["value"], 30);
        assert_eq!(calculator["driveDiscs"][0]["subStats"][0]["value"], 4.8);
        assert_eq!(calculator["driveDiscs"][1]["mainStat"]["stat"], "windDmg");
        assert_eq!(calculator["driveDiscs"][1]["mainStat"]["value"], 7.5);

        fs::remove_dir_all(temp_dir).unwrap();
    }
}
