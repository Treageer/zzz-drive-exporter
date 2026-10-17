use std::{
    io::{self, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::Parser;
use tracing_subscriber::EnvFilter;
use zzz_drive_exporter::{ExporterOutcome, capture_until_current_equip, process_exporter_capture};

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Capture ZZZ drive discs and export ZOOD and zzz_calculator JSON"
)]
struct Cli {
    /// Process an existing capture instead of starting a live capture.
    #[arg(long)]
    from_capture: Option<PathBuf>,

    /// Explicit earlier session to use for session-pad recovery.
    #[arg(long)]
    baseline: Option<PathBuf>,

    /// Root directory for captures and automatic baseline discovery.
    #[arg(long, default_value = "captures")]
    capture_root: PathBuf,

    /// ZOOD v1 output path. Defaults to exports/zzz-drives-zood-v1.json.
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// zzz_calculator v1 output path. Defaults to exports/zzz-drives-zzz-calculator-v1.json.
    #[arg(long)]
    calculator_output: Option<PathBuf>,

    /// Replace existing custom output files.
    #[arg(long)]
    force: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();

    let replace_zood = cli.force || cli.output.is_none();
    let replace_calculator = cli.force || cli.calculator_output.is_none();
    let zood_output = cli
        .output
        .unwrap_or_else(|| PathBuf::from("exports").join("zzz-drives-zood-v1.json"));
    let calculator_output = cli
        .calculator_output
        .unwrap_or_else(|| PathBuf::from("exports").join("zzz-drives-zzz-calculator-v1.json"));
    if let Some(run_dir) = cli.from_capture {
        let outcome = process_capture(
            &run_dir,
            &cli.capture_root,
            cli.baseline.as_deref(),
            &zood_output,
            &calculator_output,
            replace_zood,
            replace_calculator,
        )?;
        print_outcome(outcome);
        return Ok(());
    }

    println!("请将游戏停在登录页，看到 Capture started 后再点击登录进入游戏。");
    println!("程序检测到完整驱动盘响应后会自动停止，请不要按 Ctrl+C。\n");
    let first_capture = capture_until_current_equip(&cli.capture_root).await?;
    let first_outcome = process_capture(
        &first_capture,
        &cli.capture_root,
        cli.baseline.as_deref(),
        &zood_output,
        &calculator_output,
        replace_zood,
        replace_calculator,
    )?;

    match first_outcome {
        exported @ (ExporterOutcome::ExportedSingleSession { .. }
        | ExporterOutcome::ExportedPaired { .. }) => print_outcome(exported),
        ExporterOutcome::NeedsSecondSession {
            capture,
            attempted_baselines,
        } => {
            println!("\n第一轮抓包已完成并保存：{}", capture.display());
            println!("检查了 {attempted_baselines} 份历史会话，但没有找到可配对的会话。");
            println!("当前登录会话的加密 pad 无法固化，需要用库存相同的第二次登录恢复。");
            println!("\n请按以下步骤操作：");
            println!("1. 保持驱动盘库存不变，完全退出游戏。");
            println!("2. 重新启动游戏，并停在登录页。");
            println!("3. 回到本窗口按 Enter，待看到 Capture started 后再点击登录进入游戏。");
            wait_for_enter()?;

            println!("\n开始第二轮抓包。看到 Capture started 后，请点击登录进入游戏。\n");
            let second_capture = capture_until_current_equip(&cli.capture_root).await?;
            let second_outcome = process_capture(
                &second_capture,
                &cli.capture_root,
                Some(&first_capture),
                &zood_output,
                &calculator_output,
                replace_zood,
                replace_calculator,
            )?;
            match second_outcome {
                exported @ (ExporterOutcome::ExportedSingleSession { .. }
                | ExporterOutcome::ExportedPaired { .. }) => print_outcome(exported),
                ExporterOutcome::NeedsSecondSession { .. } => {
                    anyhow::bail!("两轮抓包无法配对；请确认两次登录之间驱动盘库存完全未改变");
                }
            }
        }
    }
    Ok(())
}

fn process_capture(
    run_dir: &Path,
    capture_root: &Path,
    baseline: Option<&Path>,
    zood_output: &Path,
    calculator_output: &Path,
    replace_zood: bool,
    replace_calculator: bool,
) -> Result<ExporterOutcome> {
    process_exporter_capture(
        run_dir,
        capture_root,
        baseline,
        zood_output,
        calculator_output,
        replace_zood,
        replace_calculator,
    )
    .with_context(|| format!("processing capture {}", run_dir.display()))
}

fn print_outcome(outcome: ExporterOutcome) {
    match outcome {
        ExporterOutcome::ExportedSingleSession {
            capture,
            equip_json,
            zood_json,
            calculator_json,
            disc_count,
        } => {
            println!("\n完成：单次抓包恢复并导出 {disc_count} 个驱动盘。");
            println!("本次抓包：{}", capture.display());
            println!("原始解析：{}", equip_json.display());
            println!("ZOOD v1：{}", zood_json.display());
            println!("zzz_calculator v1：{}", calculator_json.display());
        }
        ExporterOutcome::ExportedPaired {
            capture,
            baseline,
            equip_json,
            zood_json,
            calculator_json,
            disc_count,
        } => {
            println!("\n完成：已导出 {disc_count} 个驱动盘。");
            println!("本次抓包：{}", capture.display());
            println!("配对会话（回退路径）：{}", baseline.display());
            println!("原始解析：{}", equip_json.display());
            println!("ZOOD v1：{}", zood_json.display());
            println!("zzz_calculator v1：{}", calculator_json.display());
        }
        ExporterOutcome::NeedsSecondSession {
            capture,
            attempted_baselines,
        } => {
            println!("\n已保存第一份完整会话：{}", capture.display());
            println!("检查了 {attempted_baselines} 份历史会话，但没有可用于恢复 pad 的配对会话。");
            println!("离线模式不会自动开始第二轮；请再提供一份库存相同的登录会话作为 --baseline。");
        }
    }
}

fn wait_for_enter() -> Result<()> {
    print!("\n准备好后按 Enter 继续... ");
    io::stdout().flush()?;
    let mut input = String::new();
    if io::stdin().read_line(&mut input)? == 0 {
        anyhow::bail!("标准输入已关闭，无法开始第二轮抓包");
    }
    Ok(())
}
