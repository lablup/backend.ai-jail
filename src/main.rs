mod jail;

use clap::Parser;
use fern::colors::{Color, ColoredLevelConfig};
use jail::Jail;
use libc::umask;
use log::info;
use std::process::id as getpid;

pub mod interface;
pub mod policy;
pub mod utils;

fn setup_logger(level: log::LevelFilter) -> Result<(), fern::InitError> {
    let colors = ColoredLevelConfig::new()
        .error(Color::Red)
        .warn(Color::Yellow)
        .info(Color::BrightCyan)
        .debug(Color::Green)
        .trace(Color::BrightBlack);

    fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "{color_time}{time} {color_level}{level}{color_reset} {color_name}{target} {color_pid}[{pid}] {color_line}{message}{color_reset}",
                time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.6f"),
                level = record.level(),
                target = record.target(),
                pid = getpid(),
                message = message,
                color_time = "\x1B[38;5;240m",
                color_level = "\x1B[38;5;248;1m",
                color_reset = "\x1B[0m",
                color_name = "\x1B[38;5;246m",
                color_pid = format!("\x1B[{}m", Color::Cyan.to_fg_str()),
                color_line = format!("\x1B[{}m", colors.get_color(&record.level()).to_fg_str()),
            ));
        })
        .level(level)
        .chain(std::io::stderr())
        .apply()?;
    Ok(())
}

#[cfg(
    all(
        any(target_arch = "x86_64"), // TODO: Support Aarch64
        any(target_os = "macos", target_os = "linux"), // macOS is set only for convenience, this program won't run on macOS
    )
)]
fn main() {
    unsafe {
        umask(0o022);
    }

    let cli = interface::Args::parse();
    let log_level_str = match &cli.log_level {
        Some(l) => l,
        None => "info",
    };
    let log_level = match log_level_str {
        "error" => log::LevelFilter::Error,
        "warn" => log::LevelFilter::Warn,
        "info" => log::LevelFilter::Info,
        "debug" => log::LevelFilter::Debug,
        unknown => {
            println!("Unknown log level {}, setting to info", unknown);
            log::LevelFilter::Info
        }
    };
    panic_if_err!(setup_logger(log_level));

    if cli.noop {
        info!("NOOP MODE: doing nothing! (debug/watch are disabled, too)");
    } else {
        if cli.watch {
            info!("WATCH MODE: all syscalls are ALLOWED but it shows which ones will be blocked by the current policy.");
        }
    }

    let mut jail = Jail::new(cli);

    jail.run_tracer();
}
