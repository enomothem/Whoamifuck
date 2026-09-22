//! 通用工具函数：命令检测与依赖安装提示，对应 `fk_command` 与 `i`。

use crate::color::*;
use crate::sys::{command_exists, run_inherit, OsType};
use crate::ui::Stats;
use std::io::{self, Write};

/// 对应 `fk_command`：curl 缺失时给出警告。
pub fn check_command() {
    if !command_exists("curl") {
        println!("{} curl 命令不存在将导致web存活模块无法使用。", Stats::war());
    }
}

/// 对应 `i`：检测软件包是否安装，未安装则交互式提示安装。
pub fn ensure_installed(package: &str) {
    let os_app = match crate::sys::os_name().os_type {
        OsType::Debian => "apt-get",
        OsType::RedHat => "yum",
    };

    if command_exists(package) {
        println!("{package}   {GREEN} installed {RESET} ");
        return;
    }

    println!("{package}   {REDX} uninstalled {RESET} ");
    print!("是否安装 {package}？ (Y/n): ");
    let _ = io::stdout().flush();

    let mut choice = String::new();
    if io::stdin().read_line(&mut choice).is_err() {
        std::process::exit(1);
    }
    let choice = choice.trim();
    let choice = if choice.is_empty() { "y" } else { choice };

    match choice {
        "y" | "Y" => {
            println!("正在安装 {package}...");
            run_inherit(&format!("sudo {os_app} update"));
            run_inherit(&format!("sudo {os_app} install -y {package}"));
        }
        _ => {
            println!("exit");
            std::process::exit(1);
        }
    }
}
