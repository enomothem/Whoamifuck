//! Rootkit 后门查杀，对应 `fk_rookit_analysis`（-k）。

use crate::sys::run_inherit;
use crate::ui::bar;
use crate::util;
use std::fs;

pub fn run() {
    println!();
    println!("{}", bar("rootkit查杀"));
    println!();

    util::ensure_installed("chkrootkit");
    util::ensure_installed("rkhunter");

    let _ = fs::create_dir_all("./output");

    println!("正在运行 chkrootkit...");
    run_inherit("sudo chkrootkit > ./output/chkrootkit_results.txt");
    println!("chkrootkit 扫描结果已保存到 ./output/chkrootkit_results.txt");

    println!("正在运行 rkhunter...");
    run_inherit("sudo rkhunter --check --sk > ./output/rkhunter_results.txt");
    println!("rkhunter 扫描结果已保存到 ./output/rkhunter_results.txt");
}
