//! 计划任务信息，对应 `fk_crontab`（-n / -a）。

use crate::sys::capture;
use crate::ui::bar;

pub fn run() {
    let cron = capture("crontab -l 2>/dev/null");
    println!();
    println!("{}", bar("用户计划任务"));
    println!();
    print!("{cron}");
    println!();
}
