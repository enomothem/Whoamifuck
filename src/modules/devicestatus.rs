//! 系统状态信息，对应 `fk_devicestatus`（-s / -n / -a）。

use crate::sys::capture;
use crate::ui::bar;

pub fn run() {
    let ta = capture("free -m | awk 'NR==2{printf \"%.2f%%\\t\\t\",$3*100/$2}'");
    let tb = capture("df -h| awk '$NF==\"/\"{printf \"%s\\t\\t\",$5}'");
    let tc = capture("top -bn1 | grep load | awk '{printf \"%.2f%%\\t\\t\\n\",2$(NF2)}'");

    println!("{}", bar("系统状态信息"));
    println!();
    print!("Memory:{ta}");
    print!("Disk:{tb}");
    print!("CPU:{tc}");
    println!();
}
