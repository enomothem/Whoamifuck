//! 历史命令信息，对应 `fk_history`（-n / -a）。

use crate::sys::capture;
use crate::ui::bar;

pub fn run() {
    let hi = capture("cat ~/.*sh_history 2>/dev/null | tail -10");
    println!();
    println!("{}", bar("用户历史命令"));
    println!();
    print!("{hi}");
    println!();
    println!();
}
