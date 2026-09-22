//! 进程与服务信息，对应 `fk_procserv`（-x）。

use crate::sys::capture;
use crate::ui::bar;

pub fn run() {
    println!("{}", bar("进程状态信息"));
    print!("{}", capture("ps aux"));
    println!();
    println!("{}", bar("服务状态信息"));
    println!();
    print!(
        "{}",
        capture("systemctl | grep -E \"\\.service.*running\" | awk -F. '{print $1}'")
    );
    println!();
    print!(
        "{}",
        capture(
            "for service in $(systemctl list-units --all | grep -v \"inactive\" | awk '/\\S+\\.service/ {gsub(/^[^[:alnum:]]+/, \"\"); print $1}' | grep -v UNIT); do   echo -e \"\\n-------------\\n服务: $service\\n-------------\";   systemctl show \"$service\" | grep -E \"MainPID|path\"; done"
        )
    );
}
