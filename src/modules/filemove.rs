//! 文件修改信息排查，对应 `fk_filemove`（-n / -a）。

use crate::sys::capture;
use crate::ui::{bar, Stats};
use std::path::Path;

pub fn run() {
    let m_file = capture("find -type f -mtime -3");
    let m_file_var = capture("find /var/ -type f -mtime -3 | xargs ls -la 2>/dev/null");
    let c_file = capture("find -type f -ctime -3");

    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let sshkey_file = format!("{home}/.ssh/authorized_keys");
    let sshpubkey = if Path::new(&sshkey_file).is_file() {
        let perm = capture(&format!("stat -c %a {sshkey_file}"));
        let modi = capture(&format!("stat -c %y {sshkey_file}"));
        format!("{modi}({perm})")
    } else {
        "未找到该文件".to_string()
    };

    println!("{}", bar("文件信息排查"));
    println!();
    println!("{} 最近三天更改的文件", Stats::ok());
    println!("-----------------");
    println!("{m_file}\n");
    println!("{} 最近三天创建的文件", Stats::ok());
    println!("-----------------");
    println!("{c_file}\n");
    println!("{} /var下最近三天更改的文件", Stats::ok());
    println!("-----------------");
    println!("{m_file_var}\n");
    println!("{} PublicKey修改时间及其权限", Stats::ok());
    println!("-----------------");
    println!("{sshpubkey}\n");
    println!();
}
