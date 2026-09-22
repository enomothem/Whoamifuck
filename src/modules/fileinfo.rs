//! 异常文件位置排查，对应 `fk_fileinfo`（-n / -a）。

use crate::color::*;
use crate::sys::capture;
use crate::ui::{bar, Stats};
use std::path::Path;

const DIRECTORIES: &[&str] = &["/home", "/opt"];

pub fn run() {
    let mut file_output = String::new();
    for dir in DIRECTORIES {
        file_output.push_str(&format!("{GREEN}列出 {dir} 下的文件和目录：{RESET}\n"));
        if Path::new(dir).is_dir() {
            let subdirs = capture(&format!("ls -d {dir}/*/ 2>/dev/null"));
            for user_dir in subdirs.lines() {
                if user_dir.is_empty() {
                    continue;
                }
                file_output.push_str(&format!("{GREEN}目录：{RESET}{user_dir}\n"));
                let listing = capture(&format!("ls -lt {user_dir} | head -n 10"));
                file_output.push_str(&listing);
                file_output.push('\n');
            }
        } else {
            file_output.push_str(&format!("{RED}目录 {dir} 不存在。{RESET}\n"));
        }
    }

    println!("{}", bar("文件位置排查"));
    println!();
    println!("{} 常见目录下的文件", Stats::ok());
    println!("-----------------");
    println!("{file_output}");
    println!();
}
