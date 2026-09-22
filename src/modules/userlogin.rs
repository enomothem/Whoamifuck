//! 用户登录信息排查，对应 `fk_userlogin` / `user_debian` / `user_centos`（-l）。

use crate::color::*;
use crate::env::Env;
use crate::sys::{self, capture, OsType};
use crate::ui::bar;
use std::path::Path;

/// 主入口。`file` 为用户通过 -l 指定的日志文件（可为空）。
pub fn run(env: &Env, file: Option<&str>) {
    println!("{}", bar("用户登录信息"));

    if let Some(f) = file {
        if !f.is_empty() && Path::new(f).is_file() {
            if f.contains("secure") {
                user_centos(f);
            } else {
                user_debian(f);
            }
            return;
        }
    }

    // 未指定文件：按发行版选择默认日志路径。
    let os = sys::os_name();
    match os.os_type {
        OsType::Debian => {
            if Path::new(&env.authlog_file).is_file() {
                user_debian(&env.authlog_file);
            } else {
                println!("{}文件不存在", env.authlog_file);
            }
        }
        OsType::RedHat => {
            // 未知内核默认采用 RedHat 系列
            if os.name == "Unknown distribution" {
                println!("内核未知版本，默认采用RedHat系列。");
            }
            if Path::new(&env.secure_file).is_file() {
                user_centos(&env.secure_file);
            } else {
                println!("{}文件不存在", env.secure_file);
            }
        }
    }
}

fn user_debian(auth: &str) {
    println!("{BG_RED}\n『 用户登录 』{RESET}\n");
    println!(
        "{}",
        capture(&format!(
            "cat {auth} | grep \"session opened\" | awk '{{print $1 \" \" $2, $3, \"用户登录\", $11}}' | tail -20"
        ))
    );
    println!("{BG_RED}\n『 用户登出 』{RESET}\n");
    println!(
        "{}",
        capture(&format!(
            "cat {auth} | grep \"session closed\" | awk '{{print $1 \" \" $2, $3, \"用户登出\", $11}}' | tail -20"
        ))
    );
    println!("{BG_RED}\n『 攻击次数 攻击者IP --> 枚举用户名 』{RESET}\n");
    println!(
        "{}",
        capture(&format!(
            "cat {auth} | grep \"Failed password for invalid user\" | awk '{{print $13 \" --> \" $11}}' | sort | uniq -c | sort -rn | awk '{{print \"[+] 用户名不存在 \"$0}}' | head -20"
        ))
    );
    println!("{BG_RED}\n『 攻击者IP次数 』{RESET}\n");
    println!(
        "{}",
        capture(&format!(
            "cat {auth} | grep \"Failed password for invalid user\" | awk '{{print $11 \" --> \" $13}}' | sort | uniq -c | sort -rn | awk '{{print $4}}' | sort | uniq -c | awk '{{print \"[+] \"$2\" 攻击次数 \"$1\"次\"}}'"
        ))
    );
    println!("{BG_RED}\n『 登录成功IP地址 』{RESET}\n");
    println!(
        "{}",
        capture(&format!(
            "cat {auth} | grep \"Accepted\" | awk '{{print \"时间:\"$1\"-\"$2\"-\"$3\"\\t登录成功\\t \"$11\" --> \"$9 \" 使用方式: \"$7}}'"
        ))
    );
    println!("{BG_RED}\n『 对用户名进行密码爆破次数 』{RESET}\n");
    println!(
        "{}",
        capture(&format!(
            "cat {auth} | grep \"Failed password for\" | grep -v invalid | awk '{{print $11\"—->\"$9}}'| uniq -c | sort -rn | awk '{{print \"[+] 攻击次数: \" $1   \" 详情:   \"$2}}' | head -20"
        ))
    );
}

fn user_centos(secure: &str) {
    println!("{BG_RED}\n『 攻击次数TOP 攻击者IP --> 枚举用户名 』{RESET}\n");
    println!(
        "{}",
        capture(&format!(
            "cat {secure} | grep \"Failed password for invalid user\" | awk '{{print $13 \" --> \" $11}}' | sort | uniq -c | sort -rn | awk '{{print \"[+] 用户名不存在 \"$0}}' | head -20"
        ))
    );
    println!("{BG_RED}\n『 攻击者IP次数TOP 』{RESET}\n");
    println!(
        "{}",
        capture(
            "cat /var/log/secure | grep \"Failed password for invalid user\" | awk '{print $11 \" --> \" $13}' | sort | uniq -c | sort -rn | awk '{print $4}' | sort | uniq -c | sort -k1rn | awk '{print \"[+] \"$2\" 攻击次数 \"$1\"次\"}'"
        )
    );
    println!("{BG_RED}\n『 登录成功IP地址 』{RESET}\n");
    println!(
        "{}",
        capture(&format!(
            "cat {secure} | grep \"Accepted\" | awk '{{print \"时间:\"$1\"-\"$2\"-\"$3\"\\t登录成功\\t \"$11\" --> \"$9 \" 使用方式: \"$7}}'"
        ))
    );
    println!("{BG_RED}\n『 对用户名进行密码爆破次数 』{RESET}\n");
    println!(
        "{}",
        capture(&format!(
            "cat {secure} | grep \"Failed password for\" | grep -v invalid | awk '{{print $11\"—->\"$9}}'| uniq -c | sort -rn | awk '{{print \"[+] 攻击次数: \" $1   \" 详情:   \"$2}}' | head -20"
        ))
    );
}
