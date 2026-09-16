//! 用户信息排查，对应 `fk_userinfo`（-n / -a）。

use crate::env::Env;
use crate::modules::{extention, userlogin};
use crate::sys::capture;
use crate::ui::{bar, Stats};
use std::path::Path;

pub fn run(env: &Env) {
    let user = capture("cat /etc/passwd | tail -10");
    let shadow = capture("cat /etc/shadow | tail -10");
    let root = capture("awk -F: '$3==0{print $1}' /etc/passwd");
    let telnet = capture("awk '/$1|$6/{print $1}' /etc/shadow");
    let sudo_file = "/etc/sudoers";
    let sudo = if Path::new(sudo_file).is_file() {
        capture("more /etc/sudoers | grep -v \"^#|^$\" | grep \"ALL=(ALL)\"")
    } else {
        format!("{} 不存在 {} 文件。", Stats::no(), sudo_file)
    };

    println!();
    println!("{}", bar("用户信息排查"));
    println!();
    println!("{} /etc/passwd最新10个用户", Stats::ok());
    println!("-----------------");
    println!();
    println!("{user}");
    println!();
    println!("{} /etc/shadow最新10个影子", Stats::ok());
    println!("-----------------");
    println!();
    println!("{shadow}");
    println!();
    println!("{} 具有root权限的用户", Stats::ok());
    println!("-----------------");
    println!("{root}");
    println!();
    println!("{} 具有远程登入权限的用户", Stats::ok());
    println!("-----------------");
    println!("{telnet}");
    println!();
    println!("{} 是否拥有SUDO权限的普通用户", Stats::ok());
    println!("-----------------");
    println!("{sudo}");
    println!();
    userlogin::run(env, None);
    println!();

    // 若存在配置文件且 EXT=true，则执行扩展命令。
    let conf = env.conf_full();
    if Path::new(&conf).is_file() {
        if let Some(cfg) = extention::parse_conf(&conf) {
            if cfg.ext.as_deref() == Some("true") {
                extention::run(env, None);
            }
        }
    }
}
