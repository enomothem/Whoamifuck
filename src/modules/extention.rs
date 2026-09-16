//! 自定义扩展命令，对应 `fk_extention`（-z）。

use crate::color::*;
use crate::env::Env;
use crate::sys::{capture, run_inherit};
use crate::ui::{bar, Stats};
use std::fs;
use std::path::Path;

/// 解析后的配置文件内容。
pub struct Conf {
    pub ext: Option<String>,
    #[allow(dead_code)]
    pub email: Option<String>,
    pub commands: Vec<(String, String)>,
}

/// 通过 bash source 解析配置文件（保持与原脚本一致的语义）。
pub fn parse_conf(path: &str) -> Option<Conf> {
    if !Path::new(path).is_file() {
        return None;
    }
    let ext = capture(&format!("source '{path}' 2>/dev/null; echo \"$EXT\""));
    let email = capture(&format!("source '{path}' 2>/dev/null; echo \"$EMAIL\""));
    let cmds_raw = capture(&format!(
        "source '{path}' 2>/dev/null; printf '%s\\n' \"${{commands[@]}}\""
    ));
    let commands = cmds_raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let mut it = l.splitn(2, ';');
            let cmd = it.next().unwrap_or("").to_string();
            let desc = it.next().unwrap_or("").to_string();
            (cmd, desc)
        })
        .collect();
    Some(Conf {
        ext: opt(ext),
        email: opt(email),
        commands,
    })
}

fn opt(s: String) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// 生成默认配置文件模板。
pub fn write_default_conf(path: &str) {
    if let Some(parent) = Path::new(path).parent() {
        let _ = fs::create_dir_all(parent);
    }
    let content = "EMAIL=\"false\"\n\
# 信使 - 邮箱配置，抄送CC可选\n\
FROM=\"Your Email\"\n\
KEY=\"Your Email Auth Code\"\n\
TO=\"to Email\"\n\
CC=\"to Email\"\n\
SERVER=\"Your Email SERVER\"\n\
EXT=\"false\"\n\
# 以命令 + 描述的方式增加\n\
commands=(\n\
#    \"cat /etc/passwd | grep -v nologin | cut -d: -f1 | paste -sd,;列出所有用户\"\n\
)\n";
    let _ = fs::write(path, content);
}

pub fn run(env: &Env, ext_path: Option<&str>) {
    println!("{}", bar("高级扩展命令"));
    println!();

    let ext_file = match ext_path {
        Some(p) if !p.is_empty() => p.to_string(),
        _ => env.conf_full(),
    };

    if Path::new(&ext_file).is_file() {
        if let Some(conf) = parse_conf(&ext_file) {
            let ext_stat = match conf.ext.as_deref() {
                Some("true") => format!("{} 扩展命令已开启。", Stats::suc()),
                Some("false") => format!("{} 扩展命令已关闭。", Stats::war()),
                _ => format!("{} config error.", Stats::err()),
            };
            println!("{ext_stat}");
            for (cmd, desc) in &conf.commands {
                println!("{} {desc}", Stats::ok());
                println!("-----------------");
                run_inherit(cmd);
            }
        }
    } else {
        println!("{} 配置文件{}未找到。", Stats::err(), env.conf_file);
        write_default_conf(&ext_file);
        println!("{} 配置文件已生成！{GREEN}{ext_file}{RESET}", Stats::ok());
    }
}
