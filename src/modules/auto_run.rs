//! 定时运行计划，对应 `fk_auto_run`（-e）。

use crate::color::*;
use crate::env::Env;
use crate::modules::extention::write_default_conf;
use crate::sys::{capture, run_inherit};
use crate::ui::Stats;
use std::path::Path;
use std::process;

pub fn run(env: &Env, hour_arg: Option<&str>, minute_arg: Option<&str>) {
    let dir = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "who".to_string());
    let script_dir = Path::new(&dir)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let dir_e = format!("{script_dir}/courier");
    let ext_file = env.conf_full();
    let ok_html = format!("{}/{}", env.output_m, env.courier);

    // 读取/生成配置并计算信使状态
    let mut email_stat = String::new();
    if Path::new(&ext_file).is_file() {
        println!(
            "{} 配置文件已找到，请正确配置文件{GREEN}{ext_file}{RESET}邮件信息！",
            Stats::ok()
        );
        let email = capture(&format!("source '{ext_file}' 2>/dev/null; echo \"$EMAIL\""));
        if email.is_empty() {
            println!("{} 未配置EMAIL开关。", Stats::no());
            let _ = append_line(&ext_file, "EMAIL=\"false\"");
            println!("{} 已将EMAIL开关导入配置文件，默认关闭。", Stats::ok());
            email_stat = format!("{} 信使未开启。", Stats::war());
        } else {
            email_stat = match email.as_str() {
                "true" => format!("{} 信使已开启。", Stats::suc()),
                "false" => format!("{} 信使未开启。", Stats::war()),
                _ => format!("{} EMAIL配置错误，只能是true或false。", Stats::war()),
            };
        }
    } else {
        println!("{} 配置文件{}未找到。", Stats::err(), env.conf_file);
        write_default_conf(&ext_file);
        println!(
            "{} 配置文件已生成，请前往配置文件{GREEN}{ext_file}{RESET}填写信息！",
            Stats::ok()
        );
    }
    println!("{email_stat}");

    // 解析小时
    let hour: String = match hour_arg {
        None | Some("") => {
            println!("{} 可使用 -e c 清除whoamifuck的所有日志。", Stats::info());
            println!(
                "{} 可使用 -e 时 分 设置每天的执行时间（default: 0:0）。",
                Stats::info()
            );
            "0".to_string()
        }
        Some("c") => {
            clear_crontab(&dir);
            return;
        }
        Some(h) => h.to_string(),
    };
    let minute: String = match minute_arg {
        None | Some("") => "0".to_string(),
        Some(m) => m.to_string(),
    };

    // 校验范围
    match hour.parse::<i64>() {
        Ok(h) if (0..=23).contains(&h) => {}
        _ => {
            println!("{} 请填写范围0到23小时之间的整数。", Stats::err());
            process::exit(1);
        }
    }
    match minute.parse::<i64>() {
        Ok(m) if (0..=59).contains(&m) => {}
        _ => {
            println!("{} 请填写范围0到59分钟之间的整数。", Stats::err());
            process::exit(1);
        }
    }

    // 读取邮件相关配置
    let email = capture(&format!("source '{ext_file}' 2>/dev/null; echo \"$EMAIL\""));
    let from = capture(&format!("source '{ext_file}' 2>/dev/null; echo \"$FROM\""));
    let key = capture(&format!("source '{ext_file}' 2>/dev/null; echo \"$KEY\""));
    let to = capture(&format!("source '{ext_file}' 2>/dev/null; echo \"$TO\""));
    let cc = capture(&format!("source '{ext_file}' 2>/dev/null; echo \"$CC\""));
    let server = capture(&format!(
        "source '{ext_file}' 2>/dev/null; echo \"$SERVER\""
    ));

    // 设置 cron 作业
    match email.as_str() {
        "false" => {
            add_crontab(&format!("{minute} {hour} * * * {dir} -m"));
        }
        "true" => {
            if Path::new("courier").is_file() {
                println!("{} 信使已到达。", Stats::suc());
                if cc.is_empty() {
                    add_crontab(&format!(
                        "{minute} {hour} * * * {dir} -m && {dir_e} -u {from} -s {server} -t {to} -r {ok_html} -k {key} "
                    ));
                } else {
                    add_crontab(&format!(
                        "{minute} {hour} * * * {dir} -m && {dir_e} -u {from} -s {server} -t {to} -r {ok_html} -k {key} -c {cc}"
                    ));
                }
            } else {
                println!("{} 信使已失踪。", Stats::war());
                add_crontab(&format!("{minute} {hour} * * * {dir} -m"));
            }
        }
        _ => {
            println!("{} 邮件配置错误。", Stats::err());
        }
    }

    println!(
        "{} Whoamifuck的计划任务日志模块将在每天 {hour}:{minute} 执行一次。",
        Stats::info()
    );
    println!("{CYAN}------------- | {RESET}{PURPLE}crontab{RESET}{CYAN} | --------------{RESET}");
    run_inherit("crontab -l");
}

fn clear_crontab(dir: &str) {
    run_inherit(&format!(
        "crontab -l 2>/dev/null | grep -v '{dir}' | crontab -"
    ));
    println!("{} 清除成功\n", Stats::suc());
    println!("{CYAN}------------- | {RESET}{PURPLE}crontab{RESET}{CYAN} | --------------{RESET}");
    run_inherit("crontab -l");
}

fn add_crontab(entry: &str) {
    run_inherit(&format!(
        "(crontab -l 2>/dev/null; echo {}) | crontab -",
        sq(entry)
    ));
}

fn sq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn append_line(path: &str, line: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(f, "{line}")
}
