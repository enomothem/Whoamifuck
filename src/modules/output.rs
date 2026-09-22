//! 文本报告导出，对应 `fk_output` + `fk_hashfile`（-o）。

use crate::color::strip_ansi;
use crate::env::Env;
use crate::sys::{capture, command_exists, run_inherit, OsType};
use crate::ui::bar;
use std::fs;

const HASH_DIRS: &[&str] = &["/usr/bin", "/usr/local/bin", "/bin"];

pub fn run(env: &Env, out_name: Option<&str>) {
    println!("{}", bar("生成应急报告"));

    let output = &env.output;
    let _ = fs::create_dir_all(&env.output_t);
    let current_time = capture("date \"+%Y%m%d%H%M%S\"");
    let os = crate::sys::os_name();

    // --- 用户登录信息 ---
    let self_exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "who".to_string());
    let userlogin_raw = capture(&format!("'{self_exe}' -l"));
    let _ = fs::write(
        format!("{output}/chief_userlogin_info.txt"),
        strip_ansi(&userlogin_raw),
    );
    let login_all = match os.os_type {
        OsType::Debian => capture(&format!(
            "cat {} 2>/dev/null | tail -20000",
            env.authlog_file
        )),
        OsType::RedHat => capture(&format!(
            "cat {} 2>/dev/null | tail -20000",
            env.secure_file
        )),
    };
    let _ = fs::write(format!("{output}/chief_userlogin_info_all.txt"), login_all);

    // --- 历史命令 ---
    let _ = fs::write(
        "chief_history_current.txt",
        capture("cat ~/.*sh_history 2>/dev/null"),
    );
    let who_history = collect_all_users_history();
    let _ = fs::write(format!("{output}/chief_history_allusers.txt"), who_history);

    // --- 计划任务 ---
    let _ = fs::write("chief_crontab.txt", capture("crontab -l 2>/dev/null"));
    let _ = fs::write(
        format!("{output}/chief_cron_spool.txt"),
        capture("find /var/spool/cron/ -type f -exec cat {} \\; 2>/dev/null"),
    );
    let _ = fs::write(
        format!("{output}/chief_crond.txt"),
        capture("cat /etc/cron.*/* 2>/dev/null"),
    );

    // --- 二进制目录 hash ---
    let mut hashes = String::new();
    for dir in HASH_DIRS {
        hashes.push_str(&capture(&format!(
            "find {dir} -maxdepth 1 -type f -exec md5sum {{}} \\; 2>/dev/null"
        )));
        hashes.push('\n');
    }
    let _ = fs::write(format!("{output}/chief_binhashfile.txt"), hashes);

    // --- SSH 公钥 ---
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let sshkey = format!("{home}/.ssh/authorized_keys");
    if std::path::Path::new(&sshkey).is_file() {
        let _ = fs::write(
            format!("{output}/chief_sshpublickey.txt"),
            capture(&format!("cat {sshkey} 2>/dev/null")),
        );
    }

    // --- 服务信息 ---
    let service_show = capture(
        "for service in $(systemctl list-units --all | grep -v \"inactive\" | awk '/\\S+\\.service/ {gsub(/^[^[:alnum:]]+/, \"\"); print $1}' | grep -v UNIT); do   echo -e \"\\n-------------\\n服务: $service\\n-------------\";   systemctl show \"$service\" | grep -E \"path|ActiveState=\"; done",
    );
    if !service_show.is_empty() {
        let _ = fs::write(format!("{output}/chief_serviceinfo.txt"), service_show);
    }

    // --- 进程 / 网络 ---
    let process_show = capture("ps -ef");
    if command_exists("lsof") {
        let lsof_show = capture("lsof -i -L 2>/dev/null");
        let _ = fs::write(
            format!("{output}/processinfo.txt"),
            format!("{process_show} {lsof_show}"),
        );
    } else {
        let _ = fs::write(
            format!("{output}/processinfo.txt"),
            capture("netstat -antp 2>/dev/null"),
        );
    }

    // --- 全量文本（Normal 模式） ---
    let normal = capture(&format!("'{self_exe}' -n"));
    let stripped = strip_ansi(&normal);
    let out_file = match out_name {
        Some(n) if !n.is_empty() => format!("{output}/chief_{n}"),
        _ => format!("{output}/chief_output.txt"),
    };
    let _ = fs::write(&out_file, stripped);

    // 打包
    run_inherit(&format!(
        "tar -czf {}/report-{current_time}.tar.gz {output}/chief_* 2>/dev/null",
        env.output_t
    ));
    println!(
        "\n{} 导出结果成功。路径：{}/report-{current_time}.tar.gz",
        crate::ui::Stats::suc(),
        env.output_t
    );
    run_inherit(&format!("rm -f {output}/chief_*"));
}

fn collect_all_users_history() -> String {
    let files = [
        ".bash_history",
        ".zsh_history",
        ".csh_history",
        ".tcsh_history",
        ".fish_history",
    ];
    let mut out = String::new();
    if let Ok(entries) = fs::read_dir("/home") {
        for entry in entries.flatten() {
            let userdir = entry.path();
            if userdir.is_dir() {
                for f in &files {
                    let p = userdir.join(f);
                    if p.is_file() {
                        out.push_str(&format!(
                            "-------------| {} history | ----------------\n",
                            userdir.display()
                        ));
                        if let Ok(c) = fs::read_to_string(&p) {
                            out.push_str(&c);
                        }
                    }
                }
            }
        }
    }
    out
}
