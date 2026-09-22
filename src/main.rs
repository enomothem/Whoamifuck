//! 司稽 (Whoamifuck / Chief-Inspector) —— Linux 应急响应与入侵检测工具。
//!
//! 本程序是原 who.sh (bash) 的 Rust 重构版本，忠实保留了原有的命令行接口、
//! 输出风格与检测逻辑。控制流、CLI 分发、数据表（内核 CVE 列表）、版本比较等
//! 由 Rust 原生实现；对系统状态的采集仍复用底层系统命令（ps/ss/last/find 等），
//! 这与任何应急响应工具的做法一致，也保证了输出与原版一致。

mod color;
mod env;
mod modules;
mod sys;
mod ui;
mod util;
mod version;

use env::Env;

fn main() {
    let env = Env::new();

    // 必须以 root 运行，对应 `fk_main` 中的 EUID 检查。
    if !sys::is_root() {
        println!(
            "{}[-] This script must be run as root{}",
            color::REDX,
            color::RESET
        );
        std::process::exit(1);
    }

    util::check_command();

    let args: Vec<String> = std::env::args().collect();
    let op = args.get(1).map(|s| s.as_str()).unwrap_or("");
    let arg2 = args.get(2).map(|s| s.as_str());
    let arg3 = args.get(3).map(|s| s.as_str());

    dispatch(&env, op, arg2, arg3);
}

/// 命令分发，对应原 `fk_options`。
fn dispatch(env: &Env, op: &str, arg2: Option<&str>, arg3: Option<&str>) {
    match op {
        "-a" | "--all" => {
            modules::baseinfo::run(env);
            modules::devicestatus::run();
            modules::userlogin::run(env, None);
        }
        "-b" | "--baseline" => modules::baseline::run(),
        "-c" | "--code" => modules::http_scan::run(arg2),
        "-e" | "--auto-run" => modules::auto_run::run(env, arg2, arg3),
        "-h" | "--help" => ui::help_cn(env),
        "-i" | "--sqletlog" => modules::sqli::run(arg2),
        "-k" | "--rootkitcheck" | "--rookitcheck" => modules::rootkit::run(),
        "-l" | "--login" => modules::userlogin::run(env, arg2),
        "-m" | "--html" => modules::report_html::run(env, arg2),
        "-n" | "--nomal" => {
            modules::baseinfo::run(env);
            modules::history::run();
            modules::crontab::run();
            modules::filemove::run();
            modules::fileinfo::run();
            modules::userinfo::run(env);
        }
        "-o" | "--output" => modules::output::run(env, arg2),
        "-p" | "--port" => modules::port::run(),
        "-r" | "--risk" => modules::vulncheck::run(),
        "-s" | "--os-status" => modules::devicestatus::run(),
        "-t" | "--terminalproxy" => modules::terminal_proxy::run(arg2),
        "-u" | "--user-device" => modules::baseinfo::run(env),
        "-v" | "--version" => println!("{}", env.ver),
        "-w" | "--webshell" => modules::webshell::run(arg2),
        "-x" | "--proc-serv" => modules::procserv::run(),
        "-y" | "--whoamifuck" => modules::autofuck::run(),
        "-z" | "--ext" => modules::extention::run(env, arg2),
        _ => ui::help_en(env),
    }
}
