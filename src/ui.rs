//! 界面输出：LOGO、帮助信息、模块标题栏(bar)、状态标记(stats)。

use crate::color::*;
use crate::env::Env;

/// 状态标记，对应原 `stats` 函数。
pub struct Stats;

impl Stats {
    pub fn suc() -> String {
        format!("[{GREEN}SUCCESS{RESET}]")
    }
    pub fn war() -> String {
        format!("[{ORANGE}WARNING{RESET}]")
    }
    pub fn err() -> String {
        format!("[{REDX}ERROR{RESET}]")
    }
    pub fn ok() -> String {
        format!("[{GREEN}+{RESET}]")
    }
    pub fn no() -> String {
        format!("[{REDX}-{RESET}]")
    }
    pub fn info() -> String {
        format!("[{BLUE}*{RESET}]")
    }
}

/// 生成右对齐 50 宽的红色标题栏，对应原 `bar` 函数中的各变量。
pub fn bar(title: &str) -> String {
    format!("{RED}{:>50}{RESET}", format!("[ {title} ]"))
}

/// 打印 LOGO，对应原 `logo` 函数。
pub fn logo(env: &Env) {
    println!();
    println!();
    let hh = format!("{RESET}{GREEN}<bug>{RESET}{RED}");
    let s = format!("{RESET}{REDX}777{RESET}{RED}");
    let r = format!("{RESET}{YELLOW}who!{RESET}{RED}");
    let x = format!("{RESET}{ORANGE}root{RESET}{RED}");
    println!("{RED} ██╗    ██╗██╗  ██╗ ██████╗  █████╗ ███╗   ███╗██╗    ███████╗██╗   ██╗ ██████╗██╗  ██╗ {RESET}");
    println!("{RED} ██║{x}██║██║  ██║██╔═══██╗██╔══██╗████╗ ████║██║    ██╔════╝██║   ██║██╔════╝██║ ██╔╝ {RESET}");
    println!("{RED} ██║ █╗ ██║███████║██║{s}██║███████║██╔████╔██║██║    █████╗  ██║   ██║██║{hh}█████╔╝  {RESET}");
    println!("{RED} ██║███╗██║██╔══██║██║   ██║██╔══██║██║╚██╔╝██║██║    ██╔══╝  ██║   ██║██║     ██╔═██╗  {RESET}");
    println!("{RED} ╚███╔███╔╝██║  ██║╚██████╔╝██║  ██║██║ ╚═╝ ██║██║    ██║     ╚██████╔╝╚██████╗██║  ██╗ {RESET}");
    println!("{RED}  ╚══╝╚══╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝    ╚═╝ {r} ╚═════╝  ╚═════╝╚═╝  ╚═╝ {RESET}");
    println!(
        "       Hi {}          {}          by \\Eonian Sharp\\ -{BLUE} Enomothem{RESET}     ",
        env.whoamifuck, env.ver
    );
}

const COL1: usize = 30;
const COL2: usize = 50;

fn row(indent: &str, left: &str, right: &str) {
    println!("{indent}{left:<COL1$} {right:<COL2$}");
}

/// 中文帮助，对应 `help_cn`。
pub fn help_cn(env: &Env) {
    logo(env);
    println!("{:<COL1$} {:<COL2$}", "使用方法:", "");
    println!();
    row("\t", "-v --version", "版本信息");
    row("\t", "-h --help", "帮助指南");
    println!();
    row("  ", "QUICK", "");
    row("\t", "-u --user-device", "查看设备基本信息");
    row(
        "\t",
        "-l --login [FILEPATH]",
        "用户登录信息 [default:/var/log/secure;/var/log/auth.log]",
    );
    row("\t", "-n --nomal", "基本输出模式");
    row("\t", "-a --all", "全量输出模式");
    println!();
    row("  ", "SPECIAL", "");
    row("\t", "-x --proc-serv", "检查用户进程与开启服务状态");
    row("\t", "-p --port", "查看端口开放状态");
    row("\t", "-s --os-status", "查看系统状态信息");
    println!();
    row("  ", "RISK", "");
    row("\t", "-b --baseline", "基线安全评估");
    row("\t", "-r --risk", "查看系统可能存在的漏洞");
    row("\t", "-k --rookitcheck", "检测系统可能存在的后门");
    row(
        "\t",
        "-w --webshell [PATH]",
        "查找可能存在的webshell文件 [default:/var/www/;/www/wwwroot/..]",
    );
    println!();
    row("  ", "MISC", "");
    row("\t", "-c --code [URL|FILE]", "页面存活探测");
    row("\t", "-i --sqletlog [FILE]", "日志分析-SQL注入专业分析");
    row(
        "\t",
        "-e --auto-run [0-23 0-59|c]",
        "加入到定时运行计划 [default:~/.whok/chief-inspector.conf]",
    );
    row(
        "\t",
        "-z --ext [PATH]",
        "自定义命令配置测试 [default:~/.whok/chief-inspector.conf]",
    );
    println!();
    row("  ", "OUTPUT", "");
    row("\t", "-o --output [FILENAME]", "导出全量输出模式文件");
    row("\t", "-m --html [FILENAME]", "导出全量输出模式HTML文件");
    println!();
}

/// 英文帮助，对应 `help_en`。
pub fn help_en(env: &Env) {
    logo(env);
    println!("{:<COL1$} {:<COL2$}", "USAGE:", "");
    println!();
    row("\t", "-v --version", "Show version.");
    row("\t", "-h --help", "Show help guide.");
    println!();
    row("  ", "QUICK", "");
    row("\t", "-u --user-device", "Check device information.");
    row(
        "\t",
        "-l --login [FILEPATH]",
        "Show user login log. [default:/var/log/secure;/var/log/auth.log]",
    );
    row("\t", "-n --nomal", "Nomal print.");
    row("\t", "-a --all", "All print.");
    println!();
    row("  ", "SPECIAL", "");
    row(
        "\t",
        "-x --proc-serv",
        "Check service and process information.",
    );
    row("\t", "-p --port", "Show port information.");
    row("\t", "-s --os-status", "Show os status information.");
    println!();
    row("  ", "RISK", "");
    row("\t", "-b --baseline", "Baseline security assessment.");
    row("\t", "-r --risk", "Check os vulneribility.");
    row("\t", "-k --rookitcheck", "Check os rookit.");
    row(
        "\t",
        "-w --webshell [PATH]",
        "Find the webshell file. [default:/var/www/;/www/wwwroot/..]",
    );
    println!();
    row("  ", "MISC", "");
    row("\t", "-c --code [URL|FILE]", "Http status code scan.");
    row(
        "\t",
        "-i --sqletlog [FILE]",
        "Log Analysis - Professional Analysis of SQL Injection.",
    );
    row(
        "\t",
        "-e --auto-run [0-23 0-59|c]",
        "Add to crontab to run regularly. [default:~/.whok/chief-inspector.conf]",
    );
    row(
        "\t",
        "-z --ext [PATH]",
        "Custom command configuration tests. [default:./.whok/chief-inspector.conf]",
    );
    println!();
    row("  ", "OUTPUT", "");
    row("\t", "-o --output [FILENAME]", "Output to file.");
    row("\t", "-m --html [FILENAME]", "Output to html file.");
    println!();
}
