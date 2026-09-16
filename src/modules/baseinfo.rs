//! 用户基本信息，对应 `fk_baseinfo`（-u / -n / -a 均会调用）。

use crate::color::*;
use crate::env::Env;
use crate::sys::{self, capture, command_exists};
use crate::ui::bar;

pub fn run(env: &Env) {
    // 网卡与 IP / 子网
    let (ip, zw) = collect_interfaces();

    // 网关
    let gw = if command_exists("route") {
        capture("route -n | tail -1 | awk '{print $1}'")
    } else {
        capture("ip route | head -1 | awk '{print $3}'")
    };

    let hn = capture("hostname");
    let vm = capture(
        "lscpu | grep \"Hyper.*:\\|Virtu\\|超管理器厂商\" | awk -F [:：] '{print $2}' | sed 's/ //g' | paste -sd, | sed 's/,full//g'",
    );
    let dns = capture("cat /etc/resolv.conf | grep nameserver | awk '{print $2}' | paste -sd,");
    let os = capture("uname --kernel-name --kernel-release");
    let tun = capture("uptime | sed 's/user.*$//' | awk '{print $NF}'");
    let m_time = capture("date +\"%Y-%m-%d %H:%M:%S %s\"");
    let osname_ver = capture("cat /etc/os-release | grep '^VERSION_ID=' | awk -F '=' '{print $2}'");
    let osname = sys::os_name().name;

    let ip_c = format!("{CYAN}{ip}{RESET}");
    let hn_c = format!("{YELLOW}{hn}{RESET}「 {REDX}{}{RESET} 」", env.whoamifuck);
    let osname_c = format!("{BG_YELLOW}{osname} {osname_ver}{RESET}「 {BLUE}{vm}{RESET} 」");
    let tun_c = format!("{PURPLE}{tun}{RESET}");
    let m_time_c = format!("{GREEN}{m_time}{RESET}");

    let last = capture("last -i | head");
    let lastlog = capture("lastlog | grep -v Never");

    let mut current_user_tasks = capture("crontab -l 2>/dev/null | wc -l");
    let mut etc_crontab_tasks =
        capture("grep -vE '^\\s*#|^\\s*$' /etc/crontab | grep -vE '^[A-Za-z]' | wc -l");
    let mut var_spool_tasks =
        capture("grep -s . /var/spool/cron/* | grep -v '^Binary' | wc -l");
    if current_user_tasks.is_empty() {
        current_user_tasks = "0".to_string();
    }
    if etc_crontab_tasks.is_empty() {
        etc_crontab_tasks = "0".to_string();
    }
    if var_spool_tasks.is_empty() {
        var_spool_tasks = "0".to_string();
    }

    println!("{}", bar("用户基本信息"));
    println!();
    print!("{:<21}|\t{:<25}\t\t", "本机IP地址是", ip_c);
    println!("{:<21}|\t{}", "本机子网掩码是    ", zw);
    print!("{:<21}|\t{:<25}\t", "本机网关是", gw);
    println!("{:<17}|\t{}", "当前在线用户      ", tun_c);
    println!("{:<22}|\t{}", "本机主机名是", hn_c);
    println!("{:<19}|\t{}", "本机DNS是", dns);
    println!("{:<20}|\t{}", "系统版本", os);
    println!("{:<20}|\t{}", "系统内核", osname_c);
    println!("------------------------------------------------------------------------------------------------------");
    println!("{RED}> 在线用户具体信息{RESET}");
    print!("{}", env.fuck);
    println!("\n------------------------------------------------------------------------------------------------------");
    println!("{RED}> 最近用户登录信息{RESET}");
    print!("{last}");
    println!("\n------------------------------------------------------------------------------------------------------");
    println!("{RED}> 用户最后登录信息{RESET}");
    print!("{lastlog}");
    println!("\n------------------------------------------------------------------------------------------------------");
    println!("{RED}> 计划任务计数器 {RESET}");
    println!("当前用户的计划任务数量: {current_user_tasks}");
    println!("/etc/crontab 下的任务数量: {etc_crontab_tasks}");
    println!("/var/spool/cron 下的任务数量：{var_spool_tasks}");
    println!("------------------------------------------------------------------------------------------------------");
    print!("此刻唯一时间戳[本地]: {m_time_c}");
    println!();
}

/// 收集网卡 IP 与子网信息，兼容 ifconfig 与 ip 两种工具。
fn collect_interfaces() -> (String, String) {
    if command_exists("ifconfig") {
        let eth: usize = capture("ifconfig -s | grep ^e | awk '{print $1}' | wc -l")
            .trim()
            .parse()
            .unwrap_or(0);
        match eth {
            1 => {
                let ethx = capture("ifconfig -s | grep ^e | awk '{print $1}'");
                let ip = capture(&format!("ifconfig {ethx} | head -2 | tail -1 | awk '{{print $2}}'"));
                let zw = capture(&format!("ifconfig {ethx} | head -2 | tail -1 | awk '{{print $4}}'"));
                (ip, zw)
            }
            2 => {
                let eth0 = capture("ifconfig -s | grep ^e | awk 'NR==1{print $1}'");
                let eth1 = capture("ifconfig -s | grep ^e | awk 'NR==2{print $1}'");
                let ip1 = capture(&format!("ifconfig {eth0} | head -2 | tail -1 | awk '{{print $2}}'"));
                let zw1 = capture(&format!("ifconfig {eth0} | head -2 | tail -1 | awk '{{print $4}}'"));
                let ip2 = capture(&format!("ifconfig {eth1} | head -2 | tail -1 | awk '{{print $2}}'"));
                let zw2 = capture(&format!("ifconfig {eth1} | head -2 | tail -1 | awk '{{print $4}}'"));
                (format!("{ip1},{ip2}"), format!("{zw1},{zw2}"))
            }
            n if n > 2 => {
                println!("The variable is greater than 2");
                (String::new(), String::new())
            }
            _ => {
                println!("panic!");
                (String::new(), String::new())
            }
        }
    } else {
        let eth: usize = capture("ip -o link show | grep '^[0-9]*: e' | awk '{print $2}' | tr -d ':' | wc -l")
            .trim()
            .parse()
            .unwrap_or(0);
        match eth {
            1 => {
                let ethx = capture("ip -o link show | grep '^[0-9]*: e' | awk '{print $2}' | tr -d ':'");
                let ip = capture(&format!("ip -o -4 addr show {ethx} | awk '{{print $4}}' | cut -d/ -f1"));
                let zw = capture(&format!("ip -o -4 addr show {ethx} | awk '{{print $4}}' | cut -d/ -f2"));
                (ip, zw)
            }
            2 => {
                let eth0 = capture("ip -o link show | grep '^[0-9]*: e' | awk 'NR==1{print $2}' | tr -d ':'");
                let eth1 = capture("ip -o link show | grep '^[0-9]*: e' | awk 'NR==2{print $2}' | tr -d ':'");
                let ip1 = capture(&format!("ip -o -4 addr show {eth0} | awk '{{print $4}}' | cut -d/ -f1"));
                let zw1 = capture(&format!("ip -o -4 addr show {eth0} | awk '{{print $4}}' | cut -d/ -f2"));
                let ip2 = capture(&format!("ip -o -4 addr show {eth1} | awk '{{print $4}}' | cut -d/ -f1"));
                let zw2 = capture(&format!("ip -o -4 addr show {eth1} | awk '{{print $4}}' | cut -d/ -f2"));
                (format!("{ip1},{ip2}"), format!("{zw1},{zw2}"))
            }
            n if n > 2 => {
                println!("The variable is greater than 2");
                (String::new(), String::new())
            }
            _ => {
                println!("panic!");
                (String::new(), String::new())
            }
        }
    }
}
