//! 常见漏洞自查，对应 `fk_vulcheck` + `dirty_cow` + `dirty_pipe` + `copy_fail`（-r）。

use crate::color::*;
use crate::modules::kernel_cve_data::{KPATCH_MODULE_NAMES, VALID_OS, VULNERABLE_KERNELS};
use crate::sys::{capture, command_exists};
use crate::ui::bar;
use crate::version::{version_ge, version_lt};
use std::fs;
use std::path::Path;

const SEP: &str = "-------------------------------------------------------------------------------------";

pub fn run() {
    println!();
    println!("{}", bar("常见漏洞评估"));
    println!();

    // 1. redis 未授权
    println!("{RED}1. redis未授权{RESET}\n");
    let redis_unauth = capture(
        "find / -name \"redis.conf\" -exec grep --color=always -H \"# requirepass \" {} \\; 2>/dev/null",
    );
    println!("{redis_unauth}");
    let _ = append_file("vuln.log", &format!("{}\n", strip_ansi(&redis_unauth)));
    println!();

    // 2. redis 弱口令自查
    println!("{RED}2. redis弱口令自查{RESET}\n");
    println!(
        "{}",
        capture(
            "find / -name \"redis.conf\" -exec grep --color=always -H \"^requirepass \" {} \\; 2>/dev/null | awk '{split($0, a, \" \"); $NF=\"****\"; print}'"
        )
    );
    let passes = capture(
        "find / -name \"redis.conf\" -exec grep -H \"^requirepass \" {} \\; 2>/dev/null | awk '{print $2}'",
    );
    let _ = fs::write("pass.tmp", &passes);
    println!("---------------");
    println!(
        "{}",
        capture(
            "grep -E \"admin123|test|123456|admin|root|12345678|111111|p@ssw0rd|test|qwerty|zxcvbnm|123123|12344321|123qwe|password|1qaz|000000|666666|888888|foobared\" pass.tmp | awk '{print \"[+] \"$1}'"
        )
    );

    let _ = fs::create_dir_all("output");
    if let Ok(log) = fs::read_to_string("vuln.log") {
        let _ = fs::write("output/vuln.txt", strip_ansi(&log));
    }
    let _ = fs::remove_file("vuln.log");
    let _ = fs::remove_file("pass.tmp");
    println!("{SEP}");

    // 3. CVE-2018-15473 (OpenSSH 用户名枚举)
    let openssh_15473 = if command_exists("sshd") {
        let (major, minor) = ssh_version();
        if (2..=7).contains(&major) && minor <= 7 {
            format!("OpenSSH版本 {major}.{minor} 受漏洞影响")
        } else {
            format!("{GREEN}OpenSSH版本 {major}.{minor} 不受漏洞影响{RESET}}}")
        }
    } else {
        "无".to_string()
    };
    println!("{RED}3. CVE-2018-15473(OpenSSH用户名枚举){RESET} {PURPLE}{openssh_15473}{RESET}");
    println!("{SEP}");

    // 4. CVE-2024-6387 (OpenSSH 远程代码执行)
    let openssh_6387 = if command_exists("sshd") {
        let (major, minor) = ssh_version();
        if (major == 8 && minor >= 5) || (major == 9 && minor < 8) {
            format!("OpenSSH版本 {major}.{minor} 受漏洞影响")
        } else {
            format!("{GREEN}OpenSSH版本 {major}.{minor} 不受漏洞影响{RESET}")
        }
    } else {
        "无".to_string()
    };
    println!("{RED}4. CVE-2024-6387(OpenSSH远程代码执行){RESET} {PURPLE}{openssh_6387}{RESET}");
    println!("{SEP}");

    // 5/6/7. sudo 漏洞
    let (sudo_2019, sudo_2021, sudo_2023) = sudo_risks();
    println!("{RED}5. CVE-2019-18634(Sudo本地提权漏洞){RESET} {PURPLE}{sudo_2019}{RESET}");
    println!("{SEP}");
    println!("{RED}6. CVE-2021-3156 (Sudo溢出提权漏洞){RESET} {PURPLE}{sudo_2021}{RESET}");
    println!("{SEP}");
    println!("{RED}7. CVE-2023-22809(Sudo本地提权漏洞){RESET} {PURPLE}{sudo_2023}{RESET}");
    println!("{SEP}");

    // 8. CVE-2024-3094 XZ Utils
    let xz_risk = if command_exists("xz") {
        let v = capture("xz --version 2>&1 | grep -oP 'xz.* \\K[0-9]+\\.[0-9]+\\.[0-9]+'");
        let (maj, min, pat) = three_part(&v);
        if maj == 5 && min == 6 && (pat == 0 || pat == 1) {
            format!("XZ Utils版本 {v} 受漏洞影响")
        } else {
            format!("{GREEN}XZ Utils版本 {v} 不受漏洞影响{RESET}")
        }
    } else {
        "未安装 XZ Utils".to_string()
    };
    println!("{RED}8. CVE-2024-3094（XZ投毒植入恶意后门压缩命令）{RESET} {PURPLE}{xz_risk}{RESET}");
    println!("{SEP}");

    // 9/10/11. 内核类漏洞
    dirty_cow();
    dirty_pipe();
    copy_fail();
}

/// 解析 sshd 主/次版本号。
fn ssh_version() -> (u32, u32) {
    let v = capture("sshd -v 2>&1 | grep -oP 'OpenSSH_\\K[0-9]+\\.[0-9]+'");
    let mut it = v.split('.');
    let major = it.next().unwrap_or("").trim().parse().unwrap_or(0);
    let minor = it.next().unwrap_or("").trim().parse().unwrap_or(0);
    (major, minor)
}

/// 解析形如 x.y.z 的三段版本号。
fn three_part(v: &str) -> (u32, u32, u32) {
    let mut it = v.split('.');
    let a = it.next().unwrap_or("").trim().parse().unwrap_or(0);
    let b = it.next().unwrap_or("").trim().parse().unwrap_or(0);
    let c = it.next().unwrap_or("").trim().parse().unwrap_or(0);
    (a, b, c)
}

fn sudo_risks() -> (String, String, String) {
    if !command_exists("sudo") {
        return ("无".to_string(), "无".to_string(), "无".to_string());
    }
    let v = capture("sudo -V 2>&1 | grep -oP 'Sudo version \\K[0-9]+\\.[0-9]+\\.[0-9]+'");
    let (major, minor, patch) = three_part(&v);

    let r2019 = if major == 1 && (7..=8).contains(&minor) && patch <= 30 {
        format!("Sudo版本 {v} 受漏洞影响")
    } else {
        format!("{GREEN}Sudo版本 {v} 不受漏洞影响{RESET}")
    };
    let r2021 = if (major == 1 && minor == 8 && (2..=31).contains(&patch))
        || (major == 1 && minor == 9 && patch <= 5)
    {
        format!("Sudo版本 {v} 受漏洞影响")
    } else {
        format!("{GREEN}Sudo版本 {v} 不受漏洞影响{RESET}")
    };
    let r2023 = if major == 1 && (8..=9).contains(&minor) && patch <= 12 {
        format!("Sudo版本 {v} 受漏洞影响")
    } else {
        format!("{GREEN}Sudo版本 {v} 不受漏洞影响{RESET}")
    };
    (r2019, r2021, r2023)
}

/// CVE-2016-5195 Dirty Cow 脏牛。
fn dirty_cow() {
    let running_kernel = capture("uname -r");

    // collectSystemStats: 取发行版代号 / 可更新内核版本
    let mut ver = String::new();
    let mut update_version = String::new();
    if Path::new("/etc/lsb-release").is_file() {
        ver = capture(". /etc/lsb-release 2>/dev/null; echo $DISTRIB_CODENAME");
        update_version = capture(
            "apt-cache policy linux-image-server 2>/dev/null | grep Candidate | awk -F': ' '{print $2}' | awk -F'.' '{print $1 \".\" $2 \".\" $3 \"-\" $4 \"-generic\"}'",
        );
    } else if Path::new("/etc/os-release").is_file() {
        ver = capture(". /etc/os-release 2>/dev/null; echo $REDHAT_SUPPORT_PRODUCT_VERSION");
    }

    let valid = VALID_OS.iter().any(|os| ver.contains(os));

    let vulnerable_kernel = VULNERABLE_KERNELS
        .iter()
        .any(|k| running_kernel.contains(k));
    let vulnerable_update_kernel = !update_version.is_empty()
        && VULNERABLE_KERNELS.iter().any(|k| update_version.contains(k));

    let modules = capture("lsmod");
    let applied_kpatch = KPATCH_MODULE_NAMES
        .iter()
        .find(|k| modules.contains(**k))
        .copied();

    // checkMitigation
    let dmesg = capture("dmesg 2>/dev/null");
    let mut mitigated = false;
    for line in dmesg.lines() {
        if line.contains("CVE-2016-5195 mitigation loaded") {
            mitigated = true;
        } else if line.contains("CVE-2016-5195 mitigation unloaded") {
            mitigated = false;
        }
    }

    // checkResult
    let result = if !vulnerable_kernel {
        "SAFE_KERNEL"
    } else if applied_kpatch.is_some() {
        "SAFE_KPATCH"
    } else if mitigated {
        "MITIGATED"
    } else {
        "VULNERABLE"
    };

    if !valid {
        println!("{RED}This script is only meant to detect vulnerable kernels on Ubuntu 12.04, 14.04, and 16.04.{RESET}");
        println!("{RED}This script is only meant to detect vulnerable kernels on Red Hat Enterprise Linux 5, 6 and 7.{RESET}");
    }

    println!("{RED}9. CVE-2016–5195（Dirty Cow 脏牛Linux内核提权漏洞）{RESET}");
    match result {
        "SAFE_KERNEL" => {
            println!("{GREEN}您的内核版本为 {running_kernel}，不受该漏洞影响。{RESET}");
            println!("{SEP}");
            return;
        }
        "SAFE_KPATCH" => {
            println!("您的内核版本为 {running_kernel}，通常情况下是易受攻击的。");
            println!(
                "{GREEN}但是，您已经应用了 kpatch{}，该补丁修复了该漏洞。{RESET}",
                applied_kpatch.unwrap_or("")
            );
            println!("{SEP}");
        }
        "MITIGATED" => {
            println!("{YELLOW}您的内核版本为 {running_kernel}，存在该漏洞。{RESET}");
            println!("{YELLOW}您已应用了部分缓解措施。{RESET}");
            println!("该缓解措施可防范大多数已被利用的常见攻击向量，");
            println!("但无法防范所有可能的攻击向量。");
            println!("建议您尽快更新内核。");
            println!("{SEP}");
        }
        _ => {
            println!("{RED}您的内核版本为 {running_kernel}，存在该漏洞。{RESET}");
            println!("建议您更新内核。或者，您可以应用部分缓解措施，");
            println!("{SEP}");
        }
    }
    if vulnerable_update_kernel {
        println!("{RED}可供更新的内核版本为 {update_version}，该版本同样存在漏洞。{RESET}");
        println!("{SEP}");
    }
}

/// CVE-2022-0847 Dirty Pipe。
fn dirty_pipe() {
    let kernel = capture("uname -r");
    let start = "5.8";
    let end1 = "5.16.11";
    let end2 = "5.15.25";
    let end3 = "5.10.102";

    println!("{RED}10. CVE-2022-0847（Dirty Pipe Linux内核提权漏洞）{RESET}");
    let affected = version_lt(start, &kernel)
        && (version_lt(&kernel, end1) || version_lt(&kernel, end2) || version_lt(&kernel, end3));
    if affected {
        println!("{RED}当前内核版本为 {kernel}，存在 DirtyPipe（CVE-2022-0847）漏洞。{RESET}");
    } else {
        println!("{GREEN}当前内核版本为 {kernel}，不在受影响范围内。{RESET}");
    }
    println!("{SEP}");
}

/// CVE-2026-31431 Copy Fail。
// 分支结构刻意保留与原 bash `copy_fail` 一致，逐条列出各修复版本边界以便对照。
#[allow(clippy::if_same_then_else, clippy::needless_bool_assign)]
fn copy_fail() {
    let kernel = capture("uname -r");

    let module_status = if capture("lsmod 2>/dev/null | grep -q 'algif_aead' && echo y").contains('y')
    {
        "已加载"
    } else if Path::new(&format!("/lib/modules/{kernel}/modules.builtin")).is_file()
        && capture(&format!(
            "grep -q 'algif_aead' '/lib/modules/{kernel}/modules.builtin' 2>/dev/null && echo y"
        ))
        .contains('y')
    {
        "内置(builtin)"
    } else {
        "未加载"
    };

    let mut affected = false;
    if version_ge(&kernel, "4.12") {
        if version_ge(&kernel, "7.0") {
            affected = false;
        } else if version_ge(&kernel, "6.19.12") {
            affected = false;
        } else if version_ge(&kernel, "6.18.22") && version_lt(&kernel, "6.19") {
            affected = false;
        } else {
            affected = true;
        }
    }

    println!("{RED}11. CVE-2026-31431 (Copy Fail Linux内核本地提权漏洞){RESET}");
    if affected {
        println!("{RED}当前内核版本 {kernel} 受该漏洞影响{RESET}");
        println!("algif_aead 模块状态: {YELLOW}{module_status}{RESET}");
        println!("{RED}建议: 升级内核至 6.18.22+/6.19.12+/7.0+ 或禁用 algif_aead 模块{RESET}");
    } else {
        println!("{GREEN}当前内核版本 {kernel} 不受该漏洞影响{RESET}");
        if module_status != "未加载" {
            println!("algif_aead 模块状态: {module_status}");
        }
    }
    println!("{SEP}");
}

fn append_file(path: &str, content: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = fs::OpenOptions::new().create(true).append(true).open(path)?;
    f.write_all(content.as_bytes())
}
