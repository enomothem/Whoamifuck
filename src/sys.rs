//! 系统交互辅助：命令执行、OS 识别、环境探测。
//!
//! 该 IR 工具的本质是编排系统命令并对其输出进行解析/格式化。为忠实保留原
//! who.sh 的行为（依赖 ps/ss/last/systemctl/find 等），我们通过 `bash -c`
//! 执行复杂管道，并用 Rust 负责控制流、数据表、版本比较与格式化。

use std::process::{Command, Stdio};

/// 执行 `bash -c <command>`，捕获 stdout 并返回（去除尾部换行）。stderr 被丢弃。
pub fn capture(command: &str) -> String {
    let output = Command::new("bash")
        .arg("-c")
        .arg(command)
        .stderr(Stdio::null())
        .output();
    match output {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
            while s.ends_with('\n') || s.ends_with('\r') {
                s.pop();
            }
            s
        }
        Err(_) => String::new(),
    }
}

/// 执行 `bash -c <command>`，stdout/stderr 直接继承到终端（保留颜色与实时输出）。
/// 返回退出码是否为 0。
pub fn run_inherit(command: &str) -> bool {
    Command::new("bash")
        .arg("-c")
        .arg(command)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// 判断某个命令是否存在（等价于 `command -v <name>`）。
pub fn command_exists(name: &str) -> bool {
    Command::new("bash")
        .arg("-c")
        .arg(format!("command -v {name}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// 当前是否以 root 运行。
pub fn is_root() -> bool {
    // SAFETY: geteuid 无副作用，始终成功。
    unsafe { libc_geteuid() == 0 }
}

// 通过 libc 的 geteuid，避免额外依赖：直接声明外部符号。
extern "C" {
    #[link_name = "geteuid"]
    fn libc_geteuid() -> u32;
}

/// OS 类型（红帽系 / Debian 系）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsType {
    Debian,
    RedHat,
}

/// OS 识别结果，对应原 `os_name` 函数。
#[derive(Debug, Clone)]
pub struct OsInfo {
    pub name: String,
    pub os_type: OsType,
}

/// 读取 /etc/os-release 的 PRETTY_NAME 并识别发行版类型。
pub fn os_name() -> OsInfo {
    let pretty = capture("grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '\"'");
    let p = pretty.as_str();
    let (name, os_type) = if p.contains("Debian") {
        ("Debian", OsType::Debian)
    } else if p.contains("CentOS") {
        ("CentOS", OsType::RedHat)
    } else if p.contains("Ubuntu") {
        ("Ubuntu", OsType::Debian)
    } else if p.contains("Kali") {
        ("Kali", OsType::Debian)
    } else if p.contains("Parrot") {
        ("Parrot OS", OsType::Debian)
    } else if p.contains("Deepin") {
        ("Deepin", OsType::Debian)
    } else {
        ("Unknown distribution", OsType::RedHat)
    };
    OsInfo {
        name: name.to_string(),
        os_type,
    }
}

/// `whoami` 结果。
pub fn whoami() -> String {
    capture("whoami")
}

/// `who` 结果。
pub fn who() -> String {
    capture("who")
}
