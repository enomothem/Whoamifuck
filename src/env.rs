//! 全局环境配置，对应原 who.sh 中的 `env` 函数。

use crate::sys;

/// 版本号字符串（对应 `VER`）。
pub const VER: &str = "2026.4.30@whoamifuck-version 7.1.0";

/// 运行期环境：默认路径、当前用户等。
#[derive(Debug, Clone)]
pub struct Env {
    pub ver: &'static str,
    pub whoamifuck: String,
    pub fuck: String,
    pub conf_path: String,
    pub conf_file: String,
    pub output: String,
    pub output_m: String,
    pub output_t: String,
    pub authlog_file: String,
    pub secure_file: String,
    pub courier: String,
}

impl Env {
    pub fn new() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        Env {
            ver: VER,
            whoamifuck: sys::whoami(),
            fuck: sys::who(),
            conf_path: format!("{home}/.whok"),
            conf_file: "chief-inspector.conf".to_string(),
            output: "output".to_string(),
            output_m: "output/html".to_string(),
            output_t: "output/text".to_string(),
            authlog_file: "/var/log/auth.log".to_string(),
            secure_file: "/var/log/secure".to_string(),
            courier: "courier.html".to_string(),
        }
    }

    /// 配置文件完整路径。
    pub fn conf_full(&self) -> String {
        format!("{}/{}", self.conf_path, self.conf_file)
    }
}

impl Default for Env {
    fn default() -> Self {
        Self::new()
    }
}
