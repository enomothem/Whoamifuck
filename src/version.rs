//! 版本号比较，复用系统 `sort -V` 语义，保证与原 who.sh 行为一致。

use crate::sys::capture;

/// 返回 a、b 中 `sort -V` 排序后的第一个（较小者）。
fn min_version(a: &str, b: &str) -> String {
    capture(&format!(
        "printf '%s\\n' {} {} | sort -V | head -n1",
        sq(a),
        sq(b)
    ))
}

fn sq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// a < b （对应 bash `version_lt`）。
pub fn version_lt(a: &str, b: &str) -> bool {
    a == min_version(a, b) && a != b
}

/// a >= b （对应 bash `version_ge`：min(a,b) == b）。
pub fn version_ge(a: &str, b: &str) -> bool {
    min_version(a, b) == b
}
