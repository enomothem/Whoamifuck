//! ANSI 颜色与样式常量，对应原 who.sh 中的 `color` 函数。
//!
//! 此处保留完整调色板（部分常量当前未被引用），以忠实对应原脚本定义。
#![allow(dead_code)]

pub const RESET: &str = "\x1b[0m";
pub const BOLD: &str = "\x1b[1m";
pub const UNDERLINE: &str = "\x1b[4m";
pub const INVERSE: &str = "\x1b[7m";

// 前景色
pub const REDX: &str = "\x1b[1;31m";
pub const BLACK: &str = "\x1b[30m";
pub const RED: &str = "\x1b[1;31m";
pub const GREEN: &str = "\x1b[32m";
pub const YELLOW: &str = "\x1b[33m";
pub const ORANGE: &str = "\x1b[1;93m";
pub const BLUE: &str = "\x1b[1;34m";
pub const PURPLE: &str = "\x1b[35m";
pub const CYAN: &str = "\x1b[36m";
pub const WHITE: &str = "\x1b[1;37m";

// 背景色
pub const BG_BLACK: &str = "\x1b[40m";
pub const BG_RED: &str = "\x1b[41m";
pub const BG_GREEN: &str = "\x1b[42m";
pub const BG_YELLOW: &str = "\x1b[43m";
pub const BG_BLUE: &str = "\x1b[44m";
pub const BG_PURPLE: &str = "\x1b[45m";
pub const BG_CYAN: &str = "\x1b[46m";
pub const BG_WHITE: &str = "\x1b[47m";

/// 剥离字符串中的 ANSI 转义序列（对应 sed "s/\x1B\[[0-9;]*[JKmsu]//g"）。
pub fn strip_ansi(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b && i + 1 < bytes.len() && bytes[i + 1] == b'[' {
            let mut j = i + 2;
            while j < bytes.len() && (bytes[j].is_ascii_digit() || bytes[j] == b';') {
                j += 1;
            }
            if j < bytes.len() && matches!(bytes[j], b'J' | b'K' | b'm' | b's' | b'u') {
                i = j + 1;
                continue;
            }
        }
        // 安全地按字节推进（ASCII 转义之外的多字节 UTF-8 原样保留）
        let ch_len = utf8_len(bytes[i]);
        let end = (i + ch_len).min(bytes.len());
        out.push_str(std::str::from_utf8(&bytes[i..end]).unwrap_or(""));
        i = end;
    }
    out
}

fn utf8_len(b: u8) -> usize {
    if b < 0x80 {
        1
    } else if b >> 5 == 0b110 {
        2
    } else if b >> 4 == 0b1110 {
        3
    } else if b >> 3 == 0b11110 {
        4
    } else {
        1
    }
}
