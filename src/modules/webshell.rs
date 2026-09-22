//! webshell 查找，对应 `fk_wsfinder`（-w）。

use crate::color::*;
use crate::sys::run_inherit;
use crate::ui::bar;
use std::fs;
use std::path::Path;

const RULE_PHP: &str = r#"array_map\(|pcntl_exec\(|proc_open\(|popen\(|assert\(|phpspy|c99sh|milw0rm|eval?\(|\(gunerpress|\(base64_decoolcode|spider_bc|shell_exec\(|passthru\(|base64_decode\s?\(|gzuncompress\s?\(|gzinflate|\(\$\$\w+|call_user_func\(|call_user_func_array\(|preg_replace_callback\(|preg_replace\(|register_shutdown_function\(|register_tick_function\(|mb_ereg_replace_callback\(|filter_var\(|ob_start\(|usort\(|uksort\(|uasort\(|GzinFlate\s?\(|\$\w+\(\d+\)\.\$\w+\(\d+\)\.|\$\w+=str_replace\(|eval\/\*.*\*\/\("#;
const RULE_PHP_1: &str =
    r#"^(\xff\xd8|\x89\x50|GIF89a|GIF87a|BM|\x00\x00\x01\x00\x01)[\s\S]*<\?\s*php"#;
const RULE_PHP_2: &str = r#"\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\b[\/*\s]*\(+[\/*\s]*((\$_(GET|POST|REQUEST|COOKIE)\[.{0,25})|(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\s\(]*(\$_(GET|POST|REQUEST|COOKIE)\[.{0,25}))"#;
const RULE_PHP_3: &str = r#"\$\s*(\w+)\s*=[\s\(\{]*(\$_(GET|POST|REQUEST|COOKIE)\[.{0,25});[\s\S]{0,200}\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\b[\/*\s]*\(+[\s"\/*]*(\$\s*\1|((base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\s\("]*\$\s*\1))"#;
const RULE_PHP_4: &str = r#"\b(filter_var|filter_var_array)\b\s*\(.*FILTER_CALLBACK[^;]*((\$_(GET|POST|REQUEST|COOKIE|SERVER)\[.{0,25})|(eval|assert|ass\\x65rt|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec))"#;
const RULE_PHP_5: &str = r#"\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|include)\b\s*\(\s*(file_get_contents\s*\(\s*)?['"]php:\/\/input"#;
const RULE_JSP: &str = r#"<%@\spage\simport=[\s\S]*\\u00\d+\\u00\d+|<%@\spage\simport=[\s\S]*Runtime.getRuntime\(\).exec\(request.getParameter\(|Runtime.getRuntime\(\)"#;

pub fn run(webshell_path: Option<&str>) {
    let _ = fs::create_dir_all("output");
    println!("{}", bar("webshell查找"));

    match webshell_path {
        None | Some("") => {
            let webpath = "/www/wwwroot";
            let webroot = "/var/www";
            println!();
            println!("[+] check /www/wwwroot");
            println!();
            if Path::new(webpath).is_dir() {
                scan_dir(webpath, &[RULE_PHP], RULE_JSP);
            } else {
                println!("未找到该目录");
            }
            println!();
            println!("[+] check /var/www");
            println!();
            if Path::new(webroot).is_dir() {
                scan_dir(webroot, &[RULE_PHP], RULE_JSP);
            } else {
                println!("未找到该目录");
            }
        }
        Some(path) => {
            println!();
            println!("[+] check {path}");
            println!();
            if Path::new(path).is_dir() {
                scan_dir(
                    path,
                    &[
                        RULE_PHP, RULE_PHP_1, RULE_PHP_2, RULE_PHP_3, RULE_PHP_4, RULE_PHP_5,
                    ],
                    RULE_JSP,
                );
            } else {
                println!("未找到该目录");
            }
        }
    }

    println!();
    // 剥离颜色写入 txt，删除中间 log
    let _ = fs::create_dir_all("output");
    run_inherit(
        "sed \"s/\\x1B\\[[0-9;]*[JKmsu]//g\" output/webshell.log >> output/webshell.txt 2>/dev/null",
    );
    let _ = fs::remove_file("output/webshell.log");
}

fn scan_dir(path: &str, php_rules: &[&str], jsp_rule: &str) {
    println!("{RED}1. PHP类{RESET}");
    for rule in php_rules {
        run_inherit(&format!(
            "find {path} -type f -name \"*.php\" -exec grep -P -i --color=always {} {{}} + 2>/dev/null | tee -a output/webshell.log",
            single_quote(rule)
        ));
    }
    println!("{RED}2. JSP类{RESET}");
    run_inherit(&format!(
        "find {path} -type f -name \"*.jsp\" -exec grep -P -i --color=always {} {{}} + 2>/dev/null | tee -a output/webshell.log",
        single_quote(jsp_rule)
    ));
}

fn single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}
