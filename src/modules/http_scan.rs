//! 页面存活探测，对应 `fk_http_scan`（-c）。

use crate::color::*;
use crate::sys::capture;
use crate::ui::bar;
use std::fs;
use std::path::Path;

const USERAGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36";

pub fn run(list: Option<&str>) {
    println!();
    println!("{}", bar("存活页面探测"));
    println!();
    let _ = fs::create_dir_all("output");

    let target = list.unwrap_or("");
    if Path::new(target).is_file() {
        if let Ok(content) = fs::read_to_string(target) {
            for url in content.lines() {
                if url.trim().is_empty() {
                    continue;
                }
                probe(url.trim());
            }
        }
        println!();
    } else {
        probe(target);
        println!();
    }
}

fn probe(url: &str) {
    let response = capture(&format!(
        "curl -k -A \"{USERAGENT}\" --connect-timeout 10 --silent --location \"{url}\""
    ));
    let http_code = capture(&format!(
        "curl -k -A \"{USERAGENT}\" --connect-timeout 10 --location --write-out \"%{{http_code}}\" --silent --output /dev/null \"{url}\""
    ));
    let title = capture(&format!(
        "echo {} | grep -oP '<title>\\K(.*?)(?=<)'",
        sq(&response)
    ));
    let bytes = response.len();
    let line = format!("[INFO] {url} [{http_code}] [{bytes}] [{PURPLE}{title}{RESET}]");
    println!("{line}");
    let _ = append_file("output/http_info.txt", &format!("{line}\n"));
}

fn sq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn append_file(path: &str, content: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.write_all(content.as_bytes())
}
