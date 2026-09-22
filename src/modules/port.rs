//! 端口开放状态与 HTTP 服务探测，对应 `fk_portstatus` 与 `port_http`（-p）。

use crate::color::*;
use crate::sys::{capture, command_exists};
use crate::ui::bar;
use std::fs;

const USERAGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36";
const NON_HTTP_PORTS: &[&str] = &[
    "3306", "22", "25", "139", "143", "465", "587", "993", "995", "3389", "445",
];

pub fn run() {
    let port = if command_exists("netstat") && command_exists("lsof") {
        capture(
            "netstat -tunlp | awk '/^tcp/ {print $4,$7}; /^udp/ {print $4,$6}' | sed -r 's/.*:(.*)\\/.*/\\1/' | sort -un | awk '{cmd = \"sudo lsof -w -i :\" $1 \" | awk '\\''NR==2{print $1}'\\''\"; cmd | getline serviceName; close(cmd); print $1 \"\\t\" serviceName}'",
        )
    } else {
        capture("ss -tulpn")
    };

    println!();
    println!("{}", bar("显示开启端口"));
    println!();
    println!("{RED}>端口服务信息{RESET}");
    println!("{port}");
    println!();
    println!("{RED}>探测HTTP服务端口{RESET}");
    port_http();
}

/// 遍历本机监听端口，使用 curl 探测其是否为 HTTP 服务，对应 `port_http`。
fn port_http() {
    let open_ports = capture(
        "ss -tuln | awk '/LISTEN/ {print $1, $5}' | grep tcp | awk -F: '{print $NF}' | sort -u",
    );
    let _ = fs::create_dir_all("output");

    for port in open_ports.split_whitespace() {
        if NON_HTTP_PORTS.contains(&port) {
            continue;
        }
        let url = format!("http://localhost:{port}");
        let response = capture(&format!(
            "curl -k -A \"{USERAGENT}\" --connect-timeout 5 --max-time 10 --silent --location --write-out \"HTTPSTATUS:%{{http_code}}\" --max-redirs 10 \"{url}\" 2>/dev/null"
        ));
        let http_code = response
            .replace('\n', "")
            .rsplit("HTTPSTATUS:")
            .next()
            .unwrap_or("000")
            .to_string();
        let response_body = if let Some(idx) = response.find("HTTPSTATUS:") {
            response[..idx].to_string()
        } else {
            response.clone()
        };

        if http_code == "000" || http_code.is_empty() {
            continue;
        }
        if http_code == "302" {
            let redirect_url = capture(&format!(
                "echo {} | grep -oP '(?<=Location: ).*' | head -n 1",
                shell_quote(&response_body)
            ));
            println!("Redirected to: {redirect_url}");
        }

        let title = capture(&format!(
            "echo {} | grep -oP '(?<=<title>).*?(?=</title>)'",
            shell_quote(&response_body)
        ));
        let bytes = response_body.len();
        let line = format!("[INFO] {url} [{http_code}] [{bytes}] [{PURPLE}{title}{RESET}]");
        println!("{line}");
        let _ = append_file("output/http_info.txt", &format!("{line}\n"));
    }
}

fn shell_quote(s: &str) -> String {
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
