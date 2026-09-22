//! 终端代理开关，对应 `fk_terminal_proxy`（-t）。

use crate::color::*;
use crate::sys::run_inherit;
use std::process;

pub fn run(input: Option<&str>) {
    let stat = input.unwrap_or("");
    if stat.is_empty() {
        println!("Usage: who on|off");
        println!();
        process::exit(1);
    }

    match stat {
        "on" => {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
            let clash = format!("{home}/.clash");
            let _ = std::fs::write(
                &clash,
                "export https_proxy=http://127.0.0.1:7897\nexport http_proxy=http://127.0.0.1:7897\nexport all_proxy=socks5://127.0.0.1:7897\n",
            );
            println!("{GREEN}Proxy enabled{RESET}");
            run_inherit("source ~/.clash; curl cip.cc");
            run_inherit("ping google.com -c 3");
        }
        "off" => {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
            let clash = format!("{home}/.clash");
            println!("{REDX}Proxy disabled{RESET}");
            run_inherit("unset https_proxy; unset http_proxy; unset all_proxy; curl cip.cc");
            let _ = std::fs::write(&clash, "");
        }
        _ => {
            println!("Invalid option. Usage: who on|off");
            process::exit(1);
        }
    }
}
