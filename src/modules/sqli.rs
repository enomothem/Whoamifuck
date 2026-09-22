//! 日志分析 - SQL 注入专项，对应 `fk_weblog_sqlianalysis` / `fk_sqlianalysis`（-i）。

use crate::sys::run_inherit;
use crate::ui::bar;
use std::path::Path;

pub fn run(access_path: Option<&str>) {
    println!("{}", bar("日志分析-SQLi"));

    match access_path {
        None | Some("") => {
            let apache = "/var/log/apache*/access.log";
            let nginx = "/var/log/nginx/access.log";
            println!();
            println!("[+] check /var/log/apache*/access.log");
            println!();
            if Path::new(apache).is_file() {
                analyze(apache);
            } else {
                println!("未找到该文件");
            }
            println!();
            println!("[+] check /var/log/nginx/access.log");
            println!();
            if Path::new(nginx).is_file() {
                analyze(nginx);
            } else {
                println!("未找到该文件");
            }
        }
        Some(path) => {
            println!();
            println!("[+] check {path}");
            println!();
            if Path::new(path).is_file() {
                analyze(path);
            } else {
                println!("未找到该文件");
            }
        }
    }
}

/// 对应 `fk_sqlianalysis`：三类盲注检测（>、!=、时间延时）。
fn analyze(file: &str) {
    println!("[+] sql注入盲注'>'判断类");
    run_inherit(&format!(
        r#"sed -n -E 's/.*,([0-9]+),1\)\)>([0-9]+).*HTTP\/1.1" (404|200).*/\1 \2 \3/p' {file} | awk '($3 == 404 && ($1 not in max || $2 > max[$1])) || ($3 == 200 && ($1 not in min || $2 < min[$1])) {{max[$1] = ($3 == 404 ? $2 : max[$1]); min[$1] = ($3 == 200 ? $2 : min[$1]);}} END {{for (i in max) if ((i in max) && (i in min) && (max[i] - min[i] == 1)) print max[i]}}' | while read -r line;do printf "\x$(printf '%x' "$line")"; done"#
    ));
    println!();
    println!("[+] sql注入盲注'!='判断类");
    run_inherit(&format!(
        r#"sed -n -E 's/.*,([0-9]+),1\)\)!=([0-9]+).*HTTP\/1.1" (404|200).*/\2/p' {file} | while read -r line;do printf "\x$(printf '%x' "$line")"; done"#
    ));
    println!();
    println!("[+] sql注入盲注time延时类");
    run_inherit(&format!(
        r#"delay=$(sed -n -E "s/.*sleep\(([0-9]+)\).*HTTP\/1.1\" 200.*/\1/p" {file}) ; sed -n -E "s/.*([0-9][0-9])\/([A-Z][a-z]+)\/([12]0[0-9]+):([0-9]+:[0-9]+:[0-9]+).*\)=[a-z0-9A-Z]+\('(.?)'\).*sleep\(([0-9]+)\).*HTTP\/1.1\" 200.*/\3-\2-\1 \4 \5 \6/p" {file} | awk 'BEGIN{{m=split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec",a," ")}} {{for(i=1;i<=m;i++) {{if(index($0,a[i])) {{gsub(a[i],i,$0)}}}}}} {{print}}' | awk '{{split($2, a, ":"); t=mktime($1 " " a[1] " " a[2] " " a[3]); diff=t-prev; if (diff<$delay) print prev_line; prev_line=$3; prev=t}}' | awk '{{printf "%s", $0}}'"#
    ));
    println!();
    println!();
}
