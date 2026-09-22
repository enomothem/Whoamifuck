//! HTML 应急响应报告，对应 `fk_reporthtml`（-m）。
//!
//! 说明：原 who.sh 的 HTML 报告是一个约 1400 行、内嵌大量 CSS/JS 的模板。此处
//! 为**功能性移植**：采集与原版相同类别的信息，并渲染为一份带折叠区块与搜索框
//! 的自包含 HTML 报告，而非逐字节复刻原模板。

use crate::color::strip_ansi;
use crate::env::Env;
use crate::sys::{capture, command_exists, OsType};
use crate::ui::bar;
use crate::version::{version_ge, version_lt};
use std::fs;

pub fn run(env: &Env, report_name: Option<&str>) {
    println!("{}", bar("生成应急报告"));
    let _ = fs::create_dir_all(&env.output_m);

    let current_time = capture("date \"+%Y%m%d%H%M%S\"");
    let event_date = capture("date \"+%Y年%m月%d日 %H:%M:%S\"");
    let html_name = match report_name {
        Some(n) if !n.is_empty() => n.to_string(),
        _ => format!("report-{current_time}.html"),
    };

    let os = crate::sys::os_name();

    progress(1, "正在初始化...");

    // 端口 / 进程 / 服务
    let (network_info, portsvt_info) = if command_exists("netstat") && command_exists("lsof") {
        (
            capture("netstat -anltu"),
            capture("netstat -tunlp | awk '/^tcp/ {print $4,$7}; /^udp/ {print $4,$6}' | sed -r 's/.*:(.*)\\/.*/\\1/' | sort -un"),
        )
    } else {
        (capture("ss -anltu"), capture("ss -antup"))
    };
    let lsof_info = if command_exists("lsof") {
        capture("lsof -i -L 2>/dev/null")
    } else {
        "无lsof命令。".to_string()
    };
    let process_info = capture("ps aux");
    let service_info =
        capture("systemctl | grep -E \"\\.service.*running\" | awk -F. '{print $1}'");
    progress(2, "端口、进程、服务采集完成");

    // 用户与组
    let user_info = capture("cat /etc/passwd");
    let pass_info = capture("cat /etc/shadow");
    let grop_info = capture("cat /etc/group");
    progress(3, "用户与组信息采集完成");

    // 历史命令
    let histcurrent_info = capture("cat ~/.*sh_history 2>/dev/null");
    progress(4, "历史命令采集完成");

    // 计划任务
    let crontab1 = capture("crontab -l 2>/dev/null");
    let crontab_etc = capture("cat /etc/crontab 2>/dev/null");
    let crontab_crond = capture("cat /etc/cron.*/* 2>/dev/null");
    progress(5, "计划任务采集完成");

    // 启动项
    let initpid_info = capture("systemctl list-unit-files --type=service 2>/dev/null");
    let initd_info = capture("cat /etc/init.d/* 2>/dev/null");
    progress(6, "启动项采集完成");

    // 登录日志
    let self_exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "who".to_string());
    let userlogin = strip_ansi(&capture(&format!("'{self_exe}' -l")));
    let (userlog_info, userlog_file) = match os.os_type {
        OsType::Debian => (
            capture(&format!(
                "cat {} 2>/dev/null | tail -2000",
                env.authlog_file
            )),
            env.authlog_file.clone(),
        ),
        OsType::RedHat => (
            capture(&format!("cat {} 2>/dev/null | tail -2000", env.secure_file)),
            env.secure_file.clone(),
        ),
    };
    progress(7, "登录日志采集完成");

    // 文件信息
    let m_file = capture("find -type f -mtime -3");
    let c_file = capture("find -type f -ctime -3");
    let m_file_var = capture("find /var/ -type f -mtime -3 | xargs ls -la 2>/dev/null");
    progress(8, "文件信息采集完成");

    // 环境变量
    let env_alias_info = capture("cat ~/.bashrc 2>/dev/null | grep alias");
    let env_profile = capture("cat /root/.bashrc /etc/bashrc /root/.bash_profile 2>/dev/null");
    progress(9, "环境变量采集完成");

    // 风险
    let mut kill_process = capture("ps -al | awk '{print $2,$4}' | grep -e '^[Zz]'");
    if kill_process.is_empty() {
        kill_process = "无".to_string();
    }
    let mut redis_risk = capture(
        "find / -name \"redis.conf\" -exec grep --color=none -H \"# requirepass \" {} \\; 2>/dev/null",
    );
    if redis_risk.is_empty() {
        redis_risk = "无".to_string();
    }
    let copy_fail_html = copy_fail_status();
    let dirty_pipe_html = dirty_pipe_status();
    progress(10, "漏洞检测完成");

    // SSH 后门
    let ssh_info = capture(
        "netstat -ntpl 2>/dev/null | awk '{if (NR>2){print $7}}' | sed 's|/.*||' | while read -r pid; do [ -e \"/proc/$pid/exe\" ] && ls -al /proc/$pid/ | grep 'exe'; done",
    );
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let sshkey = format!("{home}/.ssh/authorized_keys");
    let sshpubkey = if std::path::Path::new(&sshkey).is_file() {
        let perm = capture(&format!("stat -c %a {sshkey}"));
        let modi = capture(&format!("stat -c %y {sshkey}"));
        format!("{modi}({perm})")
    } else {
        "未找到该文件".to_string()
    };
    progress(11, "SSH后门检测完成");

    // 组装 HTML
    let mut body = String::new();
    add_section(
        &mut body,
        "系统基本信息",
        &format!(
            "操作系统: {}\n内核: {}\n主机名: {}\n报告时间: {event_date}\n当前用户: {}",
            os.name,
            capture("uname -a"),
            capture("hostname"),
            env.whoamifuck,
        ),
    );
    add_section(&mut body, "端口 - 网络连接", &network_info);
    add_section(&mut body, "端口 - 服务映射", &portsvt_info);
    add_section(&mut body, "网络 - lsof", &lsof_info);
    add_section(&mut body, "进程信息 (ps aux)", &process_info);
    add_section(&mut body, "运行中的服务", &service_info);
    add_section(&mut body, "用户 (/etc/passwd)", &user_info);
    add_section(&mut body, "影子 (/etc/shadow)", &pass_info);
    add_section(&mut body, "用户组 (/etc/group)", &grop_info);
    add_section(&mut body, "历史命令 (当前用户)", &histcurrent_info);
    add_section(&mut body, "计划任务 (crontab -l)", &crontab1);
    add_section(&mut body, "计划任务 (/etc/crontab)", &crontab_etc);
    add_section(&mut body, "计划任务 (/etc/cron.*)", &crontab_crond);
    add_section(&mut body, "启动项 (service units)", &initpid_info);
    add_section(&mut body, "启动项 (/etc/init.d)", &initd_info);
    add_section(&mut body, "用户登录分析", &userlogin);
    add_section(
        &mut body,
        &format!("登录日志 ({userlog_file})"),
        &userlog_info,
    );
    add_section(&mut body, "最近3天修改的文件", &m_file);
    add_section(&mut body, "最近3天创建的文件", &c_file);
    add_section(&mut body, "/var 最近3天修改", &m_file_var);
    add_section(&mut body, "环境变量 - alias", &env_alias_info);
    add_section(&mut body, "环境变量 - profile", &env_profile);
    add_section(&mut body, "风险 - 僵尸进程", &kill_process);
    add_section(&mut body, "风险 - Redis 未授权", &redis_risk);
    add_section(
        &mut body,
        "风险 - CVE-2016-5195 Dirty Cow",
        &dirty_cow_status(),
    );
    add_section(
        &mut body,
        "风险 - CVE-2022-0847 Dirty Pipe",
        &dirty_pipe_html,
    );
    add_section(
        &mut body,
        "风险 - CVE-2026-31431 Copy Fail",
        &copy_fail_html,
    );
    add_section(&mut body, "后门 - SSH 进程", &ssh_info);
    add_section(&mut body, "后门 - SSH 公钥", &sshpubkey);

    let html = build_document(&event_date, &body);
    let out_path = format!("{}/{}", env.output_m, html_name);
    let courier_path = format!("{}/{}", env.output_m, env.courier);
    let _ = fs::write(&out_path, &html);
    let _ = fs::write(&courier_path, &html);
    progress(12, "报告生成完成");
    println!();
    println!("{} HTML报告已生成：{out_path}", crate::ui::Stats::suc());
}

fn progress(step: u32, desc: &str) {
    let total = 12u32;
    let width = 40u32;
    let pct = step * 100 / total;
    let filled = pct * width / 100;
    let bar: String = std::iter::repeat('#')
        .take(filled as usize)
        .chain(std::iter::repeat('.').take((width - filled) as usize))
        .collect();
    print!("\r\x1b[K[{}] {pct:3}%  {desc}", bar);
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn add_section(body: &mut String, title: &str, content: &str) {
    body.push_str(&format!(
        "        <div class=\"section\">\n            <h2 class=\"section-title\" onclick=\"toggle(this)\">{}</h2>\n            <div class=\"section-content\"><pre class=\"code-block\">{}</pre></div>\n        </div>\n",
        html_escape(title),
        html_escape(content)
    ));
}

fn build_document(event_date: &str, body: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>应急响应报告</title>
    <style>
        body {{ font-family: Arial, "Microsoft YaHei", sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; color: #333; }}
        .container {{ max-width: 960px; margin: 20px auto; padding: 20px; background-color: #fff; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ text-align: center; color: #b22222; }}
        .meta {{ text-align: center; color: #666; font-size: 13px; margin-bottom: 20px; }}
        .section {{ margin-bottom: 16px; }}
        .section-title {{ color: #000; border-bottom: 1px solid #ccc; padding-bottom: 8px; cursor: pointer; }}
        .section-title:hover {{ color: #b22222; }}
        .section-content {{ padding-left: 10px; }}
        .code-block {{ background-color: #f4f4f4; border: 1px solid #ddd; border-left: 3px solid #4CAF50; padding: 10px; margin: 10px 0; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }}
        #searchBox {{ width: 100%; padding: 8px; margin-bottom: 16px; box-sizing: border-box; }}
        .copyright {{ color: #666; font-size: 12px; text-align: center; margin-top: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>司稽 · 应急响应报告</h1>
        <div class="meta">Whoamifuck (Rust) · 生成时间：{event_date}</div>
        <input type="text" id="searchBox" placeholder="输入关键字，回车高亮/过滤区块..." onkeyup="filterSections()">
{body}
        <div class="copyright">Generated by Whoamifuck (Rust refactor) · Eonian Sharp - Enomothem</div>
    </div>
    <script>
        function toggle(el) {{
            var c = el.nextElementSibling;
            c.style.display = (c.style.display === 'none') ? 'block' : 'none';
        }}
        function filterSections() {{
            var q = document.getElementById('searchBox').value.toLowerCase();
            document.querySelectorAll('.section').forEach(function(s) {{
                var t = s.innerText.toLowerCase();
                s.style.display = (q === '' || t.indexOf(q) !== -1) ? '' : 'none';
            }});
        }}
    </script>
</body>
</html>
"#
    )
}

fn dirty_cow_status() -> String {
    let kernel = capture("uname -r");
    let vulnerable = crate::modules::kernel_cve_data::VULNERABLE_KERNELS
        .iter()
        .any(|k| kernel.contains(k));
    if vulnerable {
        format!("内核 {kernel} 存在该漏洞，建议更新内核")
    } else {
        format!("内核 {kernel} 不受该漏洞影响")
    }
}

fn dirty_pipe_status() -> String {
    let kernel = capture("uname -r");
    let affected = version_lt("5.8", &kernel)
        && (version_lt(&kernel, "5.16.11")
            || version_lt(&kernel, "5.15.25")
            || version_lt(&kernel, "5.10.102"));
    if affected {
        format!("内核 {kernel} 存在该漏洞")
    } else {
        format!("内核 {kernel} 不在受影响范围内")
    }
}

fn copy_fail_status() -> String {
    let kernel = capture("uname -r");
    let module = if capture("lsmod 2>/dev/null | grep -q 'algif_aead' && echo y").contains('y') {
        "已加载"
    } else {
        "未加载"
    };
    let patched = version_ge(&kernel, "7.0")
        || version_ge(&kernel, "6.19.12")
        || (version_ge(&kernel, "6.18.22") && version_lt(&kernel, "6.19"));
    let affected = version_ge(&kernel, "4.12") && !patched;
    if affected {
        format!("内核 {kernel} 受漏洞影响 | 模块: {module}")
    } else {
        format!("内核 {kernel} 不受漏洞影响")
    }
}
