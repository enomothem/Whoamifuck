//! 基线安全评估，对应 `fk_baseline`（-b）。

use crate::color::*;
use crate::sys::{run_inherit, OsType};
use crate::ui::bar;

pub fn run() {
    let os = crate::sys::os_name();
    let pam_file = match os.os_type {
        OsType::Debian => "/etc/pam.d/common-auth",
        OsType::RedHat => "/etc/pam.d/system-auth",
    };

    println!();
    println!("{}", bar("基线安全评估"));
    println!();

    let section = |num: &str, title: &str, expected: &str, cmd: &str, suggestion: &str| {
        println!();
        println!("{BLUE}{num} {title}{RESET}\n");
        println!("预期结果：");
        println!("{expected}");
        println!("{RED}{cmd}{RESET}");
        run_inherit(cmd);
        println!();
        println!("整改建议：");
        println!("{suggestion}");
        println!();
    };

    println!("{PURPLE}{BOLD}1. 身份鉴别{RESET}\n");

    section(
        "1.1",
        "应对登录操作系统和数据库系统的用户进行身份标识和鉴别",
        "     1)操作系统使用口令鉴别机制对用户进行身份标识和鉴别；\n     2)登录时提示输入用户名和口令；以错误口令或空口令登录时提示登录失败，验证了登录控制功能的有效性；\n     3)操作系统不存在密码为空的用户。",
        "cat /etc/passwd | tail ; cat /etc/shadow | tail",
        "操作系统和数据库每个用户都必须设置登录用户名和登录密码，不能存在空密码。",
    );

    section(
        "1.2",
        "操作系统和数据库系统管理用户身份标识应具有不易被冒用的特点，口令应有复杂度要求并定期更换",
        "     密码策略如下：\n     PASS_MAX_DAYS   90（生命期最大为90天）\n     PASS_MIN_DAYS   0（密码最短周期0天）\n     PASS_MIN_LEN   10（密码最小长度10位）\n     PASS_WARN_AGE 7（密码到期前7天提醒）\n\n        口令复杂度：\n        口令长度8位以上，并包含数字、字母、特殊字符三种形式",
        "more /etc/login.defs | grep 'PASS'",
        "     密码最大生存周期为90天\n     密码最短修改周期为0天，可以随时修改密码\n     密码最小长度为10位，包含数字，特殊字符，字母（大小写）三种形式\n     密码到期前7天必须提醒",
    );

    section(
        "1.3",
        "应启用登录失败处理功能，可采取结束会话、限制非法登录次数和自动退出等措施",
        "     1)操作系统已启用登陆失败处理、结束会话、限制非法登录次数等措施；\n    2)当超过系统规定的非法登陆次数或时间登录操作系统时，系统锁定或自动断开连接",
        &format!("cat {pam_file} | grep '^auth' ;  cat /etc/shadow | tail"),
        "建议限制，密码过期后重设的密码不能和前三次的密码相同。",
    );

    section(
        "1.4",
        "当对服务器进行远程管理时，应采取必要措施，防止鉴别信息在网络传输过程中被窃听",
        "     1)操作系统使用SSH协议进行远程连接；\n     2)若未使用SSH方式进行远程管理，则查看是否使用telnet方式进行远程管理；",
        "systemctl is-active 'ssh*' ;  systemctl is-active 'telnet*'",
        "系统远程登录时要采取SSH方式登录或采用密文传输信息，保障信息的安全性。",
    );

    section(
        "1.5",
        "为操作系统和数据库的不同用户分配不同的用户名，确保用户名具有唯一性",
        "用户的标识唯一，若系统允许用户名相同，UID不同，则UID是唯一性标识；若系统允许UID相同，则用户名是唯一性标识。",
        "awk -F: '{print $1, $3}' /etc/passwd | sort -k2 | column -t ;  systemctl is-active telnet*",
        "UID是唯一性标识，每个用户必须采用不同的UID来区分。",
    );

    println!("{PURPLE}{BOLD}2. 访问控制{RESET}\n");

    section(
        "2.1",
        "应启用访问控制功能，依据安全策略控制用户对资源的访问",
        "root用户：\n        passwd文件夹只有rw-r-r权限\n        shadow文件夹只有r- - -权限\n\n        r=4 w=2 x=1",
        "ls -l /etc/passwd ;  ls -l /etc/shadow",
        "根据实际需求，对每个用户的访问权限进行限制，对敏感的文件夹限制访问用户的权限。",
    );

    section(
        "2.2",
        "应根据管理用户的角色分配权限，实现管理用户的权限分离，仅授予管理用户所需的最小权限",
        "询问管理员，了解每个用户的作用、权限",
        "awk -F: '$3==0 {print $1}' /etc/passwd",
        "给予账户所需最小权限，避免出现特权用户。",
    );

    section(
        "2.3",
        "应实现操作系统和数据库系统特权用户的权限分离",
        "操作系统和数据库的特权用户的权限必须分离，避免一些特权用户拥有过大的权限，减少人为误操作",
        "awk -F: '$3==0 {print $1}' /etc/passwd",
        "分离数据库和操作系统的特权用户，不能使一个用户权限过大。",
    );
    println!("{CYAN}ps:具体情况还是得询问管理员是否存在数据库用户权限分离。{RESET}");

    section(
        "2.4",
        "应严格限制默认帐户的访问权限，重命名系统默认帐户，修改这些帐户的默认口令",
        "默认账户已更名，或已被禁用",
        "cat /etc/passwd | head",
        "严格限制默认账户的访问权限，对存在的默认账户的用户名和口令进行修改。使用[usermod -l <新账户名> root]来修改用户名，使用 [ usermod -L 用户名]，来锁定默认用户。",
    );
    println!(
        "{CYAN}ps: 更改root名称可能导致telnet无法使用，是否配置按具体情况，具体等级分析。{RESET}"
    );

    section(
        "2.5",
        "应及时删除多余的、过期的帐户，避免共享帐户的存在",
        "不存在多余、过期和共享账户",
        "cat /etc/passwd | awk -F: '{print $1}' | paste -sd,",
        "整改建议：删除、禁用例如uucp，ftp等多余账户。",
    );

    println!("{PURPLE}{BOLD}3. 安全审计{RESET}\n");

    section(
        "3.1",
        "审计范围应覆盖到服务器和重要客户端上的每个操作系统用户和数据库用户",
        "系统开启了安全审计功能或部署了第三方安全审计设备",
        "systemctl is-active auditd",
        "开启系统本身的安全审计功能，完整记录用户对操作系统和文件访问情况，或采用第三方的安全审计设备。",
    );

    section(
        "3.2",
        "审计内容应包括重要用户行为、系统资源的异常使用和重要系统命令的使用等系统内重要的安全相关事件",
        "审计功能已开启，包括：用户的添加和删除、审计功能的启动和关闭、审计策略的调整、权限变更、系统资源的异常使用、重要的系统操作（如用户登录、退出）等设置",
        "ps -ef | grep auditd",
        "开启审计功能，记录用户的添加和删除、审计功能的启动和关闭、审计策略的调整、权限变更、系统资源的异常使用、重要的系统操作（如用户登录、退出）等操作。",
    );

    section(
        "3.3",
        "审计记录应包括事件的日期、时间、类型、主体标识、客体标识和结果等",
        "审计记录包括事件的日期、时间、类型、主体标识、客体标识和结果等内容",
        "ps -ef | grep auditd",
        "记录事件产生的时间，日期，类型，主客体标识等",
    );
    println!("{CYAN}ps:具体查看cat /etc/audit/auditd.conf | cat /etc/audit/audit.rules。{RESET}");

    section(
        "3.4",
        "操作系统应遵循最小安装的原则，仅安装需要的组件和应用程序，并通过设置升级服务器等方式保持系统补丁及时得到更新",
        "     1)系统安装的组件和应用程序遵循了最小安装的原则；\n     2)不必要的服务没有启动；\n     3)不必要的端口没有打开；",
        "ss -tulpn ; service --status-all | grep running ",
        "在不影响系统的正常使用的前提下，对系统的一些端口和服务可以进行关闭，避免这些端口或服务的问题导致系统问题。",
    );

    println!("{PURPLE}{BOLD}4. 资源控制{RESET}\n");

    section(
        "4.1",
        "应通过设定终端接入方式、网络地址范围等条件限制终端登录",
        "已设定终端登录安全策略及措施，非授权终端无法登录管理。",
        "cat /etc/hosts.deny; cat /etc/hosts.allow",
        "建议配置固定的终端、特定的网络范围内才能进行终端登录。",
    );

    section(
        "4.2",
        "应根据安全策略设置登录终端的操作超时锁定",
        "已在/etc/profile中为TMOUT设置了合理的操作超时时间。",
        "cat /etc/profile | grep 'TMOUT'",
        "超时时间建议设置为300秒。",
    );
}
