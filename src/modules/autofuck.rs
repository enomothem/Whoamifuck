//! 溯源思路彩蛋，对应 `fk_autofuck`（-y）。

use crate::ui::bar;

pub fn run() {
    println!("{}", bar("Whoamifuck"));
    println!("溯源思路：");
    println!("三位一体、三面一线、三点一记");
    println!("端口->服务、服务->进程、进程->网络 | 时间线 = 轨迹 = 日志 = {{history、logs、crontab、filemodifytime.....}}");
    println!("溯源盲区：");
    println!("不可见字符文件如.. . | 删除绕过文件 如 --help ");
    println!("多实践，多积累，经验很重要，感觉也很重要。");
}
