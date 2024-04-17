#!/bin/bash
# Linux入侵检测报告工具-Whoamifuck
# Author: Enomothem
# Time: 2021年2月8日

# --------------------------------------
#        | Update log |             
# --------------------------------------

# update: 2021年6月3日 优化格式，加入用户基本信息
# update: 2021年6月6日 发布3.0版本
# update: 2022年6月3日 增加新功能，加入应急响应基础功能，如查看用户、服务、文件修改、历史命令等等。
# update: 2022年6月6日 发布4.0版本
# update: 2023年6月3日 增加新功能，加入开放端口、优化服务器状态、查看僵尸进程、优化用户状态等。
# update: 2023年6月6日 发布5.0版本
# update: 2023年8月14日 发布5.0.1版本，新增 『导出功能』 、优化 『用户登录日志』 、修复 『显示端口不存在用户导致错误』 
#                       |__ 增加 『全量输出』 、优化 『标题栏』 代码  
# update: 2023年8月16日 发布5.0.2版本，优化 『用户基本信息』 、修复  『某些环境DNS显示异常』 、 加速  『模块化』
#                       |__ 增加 『secure文件可选』 、增加  『颜色定义区』
# update: 2023年9月5日 发布5.1.0，优化用户登录日志代码逻辑。进一步完善debian正则。
#                       |__ 增加 『auth.log文件可选』 、增加  『虚拟机判断』
# update: 2023年9月15日 发布5.1.19，优化 『虚拟机判断的兼容能力』@Gu0st
# update: 2023年9月15日 发布5.2.0，优化 修复对虚拟判断的bug
# update: 2023年10月12日 发布5.2.1，增加对root用户的判断，修复一些小bug
# update: 2023年12月5日 发布5.3.0，修复 『导出bug』、新增 『webshell查杀』、新增 『漏洞检查』   100Star啦 ^.^
# update: 2023年12月7日 发布5.3.1，修复 『多网卡bug』、修复 『没有gawk命令显示异常』@Agreement
# update: 2023年12月8日 发布5.3.2，新增 『webshell jsp免杀规则』、优化 『代码缩进』、新增 『Redis漏洞检测』、优化 『程序执行速度』
# update: 2023年12月13日 发布5.4.0，新增 『基线检查』、优化 『help』、修复 『bar显示问题』、优化 『输出结果更加合理』、修复『sudoer文件不存在显示问题』@lockly


# --------------------------------------
#        | Root Check |             
# --------------------------------------



# [ ++ Function COLOR ++ ]
function color
{   
    # 定义颜色和样式变量
    reset="\033[0m"
    bold="\033[1m"
    underline="\033[4m"
    inverse="\033[7m"

    # 定义前景色变量
    redx="\e[1;31m"
    black="\033[30m"
    red="\033[1;31m"
    green="\033[32m"
    yellow="\033[33m"
    blue="\033[1;34m"
    purple="\033[35m"
    cyan="\033[36m"
    white="\033[1;37m"

    # 定义背景色变量
    bg_black="\033[40m"
    bg_red="\033[41m"
    bg_green="\033[42m"
    bg_yellow="\033[43m"
    bg_blue="\033[44m"
    bg_purple="\033[45m"
    bg_cyan="\033[46m"
    bg_white="\033[47m"
}

if [ "$EUID" -ne 0 ]; then
    printf "${redx}[-] This script must be run as root${reset}\n"
    exit 1
fi

# [ ++ 基本信息 ++ ]
VER="2023.12.14@whoamifuck-version 5.4.0"
WHOAMIFUCK=`whoami`

# --------------------------------------
#        | Function |             
# --------------------------------------


# [ ++ Function LOGO ++ ]
function logo
{
    color
    echo
    echo
    printf "${red} ██╗    ██╗██╗  ██╗ ██████╗  █████╗ ███╗   ███╗██╗    ███████╗██╗   ██╗ ██████╗██╗  ██╗ ${reset}\n"
    printf "${red} ██║    ██║██║  ██║██╔═══██╗██╔══██╗████╗ ████║██║    ██╔════╝██║   ██║██╔════╝██║ ██╔╝ ${reset}\n"
    printf "${red} ██║ █╗ ██║███████║██║   ██║███████║██╔████╔██║██║    █████╗  ██║   ██║██║     █████╔╝  ${reset}\n"
    printf "${red} ██║███╗██║██╔══██║██║   ██║██╔══██║██║╚██╔╝██║██║    ██╔══╝  ██║   ██║██║     ██╔═██╗  ${reset}\n"
    printf "${red} ╚███╔███╔╝██║  ██║╚██████╔╝██║  ██║██║ ╚═╝ ██║██║    ██║     ╚██████╔╝╚██████╗██║  ██╗ ${reset}\n"
    printf "${red}  ╚══╝╚══╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝    ╚═╝      ╚═════╝  ╚═════╝╚═╝  ╚═╝ ${reset}\n"
    printf "                             ${VER}           by ${blue}Enomothem${reset}\n"

}

# [ ++ Function HELP_CN ++ ]
function help_cn
{    
        printf "usage:  \n\n"
        printf "\t -v --version\t\t\t版本信息\n "
        printf "\t -h --help\t\t\t帮助指南\n"
        printf "\t -l --login [FILEPATH]\t\t用户登录信息\n"
        printf "\t -n --nomal\t\t\t基本输出模式\n"
        printf "\t -a --all\t\t\t全量输出模式\n"
        printf "\t -u --user-device\t\t查看设备基本信息\n"
        printf "\t -x --process-and-servic\t检查用户进程与开启服务状态\n"
        printf "\t -p --port\t\t\t查看端口开放状态\n"
        printf "\t -s --os-status\t\t\t查看系统状态信息\n"
        printf "\t -w --webshell [PATH]\t\t查找可能存在的webshell文件\n"
        printf "\t -r --risk\t\t\t查看系统可能存在的漏洞\n"
        printf "\t -b --baseline\t\t\t基线安全评估\n"
        printf "\t -o --output [FILENAME]\t\t导出全量输出模式文件\n"

}

function help_en
{
        logo
        printf "usage:  \n\n"
        printf "\t -v --version\t\t\tShow version.\n "
        printf "\t -h --help\t\t\tShow help guide.\n"
        printf "\t -l --login [FILEPATH]\t\tShow user login log.\n"
        printf "\t -n --nomal\t\t\tNomal print.\n"
        printf "\t -a --all\t\t\tAll print.\n"
        printf "\t -x --process-and-service\tCheck service and process information.\n"
        printf "\t -u --user-device\t\tCheck device information.\n"
        printf "\t -p --port\t\t\tShow port information.\n"
        printf "\t -s --os-status\t\t\tShow os status information.\n"
        printf "\t -w --webshell [PATH]\t\tFind the webshell file.\n"
        printf "\t -r --risk\t\t\tCheck os vulneribility.\n"
        printf "\t -b --baseline\t\t\tBaseline security assessment\n"
        printf "\t -o --output [FILENAME]\t\tOutput to file.\n"
        
}


# --------------------------------------
#        | File variables |             
# --------------------------------------


AUTHLOG_FILE="/var/log/auth.log" # 默认访问的用户日志路径
SECURE_FILE="/var/log/secure" 	 # Centos默认用户日志

# --------------------------------------
#        | Uers Functions |             
# --------------------------------------


# 维护中

function user
{
    
    if [ -e $AUTHLOG_FILE ]
    then            
            echo
            T='11'
            LOG=/tmp/valid.$$.log
            grep -v "invalid" $AUTHLOG_FILE > $LOG
            users=$(grep "Failed password" $LOG | awk '{ print $(NF-5) }' | sort | uniq)
            printf "\e[4;34m%-5s|%-10s|%-15s|%-19s|%-33s|%s\n\e[0m" "Sr#" "登入用户名" "尝试次数" "IP地址" "虚拟主机映射" "时间范围"
            ucount=0;
            ip_list="$(egrep -o "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" $LOG | sort | uniq)"
            for ip in $ip_list;
            do
                    grep $ip $LOG > /tmp/temp.$$.log
            for user in $users;
            do
                    grep $user /tmp/temp.$$.log> /tmp/$$.log
                    cut -c-16 /tmp/$$.log > $$.time
                    tstart=$(head -1 $$.time);
                    start=$(date -d "$tstart" "+%s");
                    tend=$(tail -1 $$.time);
                    end=$(date -d "$tend" "+%s")

                    limit=$(( $end - $start ))

                    if [ $limit -gt 120 ];
                    then
                            let ucount++;

                            IP=$(egrep -o "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" /tmp/$$.log | head -1 );
                            TIME_RANGE="$tstart-->$tend"

                            ATTEMPTS=$(cat /tmp/$$.log|wc -l);

                            HOST=$(host $IP | awk '{ print $NF }' )

                    printf "%-5s|%-10s|%-11s|%-17s|%-27s|%-s\n" "$ucount" "$user" "$ATTEMPTS" "$IP" "$HOST" "$TIME_RANGE";
                    fi
            done
            done

            rm -f /tmp/valid.$$.log/tmp/$$.log $$.time/tmp/temp.$$.log 2>/dev/null
            rm -f *.time
    else
            printf "\n不存在默认文件,请指定该系统文件路径。\n\n"
    fi
}

function user_debian
{
    echo -e "${bg_red}\n『 用户登录 』${reset}\n"
    cat $AUTH_S  | grep Accepted | awk '{gsub("T"," ",$1); split($1,a,"."); print "时间:"substr(a[1],1)"\t登录成功\t "$9" --> "$7 " \t使用方式: "$5}';echo
    echo -e "${bg_red}\n『 用户登出 』${reset}\n"
    cat $AUTH_S  | grep Accepted | awk '{gsub("T"," ",$1); split($1,a,"."); print "时间:"substr(a[1],1)"\t登录成功\t "$9" --> "$7 " \t使用方式: "$5}';echo
    echo -e "${bg_red}\n『 攻击次数Top20 攻击者IP --> 枚举用户名 』${reset}\n"
    cat $AUTH_S | grep "Failed password for invalid user" | awk '{print $13 " --> " $11}' | sort | uniq -c | sort -rn | awk '{print "[+] 用户名不存在 "$0}' | head -20 
    echo -e "${bg_red}\n『 攻击者IP次数TOP10 』${reset}\n"
    cat $AUTH_S | grep "Failed password for invalid user" | awk '{print $11 " --> " $13}' | sort | uniq -c | sort -rn | awk '{print $4}' | sort | uniq -c | awk '{print "[+] "$2" 攻击次数 "$1"次"}';echo 
    echo -e "${bg_red}\n『 登录成功IP地址 』${reset}\n"
    cat $AUTH_S | grep "Accepted"  | awk '{print "时间:"$1"-"$2"-"$3"\t登录成功\t "$11" --> "$9 " 使用方式: "$7}';echo 
    echo -e "${bg_red}\n『 对用户名进行密码爆破次数 』${reset}\n"
    cat $AUTH_S | grep "Failed password for" | grep -v invalid | awk '{print $11"—->"$9}'| uniq -c | sort -rn | awk '{print "[+] 攻击次数: " $1   " 详情:   "$2}' | head -20;echo
}

function user_centos
{
    echo -e "${bg_red}\n『 攻击次数Top20 攻击者IP --> 枚举用户名 』${reset}\n"
    cat $SECURE_S | grep "Failed password for invalid user" | awk '{print $13 " --> " $11}' | sort | uniq -c | sort -rn | awk '{print "[+] 用户名不存在 "$0}' | head -20 
    echo -e "${bg_red}\n『 攻击者IP次数TOP10 』${reset}\n"
    cat $SECURE_S | grep "Failed password for invalid user" | awk '{print $11 " --> " $13}' | sort | uniq -c | sort -rn | awk '{print $4}' | sort | uniq -c | awk '{print "[+] "$2" 攻击次数 "$1"次"}';echo 
    echo -e "${bg_red}\n『 登录成功IP地址 』${reset}\n"
    cat $SECURE_S | grep "Accepted"  | awk '{print "时间:"$1"-"$2"-"$3"\t登录成功\t "$11" --> "$9 " 使用方式: "$7}';echo 
    echo -e "${bg_red}\n『 对用户名进行密码爆破次数 』${reset}\n"
    cat $SECURE_S | grep "Failed password for" | grep -v invalid | awk '{print $11"—->"$9}'| uniq -c | sort -rn | awk '{print "[+] 攻击次数: " $1   " 详情:   "$2}' | head -20;echo
}

function user_centos_defi
{
    $SECURE_S=$2
    user_centos
}


# --------------------------------------
#        | Fuck module Functions |             
# --------------------------------------


# [ ++ 标题栏定义区 ++ ]
function bar
{
    color
    bar_user_logi=`printf "${red}%50s${reset}" "[ 用户登录信息 ]"`
    bar_base_info=`printf "${red}%50s${reset}" "[ 用户基本信息 ]"`
    bar_logs_hist=`printf "${red}%50s${reset}" "[ 用户历史命令 ]"`
    bar_user_info=`printf "${red}%50s${reset}" "[ 用户信息排查 ]"`
    bar_cron_task=`printf "${red}%50s${reset}" "[ 用户计划任务 ]"`
    bar_osys_stat=`printf "${red}%50s${reset}" "[ 系统状态信息 ]"`     
    bar_port_open=`printf "${red}%50s${reset}" "[ 显示开启端口 ]"`     
    bar_proc_port=`printf "${red}%50s${reset}" "[ 进程状态信息 ]"` 
    bar_proc_serv=`printf "${red}%50s${reset}" "[ 服务状态信息 ]"`           
    bar_file_move=`printf "${red}%50s${reset}" "[ 文件信息排查 ]"`    
    bar_web_shell=`printf "${red}%50s${reset}" "[ webshell查找 ]"`        
    bar_vuln_find=`printf "${red}%50s${reset}" "[ 常见漏洞评估 ]"`         
    bar_base_line=`printf "${red}%50s${reset}" "[ 基线安全评估 ]"`
    bar_auto_fuck=`printf "${red}%50s${reset}" "[ 一键溯源 ]"`
}

# [ ++ Function OS_NAME ++ ]
# * Run the appropriate script based on the distribution name
function os_name
{
    if [ -e /etc/os-release ]; then
        # Get the name of the current Linux distribution
        # 如果不存在这个文件呢？待改进 TODO
        os_name=$(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
        if [[ "$os_name" == *"Debian"* ]]; then
            OSNAME="Debian"
            OSTYPE="T_Debian"
        elif [[ "$os_name" == *"CentOS"* ]]; then
            OSNAME="CentOS"
            OSTYPE="T_RedHat"
        elif [[ "$os_name" == *"Ubuntu"* ]]; then
            OSNAME="Ubuntu"
            OSTYPE="T_Debian"
        elif [[ "$os_name" == *"Kali"* ]]; then
            OSNAME="Kali"
            OSTYPE="T_Debian"
        else
            OSNAME="Unknown distribution"
            OSTYPE="T_RedHat"   # 未知情况默认红帽系，centos的阉割版还是多的
        fi
    fi
}

# [ ++ Function User_Login pro ++ ]
function fk_userlogin
{
    bar
    printf "%s\n" "$bar_user_logi"
    if [ -f "$FILE" ]; then
        if [[ "$FILE" == *"secure"* ]]; then
            SECURE_S=$FILE
            user_centos "SECURE_S"
        else
            AUTH_S=$FILE
            user_debian "AUTH_S"
        fi
    else
        if [ -e /etc/os-release ]; then
        # Get the name of the current Linux distribution
        os_name=$(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
        # Run the appropriate script based on the distribution name
            if [[ "$os_name" == *"Debian"* ]]; then
                if [ -f $AUTHLOG_FILE ]; then
                    AUTH_S=$AUTHLOG_FILE
                    user_debian "$AUTH_S"
                else
                    echo $AUTHLOG_FILE"文件不存在"
                fi
            elif [[ "$os_name" == *"CentOS"* ]]; then
                if [ -f "$SECURE_FILE" ]; then
                    SECURE_S=$SECURE_FILE
                    user_centos "$SECURE_S" 
                else
                    echo $SECURE_FILE"文件不存在"
                fi
            elif [[ "$os_name" == *"Ubuntu"* ]]; then
                if [ -f $AUTHLOG_FILE ]; then
                    AUTH_S=$AUTHLOG_FILE
                    user_debian "$AUTH_S"
                else
                    echo $AUTHLOG_FILE"文件不存在"
                fi
            elif [[ "$os_name" == *"Kali"* ]]; then
                if [ -f $AUTHLOG_FILE ]; then
                    AUTH_S=$AUTHLOG_FILE
                    user_debian "$AUTH_S"
                else
                    echo $AUTHLOG_FILE"文件不存在"
                fi
            else
                echo "内核未知版本，默认采用RedHat系列。"
                SECURE_S=$SECURE_FILE
                user_centos "SECURE_S"
            fi
        fi
    fi
}

# [ ++ Function BASE_INFOMATION ++ ]
## 用户基本信息

function fk_baseinfo
{

    color

    ETH=`ifconfig -s | grep ^e | awk '{print $1}' | wc -l`

    if [ $ETH -eq 1 ]; then
        ETHx=`ifconfig -s | grep ^e | awk '{print $1}'`
        IP=`ifconfig $ETHx | head -2 | tail -1 | awk '{print $2}'`
        ZW=`ifconfig $ETHx | head -2 | tail -1 | awk '{print $4}'`
    elif [ $ETH -eq 2 ]; then
        ETH0=`ifconfig -s | grep ^e | awk 'NR==1{print $1}'`
        ETH1=`ifconfig -s | grep ^e | awk 'NR==2{print $1}'`
        IP1=`ifconfig $ETH0 | head -2 | tail -1 | awk '{print $2}'`
        ZW1=`ifconfig $ETH0 | head -2 | tail -1 | awk '{print $4}'`
        IP2=`ifconfig $ETH1 | head -2 | tail -1 | awk '{print $2}'`
        ZW2=`ifconfig $ETH1 | head -2 | tail -1 | awk '{print $4}'`
        IP="$IP1,$IP2"
        ZW="$ZW1,$ZW2"
    elif [ $ETH -gt 2 ]; then
        echo "The variable is greater 3"
    else
        echo "panic!"
    fi

    GW=`route -n | tail -1 | awk '{print $1}'`
    HN=`hostname`
    VM=`lscpu | grep "Hyper.*:\|Virtu\|超管理器厂商" | grep -oP "(?<=:)\s*\K.*" | paste -sd,`
    DNS=`cat "/etc/resolv.conf" 	 | grep nameserver | awk '{print $2}' | paste -sd,`
    OS=`uname --kernel-name --kernel-release`
    TUN=`uptime | sed 's/user.*$//' | awk '{print $NF}'`
    M_TIME=`date +"%Y-%m-%d %H:%M:%S %s"`

    # show
    os_name
    IP_C=`echo -e "${cyan}$IP${reset}"`
    HN_C=`echo -e "${yellow}$HN${reset}「 ${white}$WHOAMIFUCK${reset} 」"`
    OSNAME_C=`echo -e "${bg_purple}$OSNAME${reset}「 ${blue}$VM${reset} 」"`
    TUN_C=`echo -e "${white}$TUN${reset}"`
    M_TIME_C=`echo -e "${green}$M_TIME${reset}"`
    bar
    printf "%s\n" "$bar_base_info"
    echo
    printf "%-21s|\t%-25s\t\t" "本机IP地址是" "$IP_C"
    printf "%-21s|\t%s\n" "本机子网掩码是    " "$ZW"
    printf "%-21s|\t%-25s\t" "本机网关是" "$GW"
    printf "%-17s|\t%s\n" "当前在线用户      " "$TUN_C"
    printf "%-22s|\t%s\n" "本机主机名是" "$HN_C"
    printf "%-19s|\t%s\n" "本机DNS是" "$DNS"
    printf "%-20s|\t%s\n" "系统版本" "$OS"
    printf "%-20s|\t%s\n" "系统内核" "$OSNAME_C"
    echo "------------------------------------------------------------------------------------------------------"
    printf "%s%s" "此刻唯一时间戳[本地]: " "$M_TIME_C"
    echo
}

# [ ++ Function OS_STATUS_INFORMATION ++ ]
## 系统状态信息
function fk_devicestatus
{
    # 查看内存、磁盘、CPU状态
    TA=$(free -m | awk 'NR==2{printf "%.2f%%\t\t",$3*100/$2}' ;echo;)
    TB=$(df -h| awk '$NF=="/"{printf "%s\t\t",$5}')
    TC=$(top - bn1 | grep load | awk '{printf "%.2f%%\t\t\n",2$(NF2)}')
    bar
    printf "%s\n" "$bar_osys_stat"
    echo
    printf "%s%s" "Memory:" "$TA"
    printf "%s%s" "Disk:" "$TB"
    printf "%s%s" "CPU:" "$TC"
    echo
}

# [ ++ Function PROCESS_SERVICE_INFORMATION ++ ]
## 进程与服务信息
function fk_procserv
{
    bar
    printf "%s\n" "$bar_proc_port"

    printf "%s" "`ps aux`"
    echo
    printf "%s\n" "$bar_proc_serv"
    echo
    printf "%s" "`service --status-all`"
    echo
}

# [ ++ Function OPENPORT_INFORMATION ++ ]
## 开启端口列表
function fk_portstatus
{
    PORT=`netstat -tunlp | awk '/^tcp/ {print $4,$7}; /^udp/ {print $4,$6}' | sed -r 's/.*:(.*)\/.*/\1/' | sort -un | awk '{cmd = "sudo lsof -w -i :" $1 " | awk '\''NR==2{print $1}'\''"; cmd | getline serviceName; close(cmd); print $1 "\t" serviceName}'`
    bar
    echo
    printf "%s\n" "$bar_port_open"
    echo
    printf "%s\n" "$PORT"
}

# [ ++ Function HISTORY_INFORMSTION ++ ]
# 历史命令
function fk_history
{
    # 脚本无法执行history命令
    HI=`cat ~/.*sh_history | tail -10` # 查看用户的历史命令，适用通配符的方式

    bar
    echo
    printf "%s\n" "$bar_logs_hist"
    echo
    printf "%s" "$HI"
    echo
    echo
}

# [ ++ Function CRONTAB_INFORMSTION ++ ]
## 计划任务
function fk_crontab
{
    CRON=`crontab -l 2>/dev/null`
    bar
    echo
    printf "%s\n" "$bar_cron_task"            
    echo
    printf "%s" "$CRON"
    echo
}

# [ ++ Function FILEMOVE_INFORMSTION ++ ]
## 文件修改信息
function fk_filemove
{
    M_FILE=`find -type f -mtime -3`
    M_FILE_VAR=`find /var/ -type f -mtime -3 | xargs ls -la`
    C_FILE=`find -type f -ctime -3`
    echo
    bar
    printf "%s\n" "$bar_file_move"
    echo
    echo "[+] 最近三天更改的文件"
    printf "%s\n\n" "$M_FILE"
    echo "[+] 最近三天创建的文件"
    printf "%s\n\n" "$C_FILE"
    echo "[+] /var下最近三天更改的文件"
    printf "%s\n\n" "$M_FILE_VAR"
    echo
}

# [ ++ Function USER_INFORMSTION ++ ]
## 用户信息排查
function fk_userinfo
{
    USER=`cat /etc/passwd | tail -10`
    SHADOW=`cat /etc/shadow | tail -10`
    ROOT=`awk -F: '$3==0{print $1}' /etc/passwd`
    TELNET=`awk '/$1|$6/{print $1}' /etc/shadow`
    SUDO_FILE="/etc/sudoers"
    if [ -f "$SUDO_FILE" ]; then
        SUDO=`more /etc/sudoers | grep -v "^#|^$" | grep "ALL=(ALL)"`
    else
        SUDO="[-] 不存在 $SUDO_FILE 文件。"
    fi
    echo
    bar
    printf "%s\n" "$bar_user_info"
    echo
    echo "[+] /etc/passwd最新10个用户"
    echo
    printf "%s\n" "$USER"
    echo
    echo "[+] /etc/shadow最新10个影子"
    echo
    printf "%s\n" "$SHADOW"
    echo
    echo "[+] 具有root权限的用户"
    printf "%s\n" "$ROOT"
    echo
    echo "[+] 具有远程登入权限的用户"
    printf "%s\n" "$TELNET"
    echo
    echo "[+] 是否拥有SUDO权限的普通用户"
    printf "%s\n" "$SUDO"
    echo
    fk_userlogi
    echo
}

# [ ++ Function Webshell_Check ++ ]           
## webshell检测
function fk_wsfinder
{
    WEBSHELL_RULE_PHP='array_map\(|pcntl_exec\(|explode(\(|proc_open\(|popen\(|assert\(|phpspy|c99sh|milw0rm|eval?\(|\(gunerpress|\(base64_decoolcode|spider_bc|shell_exec\(|passthru\(|base64_decode\s?\(|gzuncompress\s?\(|gzinflate|\(\$\$\w+|call_user_func\(|call_user_func_array\(|preg_replace_callback\(|preg_replace\(|register_shutdown_function\(|register_tick_function\(|mb_ereg_replace_callback\(|filter_var\(|ob_start\(|usort\(|uksort\(|uasort\(|GzinFlate\s?\(|\$\w+\(\d+\)\.\$\w+\(\d+\)\.|\$\w+=str_replace\(|eval\/\*.*\*\/\('
    WEBSHELL_RULE_PHP_1='^(\xff\xd8|\x89\x50|GIF89a|GIF87a|BM|\x00\x00\x01\x00\x01)[\s\S]*<\?\s*php'
    WEBSHELL_RULE_PHP_2='\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\b[\/*\s]*\(+[\/*\s]*((\$_(GET|POST|REQUEST|COOKIE)\[.{0,25})|(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\s\(]*(\$_(GET|POST|REQUEST|COOKIE)\[.{0,25}))'
    WEBSHELL_RULE_PHP_3='\$\s*(\w+)\s*=[\s\(\{]*(\$_(GET|POST|REQUEST|COOKIE)\[.{0,25});[\s\S]{0,200}\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\b[\/*\s]*\(+[\s"\/*]*(\$\s*\1|((base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\s\("]*\$\s*\1))'
    WEBSHELL_RULE_PHP_4='\b(filter_var|filter_var_array)\b\s*\(.*FILTER_CALLBACK[^;]*((\$_(GET|POST|REQUEST|COOKIE|SERVER)\[.{0,25})|(eval|assert|ass\\x65rt|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec))'
    WEBSHELL_RULE_PHP_5="\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|include)\b\s*\(\s*(file_get_contents\s*\(\s*)?[\'\"]php:\/\/input"
    WEBSHELL_RULE_JSP='<%@\spage\simport=[\s\S]*\\u00\d+\\u00\d+|<%@\spage\simport=[\s\S]*Runtime.getRuntime\(\).exec\(request.getParameter\(|Runtime.getRuntime\(\)'
    color
    bar
    mkdir -p output
    printf "%s\n" "$bar_web_shell"

    if [ -z $WEBSHELL_PATH ]; then
        webpath="/www/wwwroot"
        webroot="/var/www"
        echo
        echo "[+] check /www/wwwroot"
        echo
        if [ -d $webpath ]; then
            echo -e "${red}1. PHP类${reset}"
            find $webpath -type f -name "*.php"  -exec grep -P -i --color=always $WEBSHELL_RULE_PHP {} + | tee -a output/webshell.log
            echo -e "${red}2. JSP类${reset}"
            find $webpath -type f -name "*.jsp"  -exec grep -P -i --color=always $WEBSHELL_RULE_JSP {} + | tee -a output/webshell.log
        else
            echo "未找到该目录"
        fi
        echo
        echo "[+] check /var/www"
        echo
        if [ -d $webroot ]; then
            echo -e "${red}1. PHP类${reset}"
            find $webroot -type f -name "*.php"  -exec grep -P -i --color=always $WEBSHELL_RULE_PHP {} + | tee -a output/webshell.log
            echo -e "\n" | tee -a output/webshell.log
            echo -e "${red}2. JSP类${reset}"
            find $webroot -type f -name "*.jsp"  -exec grep -P -i --color=always $WEBSHELL_RULE_JSP {} + | tee -a output/webshell.log
            echo -e "\n" | tee -a output/webshell.log
        else
            echo "未找到该目录"
        fi
    else    
        echo
        echo "[+] check $WEBSHELL_PATH"
        echo
        if [ -d $WEBSHELL_PATH ]; then
            echo -e "${red}1. PHP类${reset}"
            find $WEBSHELL_PATH -type f -name "*.php"  -exec grep -P -i --color=always $WEBSHELL_RULE_PHP   {} + | tee -a output/webshell.log
            find $WEBSHELL_PATH -type f -name "*.php"  -exec grep -P -i --color=always $WEBSHELL_RULE_PHP_1 {} + | tee -a output/webshell.log
            find $WEBSHELL_PATH -type f -name "*.php"  -exec grep -P -i --color=always $WEBSHELL_RULE_PHP_2 {} + | tee -a output/webshell.log
            find $WEBSHELL_PATH -type f -name "*.php"  -exec grep -P -i --color=always $WEBSHELL_RULE_PHP_3 {} + | tee -a output/webshell.log
            find $WEBSHELL_PATH -type f -name "*.php"  -exec grep -P -i --color=always $WEBSHELL_RULE_PHP_4 {} + | tee -a output/webshell.log
            find $WEBSHELL_PATH -type f -name "*.php"  -exec grep -P -i --color=always $WEBSHELL_RULE_PHP_5 {} + | tee -a output/webshell.log
            echo -e "${red}2. JSP类${reset}"
            find $WEBSHELL_PATH -type f -name "*.jsp"  -exec grep -P -i --color=always $WEBSHELL_RULE_JSP {} + | tee -a output/webshell.log
        else
            echo "未找到该目录"
        fi
    fi

    echo
    sed "s/\x1B\[[0-9;]*[JKmsu]//g" output/webshell.log >> /output/webshell.txt
    rm -f output/webshell.log
}

# [ ++ Function Vulneribility_Check ++ ]       
## 漏洞检查
function fk_vulcheck
{
    color
    bar
    echo
    printf "%s\n" "$bar_vuln_find"
    echo
    echo -e  "${red}1. redis未授权${reset}\n"
    find / -name "redis.conf" -exec grep --color=always -H "# requirepass " {} \; 2>/dev/null | tee -a vuln.log
    echo
    echo -e  "${red}2. redis弱口令自查${reset}\n"
    find / -name "redis.conf" -exec grep --color=always -H "^requirepass " {} \; 2>/dev/null | awk '{split($0, a, " "); $NF="****"; print}'
    find / -name "redis.conf" -exec grep --color=always -H "^requirepass " {} \; 2>/dev/null | awk '{print $2}' > pass.tmp
    echo "-------"
    grep -E "admin123|test|123456|admin|root|12345678|111111|p@ssw0rd|test|qwerty|zxcvbnm|123123|12344321|123qwe|password|1qaz|000000|666666|888888" pass.tmp | awk '{print "[+] "$1}'
    echo
    sed "s/\x1B\[[0-9;]*[JKmsu]//g" vuln.log > vuln.txt
    rm -f vuln.log pass.tmp
}

# [ ++ Function Baseline_Check ++ ]      
## 基线检查
function fk_baseline
{
    os_name
    color
    bar
    # os
    if [[ $OSTYPE == "T_Debian" ]]; then
        PAM_FILE="/etc/pam.d/common-auth"
    else
        PAM_FILE="/etc/pam.d/system-auth"
    fi

    echo
    printf "%s\n" "$bar_base_line"
    echo  
    # ----------------------------------------------------------------------
    echo -e  "${purple}${bold}1. 身份鉴别${reset}\n"
    echo # 1.1
    echo -e  "${blue}1.1 应对登录操作系统和数据库系统的用户进行身份标识和鉴别${reset}\n"
    echo "预期结果：""
          1)操作系统使用口令鉴别机制对用户进行身份标识和鉴别；
          2)登录时提示输入用户名和口令；以错误口令或空口令登录时提示登录失败，验证了登录控制功能的有效性；
          3)操作系统不存在密码为空的用户。"

    echo -e "${red}cat /etc/passwd${reset}"
    cat /etc/passwd | tail
    echo -e "${red}cat /etc/shadow${reset}"
    cat /etc/shadow | tail
    echo "整改建议：操作系统和数据库每个用户都必须设置登录用户名和登录密码，不能存在空密码。"
    echo # 1.2
    echo -e  "${blue}1.2 操作系统和数据库系统管理用户身份标识应具有不易被冒用的特点，口令应有复杂度要求并定期更换${reset}\n"
    echo "预期结果："
    echo "密码策略如下：PASS_MAX_DAYS   90（生命期最大为90天）
        PASS_MIN_DAYS   0（密码最短周期0天）
        PASS_MIN_LEN   10（密码最小长度10位）
        PASS_WARN_AGE 7（密码到期前7天提醒）

        口令复杂度：
        口令长度8位以上，并包含数字、字母、特殊字符三种形式"

    echo -e "${red}more /etc/login.defs${reset}"
    more /etc/login.defs | grep "PASS"
    echo "\n整改建议：密码最大生存周期为90天	
        密码最短修改周期为0天，可以随时修改密码	
        密码最小长度为10位，包含数字，特殊字符，字母（大小写）三种形式	
        密码到期前7天必须提醒"
    echo
    echo # 1.3
    echo -e  "${blue}1.3 应启用登录失败处理功能，可采取结束会话、限制非法登录次数和自动退出等措施${reset}\n"
    echo "预期结果："
    echo "1)操作系统已启用登陆失败处理、结束会话、限制非法登录次数等措施；"
    echo "2)当超过系统规定的非法登陆次数或时间登录操作系统时，系统锁定或自动断开连接"

    echo -e "${red}cat $PAM_FILE | grep "^auth"${reset}"
    cat $PAM_FILE | grep "^auth"
    echo -e "${red}cat /etc/shadow${reset}"
    cat /etc/shadow | tail
    echo "整改建议：建议限制，密码过期后重设的密码不能和前三次的密码相同。"
    echo
    echo # 1.4
    echo -e  "${blue}1.4 当对服务器进行远程管理时，应采取必要措施，防止鉴别信息在网络传输过程中被窃听${reset}\n"
    echo "预期结果："
    echo "1)操作系统使用SSH协议进行远程连接；
        2)若未使用SSH方式进行远程管理，则查看是否使用telnet方式进行远程管理；"

    echo -e "${red}systemctl is-active ssh*${reset}"
    systemctl is-active "ssh*"
    echo -e "${red}systemctl is-active telnet*${reset}"
    systemctl is-active "telnet*"
    echo
    echo "整改建议：系统远程登录时要采取SSH方式登录或采用密文传输信息，保障信息的安全性。"
    echo
    echo # 1.5
    echo -e  "${blue}1.5 为操作系统和数据库的不同用户分配不同的用户名，确保用户名具有唯一性${reset}\n"
    echo "预期结果："
    echo "用户的标识唯一，若系统允许用户名相同，UID不同，则UID是唯一性标识；若系统允许UID相同，则用户名是唯一性标识。"


    echo -e "${red}awk -F: '{print $1, $3}' /etc/passwd | sort -k2 | column -t${reset}"
    systemctl is-active "ssh*"
    echo -e "${red}systemctl is-active telnet*${reset}"
    systemctl is-active "telnet*"
    echo
    echo "整改建议：UID是唯一性标识，每个用户必须采用不同的UID来区分。"
    echo
    echo
    # ----------------------------------------------------------------------
    echo -e  "${purple}${bold}2. 访问控制${reset}\n"
    echo
    echo # 2.1
    echo -e  "${blue}2.1 应启用访问控制功能，依据安全策略控制用户对资源的访问${reset}\n"
    echo "预期结果："
    echo "root用户：
        passwd文件夹只有rw-r-r权限
        shadow文件夹只有r- - -权限

        r=4 w=2 x=1
        "

    echo -e "${red}ls -l /etc/passwd${reset}"
    ls -l /etc/passwd
    echo -e "${red}ls -l /etc/shadow${reset}"
    ls -l /etc/shadow
    echo
    echo "整改建议：根据实际需求，对每个用户的访问权限进行限制，对敏感的文件夹限制访问用户的权限。"
    echo
    echo # 2.2
    echo -e  "${blue}2.2 应根据管理用户的角色分配权限，实现管理用户的权限分离，仅授予管理用户所需的最小权限${reset}\n"
    echo "预期结果："
    echo "询问管理员，了解每个用户的作用、权限"

    echo -e "${red}awk -F: '$3==0 {print $1}' /etc/passwd${reset}"
    awk -F: '$3==0 {print $1}' /etc/passwd
    echo
    echo "整改建议：给予账户所需最小权限，避免出现特权用户。"
    echo
    echo # 2.3
    echo -e  "${blue}2.3 应实现操作系统和数据库系统特权用户的权限分离${reset}\n"
    echo "预期结果："
    echo "操作系统和数据库的特权用户的权限必须分离，避免一些特权用户拥有过大的权限，减少人为误操作。"

    echo -e "${red}awk -F: '$3==0 {print $1}' /etc/passwd${reset}"
    awk -F: '$3==0 {print $1}' /etc/passwd
    echo -e "${cyan}ps:具体情况还是得询问管理员是否存在数据库用户权限分离。${reset}"
    echo
    echo "整改建议：分离数据库和操作系统的特权用户，不能使一个用户权限过大。"
    echo
    echo # 2.4
    echo -e  "${blue}2.4 应严格限制默认帐户的访问权限，重命名系统默认帐户，修改这些帐户的默认口令${reset}\n"
    echo "预期结果："
    echo "默认账户已更名，或已被禁用"

    echo -e "${red}cat /etc/passwd | head${reset}"
    cat /etc/passwd | head
    echo
    echo "整改建议：严格限制默认账户的访问权限，对存在的默认账户的用户名和口令进行修改。使用[usermod -l <新账户名> root]来修改用户名，使用 [ usermod -L 用户名]，来锁定默认用户。"
    echo -e "${cyan}ps: 更改root名称可能导致telnet无法使用，是否配置按具体情况，具体等级分析。${reset}"
    echo
    echo # 2.5
    echo -e  "${blue}2.5 应及时删除多余的、过期的帐户，避免共享帐户的存在${reset}\n"
    echo "预期结果："
    echo "不存在多余、过期和共享账户"
    echo -e "${red}cat /etc/passwd | awk -F: '{print $1}' | paste -sd,${reset}"
    cat /etc/passwd | awk -F: '{print $1}' | paste -sd,
    echo
    echo "整改建议：删除、禁用例如uucp，ftp等多余账户。"
    echo


    # ----------------------------------------------------------------------
    echo -e  "${purple}${bold}3. 安全审计${reset}\n"
    echo # 3.1
    echo -e  "${blue}3.1 审计范围应覆盖到服务器和重要客户端上的每个操作系统用户和数据库用户${reset}\n"
    echo "预期结果："
    echo "系统开启了安全审计功能或部署了第三方安全审计设备"
    echo -e "${red}systemctl is-active auditd${reset}"
    systemctl is-active auditd
    echo
    echo "整改建议：开启系统本身的安全审计功能，完整记录用户对操作系统和文件访问情况，或采用第三方的安全审计设备。"
    echo
    echo # 3.2
    echo -e  "${blue}3.2 审计内容应包括重要用户行为、系统资源的异常使用和重要系统命令的使用等系统内重要的安全相关事件${reset}\n"
    echo "预期结果："
    echo "审计功能已开启，包括：用户的添加和删除、审计功能的启动和关闭、审计策略的调整、权限变更、系统资源的异常使用、重要的系统操作（如用户登录、退出）等设置"
    echo -e "${red}ps -ef | grep auditd${reset}"
    ps -ef | grep auditd
    echo
    echo "整改建议：开启审计功能，记录用户的添加和删除、审计功能的启动和关闭、审计策略的调整、权限变更、系统资源的异常使用、重要的系统操作（如用户登录、退出）等操作。"
    echo
    echo # 3.3
    echo -e  "${blue}3.3 审计记录应包括事件的日期、时间、类型、主体标识、客体标识和结果等${reset}\n"
    echo "预期结果："
    echo "审计记录包括事件的日期、时间、类型、主体标识、客体标识和结果等内容"
    echo -e "${red}ps -ef | grep auditd${reset}"
    echo -e "${cyan}ps:具体查看cat /etc/audit/auditd.conf | cat /etc/audit/audit.rules。${reset}"
    echo
    echo "整改建议：记录事件产生的时间，日期，类型，主客体标识等。"
    echo
    echo # 3.4
    echo -e  "${blue}3.4 操作系统应遵循最小安装的原则，仅安装需要的组件和应用程序，并通过设置升级服务器等方式保持系统补丁及时得到更新${reset}\n"
    echo "预期结果："
    echo "1)系统安装的组件和应用程序遵循了最小安装的原则；
        2)不必要的服务没有启动；
        3)不必要的端口没有打开；
        "
    echo -e "${red}lsof -i -P -n | grep LISTEN${reset}"
    lsof -i -P -n | grep LISTEN
    echo -e "${red}service --status-all | grep running${reset}"
    service --status-all
    echo
    echo "整改建议：在不影响系统的正常使用的前提下，对系统的一些端口和服务可以进行关闭，避免这些端口或服务的问题导致系统问题。"
    echo
    # ----------------------------------------------------------------------
    echo -e  "${purple}${bold}4. 资源控制${reset}\n"
    echo # 4.1
    echo -e  "${blue}4.1 应通过设定终端接入方式、网络地址范围等条件限制终端登录${reset}\n"
    echo "预期结果："
    echo "已设定终端登录安全策略及措施，非授权终端无法登录管理。"
    echo -e "${red}etc/hosts.deny、/etc/hosts.allow中对终端登录限制的相关配置参数${reset}"
    echo -e "${cyan}ps:查看相关配置。${reset}"
    echo
    echo "整改建议：建议配置固定的终端、特定的网络范围内才能进行终端登录。"
    echo
    echo # 4.2
    echo -e  "${blue}4.2 应根据安全策略设置登录终端的操作超时锁定${reset}\n"
    echo "预期结果："
    echo "已在/etc/profile中为TMOUT设置了合理的操作超时时间。"
    echo -e "${red}cat /etc/profile | grep "TMOUT"${reset}"
    cat /etc/profile | grep "TMOUT"
    echo
    echo "整改建议：超时时间建议设置为300秒。"
    echo
}

# [ ++ Function AUTO_FUCK ++ ]
## 彩蛋：一键溯源（不是） 溯源思路
function fk_autofuck
{

    color
    bar
    printf "%s\n" "$bar_auto_fuck"

    echo "溯源思路："
    echo "三位一体、三面一线、三点一记"
    echo "端口->服务、服务->进程、进程->网络 | 时间线 = 轨迹 = 日志 = {history、logs、crontab、filemodifytime.....}"
    echo "溯源盲区："
    echo "不可见字符文件如.. . | 删除绕过文件 如 --help "
    echo "多实践，多积累，经验很重要，感觉也很重要。"

}

# [ ++ OPTIONS PARAMETE ++ ]

op="${1}"
case ${op} in

    -h | --help)
            help_cn
            ;;
    -a | --all) 
            fk_baseinfo     # 基本消息
            fk_devicestatus # 基本状态
            fk_userlogin    # 登录日志
            ;;
    -l | --login) FILE="$2"
            fk_userlogin "$FILE" "$SECURE_FILE"
            ;;
    -u | --user-device)     
            fk_baseinfo
            ;;
    -s | --os-status)
            fk_devicestatus
            ;;
    -x | --process-and-service)
            fk_procserv
            ;;
    -n | --nomal)
            fk_baseinfo
            fk_history
            fk_crontab
            fk_filemove
            fk_userinfo
            ;;
    -p | --port)
            fk_portstatus
            ;;
    -o | --output)
            mkdir -p output
            current_time=$(date "+%Y%m%d%H%M%S")
            if [ -z "$2" ]; then
                ./"$0" -n > output.txt
                sed "s/\x1B\[[0-9;]*[JKmsu]//g" output.txt > output/${current_time}_output.txt
            else
                ./"$0" -n > "$2"
                sed "s/\x1B\[[0-9;]*[JKmsu]//g" $2 > output/${current_time}_$2
            fi
            rm -f output.txt $2
            ;;
    -w | --webshell) WEBSHELL_PATH="$2"
            fk_wsfinder "$WEBSHELL_PATH"
            ;;
    -r | --risk)
            fk_vulcheck
            ;;
    -b | --baseline)
            fk_baseline
            ;;
    -y | --whoamifuck)
            fk_autofuck
            ;;
    -v | --version)
            echo "$VER"
            ;;
    *)
        help_en
        ;;
esac

# --------------------------------------
#        | Futher |             
# --------------------------------------

# 查找僵尸进程
# TKILL=`ps -al | awk '{print $2,$4}' | grep -e '^[Zz]'`

# 软链接排查
# alias

# /home/用户名/.bashrc
# /root/.bashrc
# /etc/.bashrc针对所有用户生效
# ~/.bashrc是针对当前用户生效

# SSH软链接排查
# netstat -anpt


# SSH Public key BackDoor
# authorized_keys 的修改时间
# stat /root/.ssh/authorized_keys
# stat ~/.ssh/authorized_keys 是针对当前用户生效

