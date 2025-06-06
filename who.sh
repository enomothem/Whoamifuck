#!/bin/bash
# Linux入侵检测报告工具-Whoamifuck[司稽]
# Author: Enomothem
# Time: 2021年2月8日


# --------------------------------------
#        | Whoamifuck |
# --------------------------------------

function env
{
    # [ ++ 基本信息 ++ ]
    VER="2025.6.3@whoamifuck-version 6.3.1"
    WHOAMIFUCK=`whoami`
    FUCK=`who`

    # [ ++ 默认路径 ++ ]
    CONF_PATH="$HOME/.whok"
    CONF_FILE="chief-inspector.conf"    # Conf File
    OUTPUT="output"                     # Default Output
    OUTPUT_M="output/html"              # Html Output Path
    OUTPUT_T="output/text"              # Text Output Path
    AUTHLOG_FILE="/var/log/auth.log"    # Ubuntu Path
    SECURE_FILE="/var/log/secure"       # RedHat Path
    COURIER="courier.html"              # Email file
}

env

# --------------------------------------
#        | Function |
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
    orange="\033[1;93m"
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

# [ ++ Function LOGO ++ ]
function logo
{
    color
    echo
    echo
    hh="${reset}${green}<bug>${reset}${red}"
    s="${reset}${redx}777${reset}${red}"
    r="${reset}${yellow}who!${reset}${red}"
    x="${reset}${orange}root${reset}${red}"
    printf "${red} ██╗    ██╗██╗  ██╗ ██████╗  █████╗ ███╗   ███╗██╗    ███████╗██╗   ██╗ ██████╗██╗  ██╗ ${reset}\n"
    printf "${red} ██║${x}██║██║  ██║██╔═══██╗██╔══██╗████╗ ████║██║    ██╔════╝██║   ██║██╔════╝██║ ██╔╝ ${reset}\n"
    printf "${red} ██║ █╗ ██║███████║██║${s}██║███████║██╔████╔██║██║    █████╗  ██║   ██║██║${hh}█████╔╝  ${reset}\n"
    printf "${red} ██║███╗██║██╔══██║██║   ██║██╔══██║██║╚██╔╝██║██║    ██╔══╝  ██║   ██║██║     ██╔═██╗  ${reset}\n"
    printf "${red} ╚███╔███╔╝██║  ██║╚██████╔╝██║  ██║██║ ╚═╝ ██║██║    ██║     ╚██████╔╝╚██████╗██║  ██╗ ${reset}\n"
    printf "${red}  ╚══╝╚══╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝    ╚═╝ ${r} ╚═════╝  ╚═════╝╚═╝  ╚═╝ ${reset}\n"
    printf "       Hi ${WHOAMIFUCK}          ${VER}          by \\\Eonian Sharp\\ -${blue} Enomothem${reset}     \n"

}

# [ ++ Function HELP_CN ++ ]
function help_cn
{
    logo
    COL1_WIDTH=30
    COL2_WIDTH=50

    printf "%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "使用方法:" ""
    printf "\n"

    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-v --version"                   "版本信息"
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-h --help"                      "帮助指南"
    printf "\n"

    printf "  %-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "QUICK" ""
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-u --user-device"               "查看设备基本信息"
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-l --login [FILEPATH]"          "用户登录信息 [default:/var/log/secure;/var/log/auth.log]"
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-n --nomal"                     "基本输出模式"
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-a --all"                       "全量输出模式"
    printf "\n"

    printf "  %-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "SPECIAL" ""
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-x --proc-serv"                 "检查用户进程与开启服务状态"
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-p --port"                      "查看端口开放状态"
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-s --os-status"                 "查看系统状态信息"
    printf "\n"

    printf "  %-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "RISK" ""
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-b --baseline"                  "基线安全评估"
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-r --risk"                      "查看系统可能存在的漏洞"
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-k --rookitcheck"               "检测系统可能存在的后门"
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-w --webshell [PATH]"           "查找可能存在的webshell文件 [default:/var/www/;/www/wwwroot/..]"
    printf "\n"

    printf "  %-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "MISC" ""
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-c --code [URL|FILE]"           "页面存活探测"
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-i --sqletlog [FILE]"           "日志分析-SQL注入专业分析"
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-e --auto-run [0-23 0-59|c]"    "加入到定时运行计划 [default:~/.whok/chief-inspector.conf]"
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-z --ext [PATH]"                "自定义命令配置测试 [default:~/.whok/chief-inspector.conf]"
    printf "\n"

    printf "  %-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "OUTPUT" ""
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-o --output [FILENAME]"         "导出全量输出模式文件"
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-m --html [FILENAME]"           "导出全量输出模式HTML文件"
    printf "\n"
}

# [ ++ Function HELP_EN ++ ]
function help_en
{
    logo
    COL1_WIDTH=30
    COL2_WIDTH=50

    printf "%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "USAGE:" ""
    printf "\n"

    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-v --version"                   "Show version."
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-h --help"                      "Show help guide."
    printf "\n"

    printf "  %-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "QUICK" ""
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-u --user-device"               "Check device information."
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-l --login [FILEPATH]"          "Show user login log. [default:/var/log/secure;/var/log/auth.log]"
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-n --nomal"                     "Nomal print."
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-a --all"                       "All print."
    printf "\n"

    printf "  %-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "SPECIAL" ""
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-x --proc-serv"                 "Check service and process information."
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-p --port"                      "Show port information."
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-s --os-status"                 "Show os status information."
    printf "\n"

    printf "  %-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "RISK" ""
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-b --baseline"                  "Baseline security assessment."
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-r --risk"                      "Check os vulneribility."
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-k --rookitcheck"               "Check os rookit."
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-w --webshell [PATH]"           "Find the webshell file. [default:/var/www/;/www/wwwroot/..]"
    printf "\n"

    printf "  %-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "MISC" ""
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-c --code [URL|FILE]"           "Http status code scan."
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-i --sqletlog [FILE]"           "Log Analysis - Professional Analysis of SQL Injection."
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-e --auto-run [0-23 0-59|c]"    "Add to crontab to run regularly. [default:~/.whok/chief-inspector.conf]"
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-z --ext [PATH]"                "Custom command configuration tests. [default:./.whok/chief-inspector.conf]"
    printf "\n"

    printf "  %-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "OUTPUT" ""
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-o --output [FILENAME]"         "Output to file."
    printf "\t%-${COL1_WIDTH}s %-${COL2_WIDTH}s\n" "-m --html [FILENAME]"           "Output to html file."
    printf "\n"
}


# --------------------------------------
#        | Uers Functions |
# --------------------------------------


#---------------------------------------------------------------------------------------
#        /     /     /       /      /       /       /       /
#       |     |     |       |      |       |       |       |
# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\^V3@$%
# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\^\^\^
#                                  |/////|
#                                  |/////|
# ==========始于2021=============>入      口<==========|Whoamifuck 1.0 纪念馆|==========\
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
# ==========始于2021=============>出      口<==========================================\
#     \|/               \|/        |/////|     \|/     __ \|/      __
#             \|/                  |/////|__     __ _\|/    _______    \|/
#      \|/   __   \|/    \|/       |\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\/ -> 通往2025年 AI
#---------------------------------------------------------------------------------------

function user_debian
{
    echo -e "${bg_red}\n『 用户登录 』${reset}\n"
    cat $AUTH_S | grep "session opened"  | awk '{print $1 " " $2, $3, "用户登录", $11}' | tail -20;echo
    echo -e "${bg_red}\n『 用户登出 』${reset}\n"
    cat $AUTH_S | grep "session closed"  | awk '{print $1 " " $2, $3, "用户登出", $11}' | tail -20;echo
    echo -e "${bg_red}\n『 攻击次数 攻击者IP --> 枚举用户名 』${reset}\n"
    cat $AUTH_S | grep "Failed password for invalid user" | awk '{print $13 " --> " $11}' | sort | uniq -c | sort -rn | awk '{print "[+] 用户名不存在 "$0}' | head -20
    echo -e "${bg_red}\n『 攻击者IP次数 』${reset}\n"
    cat $AUTH_S | grep "Failed password for invalid user" | awk '{print $11 " --> " $13}' | sort | uniq -c | sort -rn | awk '{print $4}' | sort | uniq -c | awk '{print "[+] "$2" 攻击次数 "$1"次"}';echo
    echo -e "${bg_red}\n『 登录成功IP地址 』${reset}\n"
    cat $AUTH_S | grep "Accepted"  | awk '{print "时间:"$1"-"$2"-"$3"\t登录成功\t "$11" --> "$9 " 使用方式: "$7}';echo
    echo -e "${bg_red}\n『 对用户名进行密码爆破次数 』${reset}\n"
    cat $AUTH_S | grep "Failed password for" | grep -v invalid | awk '{print $11"—->"$9}'| uniq -c | sort -rn | awk '{print "[+] 攻击次数: " $1   " 详情:   "$2}' | head -20;echo
}

function user_centos
{
    echo -e "${bg_red}\n『 攻击次数TOP 攻击者IP --> 枚举用户名 』${reset}\n"
    cat $SECURE_S | grep "Failed password for invalid user" | awk '{print $13 " --> " $11}' | sort | uniq -c | sort -rn | awk '{print "[+] 用户名不存在 "$0}' | head -20
    echo -e "${bg_red}\n『 攻击者IP次数TOP 』${reset}\n"
    cat /var/log/secure | grep "Failed password for invalid user" | awk '{print $11 " --> " $13}' | sort | uniq -c | sort -rn | awk '{print $4}' | sort | uniq -c | sort -k1rn | awk '{print "[+] "$2" 攻击次数 "$1"次"}';echo
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


# [ ++ Function bar ++ ]
function bar
{
    color
    bar_auto_fuck=`printf "${red}%50s${reset}" "[ Whoamifuck ]"`
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
    bar_file_info=`printf "${red}%50s${reset}" "[ 文件位置排查 ]"`
    bar_web_shell=`printf "${red}%50s${reset}" "[ webshell查找 ]"`
    bar_vuln_find=`printf "${red}%50s${reset}" "[ 常见漏洞评估 ]"`
    bar_base_line=`printf "${red}%50s${reset}" "[ 基线安全评估 ]"`
    bar_http_scan=`printf "${red}%50s${reset}" "[ 存活页面探测 ]"`
    bar_find_rkit=`printf "${red}%50s${reset}" "[ rootkit查杀 ]"`
    bar_repo_rest=`printf "${red}%50s${reset}" "[ 生成应急报告 ]"`
    bar_sqli_anal=`printf "${red}%50s${reset}" "[ 日志分析-SQLi ]"`
    bar_conf_file=`printf "${red}%50s${reset}" "[ 高级扩展命令 ]"`

}

# [ ++ Message status ++ ]
function stats
{
    color
    SUC="[${green}SUCCESS${reset}]"
    WAR="[${orange}WARNING${reset}]"
    ERR="[${redx}ERROR${reset}]"
    OK="[${green}+${reset}]"
    NO="[${redx}-${reset}]"
    INFO="[${blue}*${reset}]"
}

# [ ++ Function OS_NAME ++ ]
function os_name
{
    if [ -e /etc/os-release ]; then
        # Get the name of the current Linux distribution
        # 如果不存在这个文件呢？待改进 TODO，不可能，绝对不可能，这得多阉割啊，除非有纯国产，嘿嘿嘿
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
        elif [[ "$os_name" == *"Parrot"* ]]; then
            OSNAME="Parrot OS"
            OSTYPE="T_Debian"
        elif [[ "$os_name" == *"Deepin"* ]]; then
            OSNAME="Deepin"    # 国产的深度，至于其它的嘛，emmmm，内核显示ubuntu，笑哭
            OSTYPE="T_Debian"
        else
            OSNAME="Unknown distribution"
            OSTYPE="T_RedHat"   # 未知情况默认红帽系，centos的阉割版还是多的
        fi
    fi
}

# [ ++ Check Command ++ ]
function fk_command
{
    stats
    if ! which curl &> /dev/null; then
        printf "$WAR curl 命令不存在将导致web存活模块无法使用。\n"
    fi
}

# [ ++ Check Command ++ ]
function i
{
    color
    os_name
    # os
    if [[ $OSTYPE == "T_Debian" ]]; then
        OS_APP="apt-get"
    else
        OS_APP="yum"
    fi
    local package=$1
    if ! command -v "$package" &> /dev/null; then
        printf "$package   ${redx} uninstalled ${reset} \n"
        read -p "是否安装 $package？ (Y/n): " choice
        choice=${choice:-y}
        case "$choice" in
            y|Y )
                echo "正在安装 $package..."
                sudo $OS_APP update
                sudo $OS_APP install -y "$package"
                ;;
            * )
                printf "exit\n"
                exit 1
                ;;
        esac
    else
        printf "$package   ${green} installed ${reset} \n"
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
            elif [[ "$os_name" == *"Parrot"* ]]; then
                if [ -f $AUTHLOG_FILE ]; then
                    AUTH_S=$AUTHLOG_FILE
                    user_debian "$AUTH_S"
                else
                    echo $AUTHLOG_FILE"文件不存在"
                fi
            elif [[ "$os_name" == *"Deepin"* ]]; then
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

    if command -v ifconfig > /dev/null; then
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
            echo "The variable is greater than 2"
        else
            echo "panic!"
        fi
    else
        ETH=`ip -o link show | grep '^[0-9]*: e' | awk '{print $2}' | tr -d ':' | wc -l`

        if [ $ETH -eq 1 ]; then
            ETHx=`ip -o link show | grep '^[0-9]*: e' | awk '{print $2}' | tr -d ':'`
            IP=`ip -o -4 addr show $ETHx | awk '{print $4}' | cut -d/ -f1`
            ZW=`ip -o -4 addr show $ETHx | awk '{print $4}' | cut -d/ -f2`
        elif [ $ETH -eq 2 ]; then
            ETH0=`ip -o link show | grep '^[0-9]*: e' | awk 'NR==1{print $2}' | tr -d ':'`
            ETH1=`ip -o link show | grep '^[0-9]*: e' | awk 'NR==2{print $2}' | tr -d ':'`
            IP1=`ip -o -4 addr show $ETH0 | awk '{print $4}' | cut -d/ -f1`
            ZW1=`ip -o -4 addr show $ETH0 | awk '{print $4}' | cut -d/ -f2`
            IP2=`ip -o -4 addr show $ETH1 | awk '{print $4}' | cut -d/ -f1`
            ZW2=`ip -o -4 addr show $ETH1 | awk '{print $4}' | cut -d/ -f2`
            IP="$IP1,$IP2"
            ZW="$ZW1,$ZW2"
        elif [ $ETH -gt 2 ]; then
            echo "The variable is greater than 2"
        else
            echo "panic!"
        fi
    fi
    # 兼容性
    if command -v route > /dev/null; then
        GW=`route -n | tail -1 | awk '{print $1}'`
    else
        GW=`ip route | head -1 | awk '{print $3}'`
    fi
    HN=`hostname`
    VM=`lscpu | grep "Hyper.*:\|Virtu\|超管理器厂商" | awk -F [:：] '{print $2}' | sed 's/ //g' | paste -sd, | sed 's/,full//g'`
    DNS=`cat "/etc/resolv.conf"  | grep nameserver | awk '{print $2}' | paste -sd,`
    OS=`uname --kernel-name --kernel-release`
    TUN=`uptime | sed 's/user.*$//' | awk '{print $NF}'`
    M_TIME=`date +"%Y-%m-%d %H:%M:%S %s"`
    OSNAME_VER=`cat /etc/os-release | grep '^VERSION_ID=' | awk -F '=' '{print $2}' `
    # show color
    os_name
    IP_C=`echo -e "${cyan}$IP${reset}"`
    HN_C=`echo -e "${yellow}$HN${reset}「 ${redx}$WHOAMIFUCK${reset} 」"`
    OSNAME_C=`echo -e "${bg_yellow}$OSNAME $OSNAME_VER${reset}「 ${blue}$VM${reset} 」"`
    TUN_C=`echo -e "${purple}$TUN${reset}"`
    M_TIME_C=`echo -e "${green}$M_TIME${reset}"`

    LAST=`last -i | head`
    LASTLOG=`lastlog  | grep -v Never`

    current_user_tasks=$(crontab -l  2>/dev/null | wc -l)
    if [ $? -ne 0 ]; then
        current_user_tasks=0
    fi
    etc_crontab_tasks=$(grep -vE '^\s*#|^\s*$' /etc/crontab | grep -vE '^[A-Za-z]' | wc -l)
    var_spool_tasks=$(grep -s . /var/spool/cron/* | grep -v "^Binary"  | wc -l)
    # 检查变量是否为空，并设置为0
    if [ -z "$current_user_tasks" ]; then
        current_user_tasks=0
    fi

    if [ -z "$etc_crontab_tasks" ]; then
        etc_crontab_tasks=0
    fi

    if [ -z "$var_spool_tasks" ]; then
        var_spool_tasks=0
    fi
    bar


    if [ -z $show ]; then
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
        echo -e "${red}> 在线用户具体信息${reset}"
        printf "$FUCK"
        printf "\n------------------------------------------------------------------------------------------------------\n"
        echo -e "${red}> 最近用户登录信息${reset}"
        printf "$LAST"
        printf "\n------------------------------------------------------------------------------------------------------\n"
        echo -e "${red}> 用户最后登录信息${reset}"
        printf "$LASTLOG"
        printf "\n------------------------------------------------------------------------------------------------------\n"
        echo -e "${red}> 计划任务计数器 ${reset}"
        echo "当前用户的计划任务数量: $current_user_tasks"
        echo "/etc/crontab 下的任务数量: $etc_crontab_tasks"
        echo "/var/spool/cron 下的任务数量：$var_spool_tasks"
        printf "%s""------------------------------------------------------------------------------------------------------\n"
        printf "%s%s" "此刻唯一时间戳[本地]: " "$M_TIME_C"
        echo
    else
        noprint=$show
    fi
}

# [ ++ Function OS_STATUS_INFORMATION ++ ]
## 系统状态信息
function fk_devicestatus
{
    # 查看内存、磁盘、CPU状态
    TA=$(free -m | awk 'NR==2{printf "%.2f%%\t\t",$3*100/$2}' ;echo;)
    TB=$(df -h| awk '$NF=="/"{printf "%s\t\t",$5}')
    TC=$(top -bn1 | grep load | awk '{printf "%.2f%%\t\t\n",2$(NF2)}')
    bar
    if [[ -z $show ]]; then
        printf "%s\n" "$bar_osys_stat"
        echo
        printf "%s%s" "Memory:" "$TA"
        printf "%s%s" "Disk:" "$TB"
        printf "%s%s" "CPU:" "$TC"
        echo
    else
        noprint=$show
    fi
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
    printf "%s" "`systemctl | grep -E "\.service.*running" | awk -F. '{print $1}'`"
    echo
    printf "%s" "`for service in $(systemctl list-units --all | grep -v "inactive" | awk '/\S+\.service/ {gsub(/^[^[:alnum:]]+/, ""); print $1}' | grep -v UNIT); do   echo -e "\n-------------\n服务: $service\n-------------";   systemctl show "$service" | grep -E "MainPID|path"; done`"
}



# [ ++ Function OPENPORT_INFORMATION ++ ]
## 开启端口列表
function port_http
{
    color

    # 获取本地开放的端口
    open_ports=$(ss -tuln | awk '/LISTEN/ {print $1, $5}' | grep tcp | awk -F: '{print $NF}' | sort -u)

    # 设置User-Agent
    useragent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"

    # 设置超时时间
    connect_timeout=5
    max_time=10

    # 已知非HTTP服务端口列表
    non_http_ports=("3306" "22" "25" "139" "143" "465" "587" "993" "995" "3389" "445")

    # 遍历每个端口，使用curl检查是否为HTTP服务
    for port in $open_ports; do
        # 跳过已知非HTTP服务端口
        if [[ " ${non_http_ports[@]} " =~ " ${port} " ]]; then
            # echo "Skipping non-HTTP port: $port"
            continue
        fi

        url="http://localhost:$port"


        # 发送HTTP请求并获取响应
        response=$(curl -k -A "${useragent}" --connect-timeout ${connect_timeout} --max-time ${max_time} --silent --location --write-out "HTTPSTATUS:%{http_code}" --max-redirs 10 "${url}" 2>/dev/null)
        http_code=$(echo "$response" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')
        response_body=$(echo "$response" | sed -e 's/HTTPSTATUS\:.*//g')

        # 检查是否为HTTP服务
        if [ "$http_code" -eq 000 ]; then
            continue
        fi

        # 检查是否为302跳转
        if [ "$http_code" -eq 302 ]; then
            redirect_url=$(echo "$response_body" | grep -oP '(?<=Location: ).*' | head -n 1)
            echo "Redirected to: $redirect_url"
        fi

        title=$(echo "$response_body" | grep -oP '(?<=<title>).*?(?=</title>)')
        bytes=$(echo -n "$response_body" | wc -c)


        # 输出结果
        echo -e "[INFO] ${url} [${http_code}] [${bytes}] [${purple}${title}${reset}]" | tee -a output/http_info.txt
    done
}

function fk_portstatus
{
    # 考虑没有net-tools工具包的情况
    # netstat 和 lsof 一起判断

    if command -v netstat > /dev/null && command -v lsof > /dev/null; then
        PORT=`netstat -tunlp | awk '/^tcp/ {print $4,$7}; /^udp/ {print $4,$6}' | sed -r 's/.*:(.*)\/.*/\1/' | sort -un | awk '{cmd = "sudo lsof -w -i :" $1 " | awk '\''NR==2{print $1}'\''"; cmd | getline serviceName; close(cmd); print $1 "\t" serviceName}'`
    else
        PORT=`ss -tulpn`
    fi
    bar
    echo
    printf "%s\n" "$bar_port_open"
    echo
    echo -e "${red}>端口服务信息${reset}"
    printf "%s\n" "$PORT"
    echo
    echo -e "${red}>探测HTTP服务端口${reset}"
    port_http



}

# [ ++ Function HISTORY_INFORMSTION ++ ]
# 历史命令
function fk_history
{
    # 脚本无法执行history命令
    HI=`cat ~/.*sh_history 2>/dev/null | tail -10` # 查看用户的历史命令，使用通配符的方式

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
    # /var/spool/cron/'
    # /etc/cron.d/'
    # /etc/cron.daily/'
    # /etc/cron.weekly/'
    # /etc/cron.hourly/'
    # /etc/cron.monthly/'
    bar
    echo
    printf "%s\n" "$bar_cron_task"
    echo
    printf "%s" "$CRON"
    echo
}

# [ ++ Function FILE ++ ]
## 异常文件排查
function fk_fileinfo
{
    color

    # 定义要检查的目录
    DIRECTORIES=("/home" "/opt")

    # 初始化一个变量来存储所有输出
    file_output=""

    # 遍历每个目录
    for dir in "${DIRECTORIES[@]}"; do
        file_output+="${green}列出 $dir 下的文件和目录：${reset}\n"
        if [ -d "$dir" ]; then
            for user_dir in "$dir"/*/; do
                file_output+="${green}目录：${reset}${user_dir}\n"
                file_output+="$(ls -lt "${user_dir}" | head -n 10)\n"
            done
        else
            file_output+="${red}目录 $dir 不存在。${reset}\n"
        fi
    done

    stats
    bar

    if [ -z $show ]; then
        echo -e "$bar_file_info"
        echo
        printf "$OK 常见目录下的文件\n"
        echo "-----------------"
        echo -e "$file_output"
        echo
    else
        noprint=$show
    fi
}

# [ ++ Function FILEMOVE_INFORMSTION ++ ]
## 文件修改信息
function fk_filemove
{
    M_FILE=`find -type f -mtime -3`
    M_FILE_VAR=`find /var/ -type f -mtime -3 | xargs ls -la 2>/dev/null`
    C_FILE=`find -type f -ctime -3`
    SSHKEY_FILE=$HOME/.ssh/authorized_keys
    if [ -f $SSHKEY_FILE ]; then
        publickey_perm=$(stat -c %a $SSHKEY_FILE)
        publickey_modi=$(stat -c %y $SSHKEY_FILE)
        sshpubkey="$publickey_modi($publickey_perm)"
    else
        sshpubkey="未找到该文件"
    fi

    stats
    bar

    if [ -z $show ]; then
        printf "%s\n" "$bar_file_move"
        echo
        printf "$OK 最近三天更改的文件\n"
        echo "-----------------"
        printf "%s\n\n" "$M_FILE"
        printf "$OK 最近三天创建的文件\n"
        echo "-----------------"
        printf "%s\n\n" "$C_FILE"
        printf "$OK /var下最近三天更改的文件\n"
        echo "-----------------"
        printf "%s\n\n" "$M_FILE_VAR"
        printf "$OK PublicKey修改时间及其权限\n"
        echo "-----------------"
        printf "%s\n\n" "$sshpubkey"
        echo
    else
        noprint=$show
    fi
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
        SUDO="$NO 不存在 $SUDO_FILE 文件。"
    fi
    stats
    bar
    echo

    printf "%s\n" "$bar_user_info"
    echo
    printf "$OK /etc/passwd最新10个用户\n"
    echo "-----------------"
    echo
    printf "%s\n" "$USER"
    echo
    printf "$OK /etc/shadow最新10个影子\n"
    echo "-----------------"
    echo
    printf "%s\n" "$SHADOW"
    echo
    printf "$OK 具有root权限的用户\n"
    echo "-----------------"
    printf "%s\n" "$ROOT"
    echo
    printf "$OK 具有远程登入权限的用户\n"
    echo "-----------------"
    printf "%s\n" "$TELNET"
    echo
    printf "$OK 是否拥有SUDO权限的普通用户\n"
    echo "-----------------"
    printf "%s\n" "$SUDO"
    echo
    fk_userlogin
    echo
    if [ -f $CONF_PATH/$CONF_FILE ]; then
        source $CONF_PATH/$CONF_FILE
        if [ $EXT = "true" ]; then
            fk_extention
        fi
    else
        status="no find file"
    fi
}

# [ ++ Function SSH_BACKDOOR ++ ]
## SSH后门
function fk_sshlink
{
    processes=$(netstat -ntpl 2>/dev/null | grep -v ':22 ' | awk '{if (NR>2){print $7}}' | sed 's|/.*||')
    processesx=$(netstat -ntpl 2>/dev/null | awk '{if (NR>2){print $7}}' | sed 's|/.*||')
    declare -a sshlink_processes=()
    declare -a sshwrapper_processes=()
    sshbackdoor_info=''
    for pid in $processes; do
        # 检查 /proc/pid/exe 是否存在 sshd 软链接
        if [ -L "/proc/$pid/exe" ]; then
            if [ "$(readlink /proc/$pid/exe)" == "/usr/sbin/sshd" ]; then
                sshlink_processes+=("$pid")
            fi
        fi
    done

    for pid in $processesx; do
        # 检查 /proc/pid/exe 是否存在 SSH Server wrapper 后门
        if [ -L "/proc/$pid/exe" ]; then
            if [ "$(readlink /proc/$pid/exe)" == "/usr/bin/sshd" ]; then
                sshwrapper_processes+=("$pid")
            fi
        fi
    done

    for pid in $processesx; do
        # 细节
        if [ -e "/proc/$pid/exe" ]; then
            sshbackdoor_info+="$(ls -al /proc/$pid/ | grep 'exe')\\n"
        fi
    done

    if [ ${#sshlink_processes[@]} -gt 0 ]; then
        sshlink="异常进程：${sshlink_processes[@]}"
    else
        sshlink="未发现异常进程"
    fi
    if [ ${#sshwrapper_processes[@]} -gt 0 ]; then
        sshwrapper="异常进程：${sshwrapper_processes[@]}"
    else
        sshwrapper="未发现异常进程"
    fi

}

# [ ++ Function Webshell_Check ++ ]
## webshell检测
function fk_wsfinder
{
    WEBSHELL_RULE_PHP='array_map\(|pcntl_exec\(|proc_open\(|popen\(|assert\(|phpspy|c99sh|milw0rm|eval?\(|\(gunerpress|\(base64_decoolcode|spider_bc|shell_exec\(|passthru\(|base64_decode\s?\(|gzuncompress\s?\(|gzinflate|\(\$\$\w+|call_user_func\(|call_user_func_array\(|preg_replace_callback\(|preg_replace\(|register_shutdown_function\(|register_tick_function\(|mb_ereg_replace_callback\(|filter_var\(|ob_start\(|usort\(|uksort\(|uasort\(|GzinFlate\s?\(|\$\w+\(\d+\)\.\$\w+\(\d+\)\.|\$\w+=str_replace\(|eval\/\*.*\*\/\('
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
    sed "s/\x1B\[[0-9;]*[JKmsu]//g" output/webshell.log >> output/webshell.txt
    rm -f output/webshell.log
}

# [ ++ Function Vulneribility_Check ++ ]
## 漏洞检查

# https://github.com/aishee/scan-dirtycow/blob/master/dirtycowscan.sh 老哥的脚本
function dirty_cow
{
    color
    SAFE_KERNEL="SAFE_KERNEL"
    SAFE_KPATCH="SAFE_KPATCH"
    MITIGATED="MITIGATED"
    VULNERABLE="VULNERABLE"

    MITIGATION_ON='CVE-2016-5195 mitigation loaded'
    MITIGATION_OFF='CVE-2016-5195 mitigation unloaded'


    VULNERABLE_VERSIONS=(
        # UBUNTU PRECISE
        "3.1.1-1400-linaro-lt-mx5"
        "3.11.0-13-generic"
        "3.11.0-14-generic"
        "3.11.0-15-generic"
        "3.11.0-17-generic"
        "3.11.0-18-generic"
        "3.11.0-20-generic"
        "3.11.0-22-generic"
        "3.11.0-23-generic"
        "3.11.0-24-generic"
        "3.11.0-26-generic"
        "3.13.0-100-generic"
        "3.13.0-24-generic"
        "3.13.0-27-generic"
        "3.13.0-29-generic"
        "3.13.0-30-generic"
        "3.13.0-32-generic"
        "3.13.0-33-generic"
        "3.13.0-34-generic"
        "3.13.0-35-generic"
        "3.13.0-36-generic"
        "3.13.0-37-generic"
        "3.13.0-39-generic"
        "3.13.0-40-generic"
        "3.13.0-41-generic"
        "3.13.0-43-generic"
        "3.13.0-44-generic"
        "3.13.0-46-generic"
        "3.13.0-48-generic"
        "3.13.0-49-generic"
        "3.13.0-51-generic"
        "3.13.0-52-generic"
        "3.13.0-53-generic"
        "3.13.0-54-generic"
        "3.13.0-55-generic"
        "3.13.0-57-generic"
        "3.13.0-58-generic"
        "3.13.0-59-generic"
        "3.13.0-61-generic"
        "3.13.0-62-generic"
        "3.13.0-63-generic"
        "3.13.0-65-generic"
        "3.13.0-66-generic"
        "3.13.0-67-generic"
        "3.13.0-68-generic"
        "3.13.0-71-generic"
        "3.13.0-73-generic"
        "3.13.0-74-generic"
        "3.13.0-76-generic"
        "3.13.0-77-generic"
        "3.13.0-79-generic"
        "3.13.0-83-generic"
        "3.13.0-85-generic"
        "3.13.0-86-generic"
        "3.13.0-88-generic"
        "3.13.0-91-generic"
        "3.13.0-92-generic"
        "3.13.0-93-generic"
        "3.13.0-95-generic"
        "3.13.0-96-generic"
        "3.13.0-98-generic"
        "3.2.0-101-generic"
        "3.2.0-101-generic-pae"
        "3.2.0-101-virtual"
        "3.2.0-102-generic"
        "3.2.0-102-generic-pae"
        "3.2.0-102-virtual"
        "3.2.0-104-generic"
        "3.2.0-104-generic-pae"
        "3.2.0-104-virtual"
        "3.2.0-105-generic"
        "3.2.0-105-generic-pae"
        "3.2.0-105-virtual"
        "3.2.0-106-generic"
        "3.2.0-106-generic-pae"
        "3.2.0-106-virtual"
        "3.2.0-107-generic"
        "3.2.0-107-generic-pae"
        "3.2.0-107-virtual"
        "3.2.0-109-generic"
        "3.2.0-109-generic-pae"
        "3.2.0-109-virtual"
        "3.2.0-110-generic"
        "3.2.0-110-generic-pae"
        "3.2.0-110-virtual"
        "3.2.0-111-generic"
        "3.2.0-111-generic-pae"
        "3.2.0-111-virtual"
        "3.2.0-1412-omap4"
        "3.2.0-1602-armadaxp"
        "3.2.0-23-generic"
        "3.2.0-23-generic-pae"
        "3.2.0-23-lowlatency"
        "3.2.0-23-lowlatency-pae"
        "3.2.0-23-omap"
        "3.2.0-23-powerpc-smp"
        "3.2.0-23-powerpc64-smp"
        "3.2.0-23-virtual"
        "3.2.0-24-generic"
        "3.2.0-24-generic-pae"
        "3.2.0-24-virtual"
        "3.2.0-25-generic"
        "3.2.0-25-generic-pae"
        "3.2.0-25-virtual"
        "3.2.0-26-generic"
        "3.2.0-26-generic-pae"
        "3.2.0-26-virtual"
        "3.2.0-27-generic"
        "3.2.0-27-generic-pae"
        "3.2.0-27-virtual"
        "3.2.0-29-generic"
        "3.2.0-29-generic-pae"
        "3.2.0-29-virtual"
        "3.2.0-31-generic"
        "3.2.0-31-generic-pae"
        "3.2.0-31-virtual"
        "3.2.0-32-generic"
        "3.2.0-32-generic-pae"
        "3.2.0-32-virtual"
        "3.2.0-33-generic"
        "3.2.0-33-generic-pae"
        "3.2.0-33-lowlatency"
        "3.2.0-33-lowlatency-pae"
        "3.2.0-33-virtual"
        "3.2.0-34-generic"
        "3.2.0-34-generic-pae"
        "3.2.0-34-virtual"
        "3.2.0-35-generic"
        "3.2.0-35-generic-pae"
        "3.2.0-35-lowlatency"
        "3.2.0-35-lowlatency-pae"
        "3.2.0-35-virtual"
        "3.2.0-36-generic"
        "3.2.0-36-generic-pae"
        "3.2.0-36-lowlatency"
        "3.2.0-36-lowlatency-pae"
        "3.2.0-36-virtual"
        "3.2.0-37-generic"
        "3.2.0-37-generic-pae"
        "3.2.0-37-lowlatency"
        "3.2.0-37-lowlatency-pae"
        "3.2.0-37-virtual"
        "3.2.0-38-generic"
        "3.2.0-38-generic-pae"
        "3.2.0-38-lowlatency"
        "3.2.0-38-lowlatency-pae"
        "3.2.0-38-virtual"
        "3.2.0-39-generic"
        "3.2.0-39-generic-pae"
        "3.2.0-39-lowlatency"
        "3.2.0-39-lowlatency-pae"
        "3.2.0-39-virtual"
        "3.2.0-40-generic"
        "3.2.0-40-generic-pae"
        "3.2.0-40-lowlatency"
        "3.2.0-40-lowlatency-pae"
        "3.2.0-40-virtual"
        "3.2.0-41-generic"
        "3.2.0-41-generic-pae"
        "3.2.0-41-lowlatency"
        "3.2.0-41-lowlatency-pae"
        "3.2.0-41-virtual"
        "3.2.0-43-generic"
        "3.2.0-43-generic-pae"
        "3.2.0-43-virtual"
        "3.2.0-44-generic"
        "3.2.0-44-generic-pae"
        "3.2.0-44-lowlatency"
        "3.2.0-44-lowlatency-pae"
        "3.2.0-44-virtual"
        "3.2.0-45-generic"
        "3.2.0-45-generic-pae"
        "3.2.0-45-virtual"
        "3.2.0-48-generic"
        "3.2.0-48-generic-pae"
        "3.2.0-48-lowlatency"
        "3.2.0-48-lowlatency-pae"
        "3.2.0-48-virtual"
        "3.2.0-51-generic"
        "3.2.0-51-generic-pae"
        "3.2.0-51-lowlatency"
        "3.2.0-51-lowlatency-pae"
        "3.2.0-51-virtual"
        "3.2.0-52-generic"
        "3.2.0-52-generic-pae"
        "3.2.0-52-lowlatency"
        "3.2.0-52-lowlatency-pae"
        "3.2.0-52-virtual"
        "3.2.0-53-generic"
        "3.2.0-53-generic-pae"
        "3.2.0-53-lowlatency"
        "3.2.0-53-lowlatency-pae"
        "3.2.0-53-virtual"
        "3.2.0-54-generic"
        "3.2.0-54-generic-pae"
        "3.2.0-54-lowlatency"
        "3.2.0-54-lowlatency-pae"
        "3.2.0-54-virtual"
        "3.2.0-55-generic"
        "3.2.0-55-generic-pae"
        "3.2.0-55-lowlatency"
        "3.2.0-55-lowlatency-pae"
        "3.2.0-55-virtual"
        "3.2.0-56-generic"
        "3.2.0-56-generic-pae"
        "3.2.0-56-lowlatency"
        "3.2.0-56-lowlatency-pae"
        "3.2.0-56-virtual"
        "3.2.0-57-generic"
        "3.2.0-57-generic-pae"
        "3.2.0-57-lowlatency"
        "3.2.0-57-lowlatency-pae"
        "3.2.0-57-virtual"
        "3.2.0-58-generic"
        "3.2.0-58-generic-pae"
        "3.2.0-58-lowlatency"
        "3.2.0-58-lowlatency-pae"
        "3.2.0-58-virtual"
        "3.2.0-59-generic"
        "3.2.0-59-generic-pae"
        "3.2.0-59-lowlatency"
        "3.2.0-59-lowlatency-pae"
        "3.2.0-59-virtual"
        "3.2.0-60-generic"
        "3.2.0-60-generic-pae"
        "3.2.0-60-lowlatency"
        "3.2.0-60-lowlatency-pae"
        "3.2.0-60-virtual"
        "3.2.0-61-generic"
        "3.2.0-61-generic-pae"
        "3.2.0-61-virtual"
        "3.2.0-63-generic"
        "3.2.0-63-generic-pae"
        "3.2.0-63-lowlatency"
        "3.2.0-63-lowlatency-pae"
        "3.2.0-63-virtual"
        "3.2.0-64-generic"
        "3.2.0-64-generic-pae"
        "3.2.0-64-lowlatency"
        "3.2.0-64-lowlatency-pae"
        "3.2.0-64-virtual"
        "3.2.0-65-generic"
        "3.2.0-65-generic-pae"
        "3.2.0-65-lowlatency"
        "3.2.0-65-lowlatency-pae"
        "3.2.0-65-virtual"
        "3.2.0-67-generic"
        "3.2.0-67-generic-pae"
        "3.2.0-67-lowlatency"
        "3.2.0-67-lowlatency-pae"
        "3.2.0-67-virtual"
        "3.2.0-68-generic"
        "3.2.0-68-generic-pae"
        "3.2.0-68-lowlatency"
        "3.2.0-68-lowlatency-pae"
        "3.2.0-68-virtual"
        "3.2.0-69-generic"
        "3.2.0-69-generic-pae"
        "3.2.0-69-lowlatency"
        "3.2.0-69-lowlatency-pae"
        "3.2.0-69-virtual"
        "3.2.0-70-generic"
        "3.2.0-70-generic-pae"
        "3.2.0-70-lowlatency"
        "3.2.0-70-lowlatency-pae"
        "3.2.0-70-virtual"
        "3.2.0-72-generic"
        "3.2.0-72-generic-pae"
        "3.2.0-72-lowlatency"
        "3.2.0-72-lowlatency-pae"
        "3.2.0-72-virtual"
        "3.2.0-73-generic"
        "3.2.0-73-generic-pae"
        "3.2.0-73-lowlatency"
        "3.2.0-73-lowlatency-pae"
        "3.2.0-73-virtual"
        "3.2.0-74-generic"
        "3.2.0-74-generic-pae"
        "3.2.0-74-lowlatency"
        "3.2.0-74-lowlatency-pae"
        "3.2.0-74-virtual"
        "3.2.0-75-generic"
        "3.2.0-75-generic-pae"
        "3.2.0-75-lowlatency"
        "3.2.0-75-lowlatency-pae"
        "3.2.0-75-virtual"
        "3.2.0-76-generic"
        "3.2.0-76-generic-pae"
        "3.2.0-76-lowlatency"
        "3.2.0-76-lowlatency-pae"
        "3.2.0-76-virtual"
        "3.2.0-77-generic"
        "3.2.0-77-generic-pae"
        "3.2.0-77-lowlatency"
        "3.2.0-77-lowlatency-pae"
        "3.2.0-77-virtual"
        "3.2.0-79-generic"
        "3.2.0-79-generic-pae"
        "3.2.0-79-lowlatency"
        "3.2.0-79-lowlatency-pae"
        "3.2.0-79-virtual"
        "3.2.0-80-generic"
        "3.2.0-80-generic-pae"
        "3.2.0-80-lowlatency"
        "3.2.0-80-lowlatency-pae"
        "3.2.0-80-virtual"
        "3.2.0-82-generic"
        "3.2.0-82-generic-pae"
        "3.2.0-82-lowlatency"
        "3.2.0-82-lowlatency-pae"
        "3.2.0-82-virtual"
        "3.2.0-83-generic"
        "3.2.0-83-generic-pae"
        "3.2.0-83-virtual"
        "3.2.0-84-generic"
        "3.2.0-84-generic-pae"
        "3.2.0-84-virtual"
        "3.2.0-85-generic"
        "3.2.0-85-generic-pae"
        "3.2.0-85-virtual"
        "3.2.0-86-generic"
        "3.2.0-86-generic-pae"
        "3.2.0-86-virtual"
        "3.2.0-87-generic"
        "3.2.0-87-generic-pae"
        "3.2.0-87-virtual"
        "3.2.0-88-generic"
        "3.2.0-88-generic-pae"
        "3.2.0-88-virtual"
        "3.2.0-89-generic"
        "3.2.0-89-generic-pae"
        "3.2.0-89-virtual"
        "3.2.0-90-generic"
        "3.2.0-90-generic-pae"
        "3.2.0-90-virtual"
        "3.2.0-91-generic"
        "3.2.0-91-generic-pae"
        "3.2.0-91-virtual"
        "3.2.0-92-generic"
        "3.2.0-92-generic-pae"
        "3.2.0-92-virtual"
        "3.2.0-93-generic"
        "3.2.0-93-generic-pae"
        "3.2.0-93-virtual"
        "3.2.0-94-generic"
        "3.2.0-94-generic-pae"
        "3.2.0-94-virtual"
        "3.2.0-95-generic"
        "3.2.0-95-generic-pae"
        "3.2.0-95-virtual"
        "3.2.0-96-generic"
        "3.2.0-96-generic-pae"
        "3.2.0-96-virtual"
        "3.2.0-97-generic"
        "3.2.0-97-generic-pae"
        "3.2.0-97-virtual"
        "3.2.0-98-generic"
        "3.2.0-98-generic-pae"
        "3.2.0-98-virtual"
        "3.2.0-99-generic"
        "3.2.0-99-generic-pae"
        "3.2.0-99-virtual"
        "3.5.0-40-generic"
        "3.5.0-41-generic"
        "3.5.0-42-generic"
        "3.5.0-43-generic"
        "3.5.0-44-generic"
        "3.5.0-45-generic"
        "3.5.0-46-generic"
        "3.5.0-49-generic"
        "3.5.0-51-generic"
        "3.5.0-52-generic"
        "3.5.0-54-generic"
        "3.8.0-19-generic"
        "3.8.0-21-generic"
        "3.8.0-22-generic"
        "3.8.0-23-generic"
        "3.8.0-27-generic"
        "3.8.0-29-generic"
        "3.8.0-30-generic"
        "3.8.0-31-generic"
        "3.8.0-32-generic"
        "3.8.0-33-generic"
        "3.8.0-34-generic"
        "3.8.0-35-generic"
        "3.8.0-36-generic"
        "3.8.0-37-generic"
        "3.8.0-38-generic"
        "3.8.0-39-generic"
        "3.8.0-41-generic"
        "3.8.0-42-generic"

        # Ubuntu Trusty
        "3.13.0-24-generic"
        "3.13.0-24-generic-lpae"
        "3.13.0-24-lowlatency"
        "3.13.0-24-powerpc-e500"
        "3.13.0-24-powerpc-e500mc"
        "3.13.0-24-powerpc-smp"
        "3.13.0-24-powerpc64-emb"
        "3.13.0-24-powerpc64-smp"
        "3.13.0-27-generic"
        "3.13.0-27-lowlatency"
        "3.13.0-29-generic"
        "3.13.0-29-lowlatency"
        "3.13.0-3-exynos5"
        "3.13.0-30-generic"
        "3.13.0-30-lowlatency"
        "3.13.0-32-generic"
        "3.13.0-32-lowlatency"
        "3.13.0-33-generic"
        "3.13.0-33-lowlatency"
        "3.13.0-34-generic"
        "3.13.0-34-lowlatency"
        "3.13.0-35-generic"
        "3.13.0-35-lowlatency"
        "3.13.0-36-generic"
        "3.13.0-36-lowlatency"
        "3.13.0-37-generic"
        "3.13.0-37-lowlatency"
        "3.13.0-39-generic"
        "3.13.0-39-lowlatency"
        "3.13.0-40-generic"
        "3.13.0-40-lowlatency"
        "3.13.0-41-generic"
        "3.13.0-41-lowlatency"
        "3.13.0-43-generic"
        "3.13.0-43-lowlatency"
        "3.13.0-44-generic"
        "3.13.0-44-lowlatency"
        "3.13.0-46-generic"
        "3.13.0-46-lowlatency"
        "3.13.0-48-generic"
        "3.13.0-48-lowlatency"
        "3.13.0-49-generic"
        "3.13.0-49-lowlatency"
        "3.13.0-51-generic"
        "3.13.0-51-lowlatency"
        "3.13.0-52-generic"
        "3.13.0-52-lowlatency"
        "3.13.0-53-generic"
        "3.13.0-53-lowlatency"
        "3.13.0-54-generic"
        "3.13.0-54-lowlatency"
        "3.13.0-55-generic"
        "3.13.0-55-lowlatency"
        "3.13.0-57-generic"
        "3.13.0-57-lowlatency"
        "3.13.0-58-generic"
        "3.13.0-58-lowlatency"
        "3.13.0-59-generic"
        "3.13.0-59-lowlatency"
        "3.13.0-61-generic"
        "3.13.0-61-lowlatency"
        "3.13.0-62-generic"
        "3.13.0-62-lowlatency"
        "3.13.0-63-generic"
        "3.13.0-63-lowlatency"
        "3.13.0-65-generic"
        "3.13.0-65-lowlatency"
        "3.13.0-66-generic"
        "3.13.0-66-lowlatency"
        "3.13.0-67-generic"
        "3.13.0-67-lowlatency"
        "3.13.0-68-generic"
        "3.13.0-68-lowlatency"
        "3.13.0-70-generic"
        "3.13.0-70-lowlatency"
        "3.13.0-71-generic"
        "3.13.0-71-lowlatency"
        "3.13.0-73-generic"
        "3.13.0-73-lowlatency"
        "3.13.0-74-generic"
        "3.13.0-74-lowlatency"
        "3.13.0-76-generic"
        "3.13.0-76-lowlatency"
        "3.13.0-77-generic"
        "3.13.0-77-lowlatency"
        "3.13.0-79-generic"
        "3.13.0-79-lowlatency"
        "3.13.0-83-generic"
        "3.13.0-83-lowlatency"
        "3.13.0-85-generic"
        "3.13.0-85-lowlatency"
        "3.13.0-86-generic"
        "3.13.0-86-lowlatency"
        "3.13.0-87-generic"
        "3.13.0-87-lowlatency"
        "3.13.0-88-generic"
        "3.13.0-88-lowlatency"
        "3.13.0-91-generic"
        "3.13.0-91-lowlatency"
        "3.13.0-92-generic"
        "3.13.0-92-lowlatency"
        "3.13.0-93-generic"
        "3.13.0-93-lowlatency"
        "3.13.0-95-generic"
        "3.13.0-95-lowlatency"
        "3.13.0-96-generic"
        "3.13.0-96-lowlatency"
        "3.13.0-98-generic"
        "3.13.0-98-lowlatency"
        "3.16.0-25-generic"
        "3.16.0-25-lowlatency"
        "3.16.0-26-generic"
        "3.16.0-26-lowlatency"
        "3.16.0-28-generic"
        "3.16.0-28-lowlatency"
        "3.16.0-29-generic"
        "3.16.0-29-lowlatency"
        "3.16.0-31-generic"
        "3.16.0-31-lowlatency"
        "3.16.0-33-generic"
        "3.16.0-33-lowlatency"
        "3.16.0-34-generic"
        "3.16.0-34-lowlatency"
        "3.16.0-36-generic"
        "3.16.0-36-lowlatency"
        "3.16.0-37-generic"
        "3.16.0-37-lowlatency"
        "3.16.0-38-generic"
        "3.16.0-38-lowlatency"
        "3.16.0-39-generic"
        "3.16.0-39-lowlatency"
        "3.16.0-41-generic"
        "3.16.0-41-lowlatency"
        "3.16.0-43-generic"
        "3.16.0-43-lowlatency"
        "3.16.0-44-generic"
        "3.16.0-44-lowlatency"
        "3.16.0-45-generic"
        "3.16.0-45-lowlatency"
        "3.16.0-46-generic"
        "3.16.0-46-lowlatency"
        "3.16.0-48-generic"
        "3.16.0-48-lowlatency"
        "3.16.0-49-generic"
        "3.16.0-49-lowlatency"
        "3.16.0-50-generic"
        "3.16.0-50-lowlatency"
        "3.16.0-51-generic"
        "3.16.0-51-lowlatency"
        "3.16.0-52-generic"
        "3.16.0-52-lowlatency"
        "3.16.0-53-generic"
        "3.16.0-53-lowlatency"
        "3.16.0-55-generic"
        "3.16.0-55-lowlatency"
        "3.16.0-56-generic"
        "3.16.0-56-lowlatency"
        "3.16.0-57-generic"
        "3.16.0-57-lowlatency"
        "3.16.0-59-generic"
        "3.16.0-59-lowlatency"
        "3.16.0-60-generic"
        "3.16.0-60-lowlatency"
        "3.16.0-62-generic"
        "3.16.0-62-lowlatency"
        "3.16.0-67-generic"
        "3.16.0-67-lowlatency"
        "3.16.0-69-generic"
        "3.16.0-69-lowlatency"
        "3.16.0-70-generic"
        "3.16.0-70-lowlatency"
        "3.16.0-71-generic"
        "3.16.0-71-lowlatency"
        "3.16.0-73-generic"
        "3.16.0-73-lowlatency"
        "3.16.0-76-generic"
        "3.16.0-76-lowlatency"
        "3.16.0-77-generic"
        "3.16.0-77-lowlatency"
        "3.19.0-20-generic"
        "3.19.0-20-lowlatency"
        "3.19.0-21-generic"
        "3.19.0-21-lowlatency"
        "3.19.0-22-generic"
        "3.19.0-22-lowlatency"
        "3.19.0-23-generic"
        "3.19.0-23-lowlatency"
        "3.19.0-25-generic"
        "3.19.0-25-lowlatency"
        "3.19.0-26-generic"
        "3.19.0-26-lowlatency"
        "3.19.0-28-generic"
        "3.19.0-28-lowlatency"
        "3.19.0-30-generic"
        "3.19.0-30-lowlatency"
        "3.19.0-31-generic"
        "3.19.0-31-lowlatency"
        "3.19.0-32-generic"
        "3.19.0-32-lowlatency"
        "3.19.0-33-generic"
        "3.19.0-33-lowlatency"
        "3.19.0-37-generic"
        "3.19.0-37-lowlatency"
        "3.19.0-39-generic"
        "3.19.0-39-lowlatency"
        "3.19.0-41-generic"
        "3.19.0-41-lowlatency"
        "3.19.0-42-generic"
        "3.19.0-42-lowlatency"
        "3.19.0-43-generic"
        "3.19.0-43-lowlatency"
        "3.19.0-47-generic"
        "3.19.0-47-lowlatency"
        "3.19.0-49-generic"
        "3.19.0-49-lowlatency"
        "3.19.0-51-generic"
        "3.19.0-51-lowlatency"
        "3.19.0-56-generic"
        "3.19.0-56-lowlatency"
        "3.19.0-58-generic"
        "3.19.0-58-lowlatency"
        "3.19.0-59-generic"
        "3.19.0-59-lowlatency"
        "3.19.0-61-generic"
        "3.19.0-61-lowlatency"
        "3.19.0-64-generic"
        "3.19.0-64-lowlatency"
        "3.19.0-65-generic"
        "3.19.0-65-lowlatency"
        "3.19.0-66-generic"
        "3.19.0-66-lowlatency"
        "3.19.0-68-generic"
        "3.19.0-68-lowlatency"
        "3.19.0-69-generic"
        "3.19.0-69-lowlatency"
        "3.19.0-71-generic"
        "3.19.0-71-lowlatency"
        "3.4.0-5-chromebook"
        "4.2.0-18-generic"
        "4.2.0-18-lowlatency"
        "4.2.0-19-generic"
        "4.2.0-19-lowlatency"
        "4.2.0-21-generic"
        "4.2.0-21-lowlatency"
        "4.2.0-22-generic"
        "4.2.0-22-lowlatency"
        "4.2.0-23-generic"
        "4.2.0-23-lowlatency"
        "4.2.0-25-generic"
        "4.2.0-25-lowlatency"
        "4.2.0-27-generic"
        "4.2.0-27-lowlatency"
        "4.2.0-30-generic"
        "4.2.0-30-lowlatency"
        "4.2.0-34-generic"
        "4.2.0-34-lowlatency"
        "4.2.0-35-generic"
        "4.2.0-35-lowlatency"
        "4.2.0-36-generic"
        "4.2.0-36-lowlatency"
        "4.2.0-38-generic"
        "4.2.0-38-lowlatency"
        "4.2.0-41-generic"
        "4.2.0-41-lowlatency"
        "4.4.0-21-generic"
        "4.4.0-21-lowlatency"
        "4.4.0-22-generic"
        "4.4.0-22-lowlatency"
        "4.4.0-24-generic"
        "4.4.0-24-lowlatency"
        "4.4.0-28-generic"
        "4.4.0-28-lowlatency"
        "4.4.0-31-generic"
        "4.4.0-31-lowlatency"
        "4.4.0-34-generic"
        "4.4.0-34-lowlatency"
        "4.4.0-36-generic"
        "4.4.0-36-lowlatency"
        "4.4.0-38-generic"
        "4.4.0-38-lowlatency"
        "4.4.0-42-generic"
        "4.4.0-42-lowlatency"

        # Ubuntu Xenial
        "4.4.0-1009-raspi2"
        "4.4.0-1012-snapdragon"
        "4.4.0-21-generic"
        "4.4.0-21-generic-lpae"
        "4.4.0-21-lowlatency"
        "4.4.0-21-powerpc-e500mc"
        "4.4.0-21-powerpc-smp"
        "4.4.0-21-powerpc64-emb"
        "4.4.0-21-powerpc64-smp"
        "4.4.0-22-generic"
        "4.4.0-22-lowlatency"
        "4.4.0-24-generic"
        "4.4.0-24-lowlatency"
        "4.4.0-28-generic"
        "4.4.0-28-lowlatency"
        "4.4.0-31-generic"
        "4.4.0-31-lowlatency"
        "4.4.0-34-generic"
        "4.4.0-34-lowlatency"
        "4.4.0-36-generic"
        "4.4.0-36-lowlatency"
        "4.4.0-38-generic"
        "4.4.0-38-lowlatency"
        "4.4.0-42-generic"
        "4.4.0-42-lowlatency"

        # RHEL5
        "2.6.18-8.1.1.el5"
        "2.6.18-8.1.3.el5"
        "2.6.18-8.1.4.el5"
        "2.6.18-8.1.6.el5"
        "2.6.18-8.1.8.el5"
        "2.6.18-8.1.10.el5"
        "2.6.18-8.1.14.el5"
        "2.6.18-8.1.15.el5"
        "2.6.18-53.el5"
        "2.6.18-53.1.4.el5"
        "2.6.18-53.1.6.el5"
        "2.6.18-53.1.13.el5"
        "2.6.18-53.1.14.el5"
        "2.6.18-53.1.19.el5"
        "2.6.18-53.1.21.el5"
        "2.6.18-92.el5"
        "2.6.18-92.1.1.el5"
        "2.6.18-92.1.6.el5"
        "2.6.18-92.1.10.el5"
        "2.6.18-92.1.13.el5"
        "2.6.18-92.1.18.el5"
        "2.6.18-92.1.22.el5"
        "2.6.18-92.1.24.el5"
        "2.6.18-92.1.26.el5"
        "2.6.18-92.1.27.el5"
        "2.6.18-92.1.28.el5"
        "2.6.18-92.1.29.el5"
        "2.6.18-92.1.32.el5"
        "2.6.18-92.1.35.el5"
        "2.6.18-92.1.38.el5"
        "2.6.18-128.el5"
        "2.6.18-128.1.1.el5"
        "2.6.18-128.1.6.el5"
        "2.6.18-128.1.10.el5"
        "2.6.18-128.1.14.el5"
        "2.6.18-128.1.16.el5"
        "2.6.18-128.2.1.el5"
        "2.6.18-128.4.1.el5"
        "2.6.18-128.4.1.el5"
        "2.6.18-128.7.1.el5"
        "2.6.18-128.8.1.el5"
        "2.6.18-128.11.1.el5"
        "2.6.18-128.12.1.el5"
        "2.6.18-128.14.1.el5"
        "2.6.18-128.16.1.el5"
        "2.6.18-128.17.1.el5"
        "2.6.18-128.18.1.el5"
        "2.6.18-128.23.1.el5"
        "2.6.18-128.23.2.el5"
        "2.6.18-128.25.1.el5"
        "2.6.18-128.26.1.el5"
        "2.6.18-128.27.1.el5"
        "2.6.18-128.29.1.el5"
        "2.6.18-128.30.1.el5"
        "2.6.18-128.31.1.el5"
        "2.6.18-128.32.1.el5"
        "2.6.18-128.35.1.el5"
        "2.6.18-128.36.1.el5"
        "2.6.18-128.37.1.el5"
        "2.6.18-128.38.1.el5"
        "2.6.18-128.39.1.el5"
        "2.6.18-128.40.1.el5"
        "2.6.18-128.41.1.el5"
        "2.6.18-164.el5"
        "2.6.18-164.2.1.el5"
        "2.6.18-164.6.1.el5"
        "2.6.18-164.9.1.el5"
        "2.6.18-164.10.1.el5"
        "2.6.18-164.11.1.el5"
        "2.6.18-164.15.1.el5"
        "2.6.18-164.17.1.el5"
        "2.6.18-164.19.1.el5"
        "2.6.18-164.21.1.el5"
        "2.6.18-164.25.1.el5"
        "2.6.18-164.25.2.el5"
        "2.6.18-164.28.1.el5"
        "2.6.18-164.30.1.el5"
        "2.6.18-164.32.1.el5"
        "2.6.18-164.34.1.el5"
        "2.6.18-164.36.1.el5"
        "2.6.18-164.37.1.el5"
        "2.6.18-164.38.1.el5"
        "2.6.18-194.el5"
        "2.6.18-194.3.1.el5"
        "2.6.18-194.8.1.el5"
        "2.6.18-194.11.1.el5"
        "2.6.18-194.11.3.el5"
        "2.6.18-194.11.4.el5"
        "2.6.18-194.17.1.el5"
        "2.6.18-194.17.4.el5"
        "2.6.18-194.26.1.el5"
        "2.6.18-194.32.1.el5"
        "2.6.18-238.el5"
        "2.6.18-238.1.1.el5"
        "2.6.18-238.5.1.el5"
        "2.6.18-238.9.1.el5"
        "2.6.18-238.12.1.el5"
        "2.6.18-238.19.1.el5"
        "2.6.18-238.21.1.el5"
        "2.6.18-238.27.1.el5"
        "2.6.18-238.28.1.el5"
        "2.6.18-238.31.1.el5"
        "2.6.18-238.33.1.el5"
        "2.6.18-238.35.1.el5"
        "2.6.18-238.37.1.el5"
        "2.6.18-238.39.1.el5"
        "2.6.18-238.40.1.el5"
        "2.6.18-238.44.1.el5"
        "2.6.18-238.45.1.el5"
        "2.6.18-238.47.1.el5"
        "2.6.18-238.48.1.el5"
        "2.6.18-238.49.1.el5"
        "2.6.18-238.50.1.el5"
        "2.6.18-238.51.1.el5"
        "2.6.18-238.52.1.el5"
        "2.6.18-238.53.1.el5"
        "2.6.18-238.54.1.el5"
        "2.6.18-238.55.1.el5"
        "2.6.18-238.56.1.el5"
        "2.6.18-274.el5"
        "2.6.18-274.3.1.el5"
        "2.6.18-274.7.1.el5"
        "2.6.18-274.12.1.el5"
        "2.6.18-274.17.1.el5"
        "2.6.18-274.18.1.el5"
        "2.6.18-308.el5"
        "2.6.18-308.1.1.el5"
        "2.6.18-308.4.1.el5"
        "2.6.18-308.8.1.el5"
        "2.6.18-308.8.2.el5"
        "2.6.18-308.11.1.el5"
        "2.6.18-308.13.1.el5"
        "2.6.18-308.16.1.el5"
        "2.6.18-308.20.1.el5"
        "2.6.18-308.24.1.el5"
        "2.6.18-348.el5"
        "2.6.18-348.1.1.el5"
        "2.6.18-348.2.1.el5"
        "2.6.18-348.3.1.el5"
        "2.6.18-348.4.1.el5"
        "2.6.18-348.6.1.el5"
        "2.6.18-348.12.1.el5"
        "2.6.18-348.16.1.el5"
        "2.6.18-348.18.1.el5"
        "2.6.18-348.19.1.el5"
        "2.6.18-348.21.1.el5"
        "2.6.18-348.22.1.el5"
        "2.6.18-348.23.1.el5"
        "2.6.18-348.25.1.el5"
        "2.6.18-348.27.1.el5"
        "2.6.18-348.28.1.el5"
        "2.6.18-348.29.1.el5"
        "2.6.18-348.30.1.el5"
        "2.6.18-348.31.2.el5"
        "2.6.18-371.el5"
        "2.6.18-371.1.2.el5"
        "2.6.18-371.3.1.el5"
        "2.6.18-371.4.1.el5"
        "2.6.18-371.6.1.el5"
        "2.6.18-371.8.1.el5"
        "2.6.18-371.9.1.el5"
        "2.6.18-371.11.1.el5"
        "2.6.18-371.12.1.el5"
        "2.6.18-398.el5"
        "2.6.18-400.el5"
        "2.6.18-400.1.1.el5"
        "2.6.18-402.el5"
        "2.6.18-404.el5"
        "2.6.18-406.el5"
        "2.6.18-407.el5"
        "2.6.18-408.el5"
        "2.6.18-409.el5"
        "2.6.18-410.el5"
        "2.6.18-411.el5"
        "2.6.18-412.el5"

        # RHEL6
        "2.6.32-71.7.1.el6"
        "2.6.32-71.14.1.el6"
        "2.6.32-71.18.1.el6"
        "2.6.32-71.18.2.el6"
        "2.6.32-71.24.1.el6"
        "2.6.32-71.29.1.el6"
        "2.6.32-71.31.1.el6"
        "2.6.32-71.34.1.el6"
        "2.6.32-71.35.1.el6"
        "2.6.32-71.36.1.el6"
        "2.6.32-71.37.1.el6"
        "2.6.32-71.38.1.el6"
        "2.6.32-71.39.1.el6"
        "2.6.32-71.40.1.el6"
        "2.6.32-131.0.15.el6"
        "2.6.32-131.2.1.el6"
        "2.6.32-131.4.1.el6"
        "2.6.32-131.6.1.el6"
        "2.6.32-131.12.1.el6"
        "2.6.32-131.17.1.el6"
        "2.6.32-131.21.1.el6"
        "2.6.32-131.22.1.el6"
        "2.6.32-131.25.1.el6"
        "2.6.32-131.26.1.el6"
        "2.6.32-131.28.1.el6"
        "2.6.32-131.29.1.el6"
        "2.6.32-131.30.1.el6"
        "2.6.32-131.30.2.el6"
        "2.6.32-131.33.1.el6"
        "2.6.32-131.35.1.el6"
        "2.6.32-131.36.1.el6"
        "2.6.32-131.37.1.el6"
        "2.6.32-131.38.1.el6"
        "2.6.32-131.39.1.el6"
        "2.6.32-220.el6"
        "2.6.32-220.2.1.el6"
        "2.6.32-220.4.1.el6"
        "2.6.32-220.4.2.el6"
        "2.6.32-220.4.7.bgq.el6"
        "2.6.32-220.7.1.el6"
        "2.6.32-220.7.3.p7ih.el6"
        "2.6.32-220.7.4.p7ih.el6"
        "2.6.32-220.7.6.p7ih.el6"
        "2.6.32-220.7.7.p7ih.el6"
        "2.6.32-220.13.1.el6"
        "2.6.32-220.17.1.el6"
        "2.6.32-220.23.1.el6"
        "2.6.32-220.24.1.el6"
        "2.6.32-220.25.1.el6"
        "2.6.32-220.26.1.el6"
        "2.6.32-220.28.1.el6"
        "2.6.32-220.30.1.el6"
        "2.6.32-220.31.1.el6"
        "2.6.32-220.32.1.el6"
        "2.6.32-220.34.1.el6"
        "2.6.32-220.34.2.el6"
        "2.6.32-220.38.1.el6"
        "2.6.32-220.39.1.el6"
        "2.6.32-220.41.1.el6"
        "2.6.32-220.42.1.el6"
        "2.6.32-220.45.1.el6"
        "2.6.32-220.46.1.el6"
        "2.6.32-220.48.1.el6"
        "2.6.32-220.51.1.el6"
        "2.6.32-220.52.1.el6"
        "2.6.32-220.53.1.el6"
        "2.6.32-220.54.1.el6"
        "2.6.32-220.55.1.el6"
        "2.6.32-220.56.1.el6"
        "2.6.32-220.57.1.el6"
        "2.6.32-220.58.1.el6"
        "2.6.32-220.60.2.el6"
        "2.6.32-220.62.1.el6"
        "2.6.32-220.63.2.el6"
        "2.6.32-220.64.1.el6"
        "2.6.32-220.65.1.el6"
        "2.6.32-220.66.1.el6"
        "2.6.32-220.67.1.el6"
        "2.6.32-279.el6"
        "2.6.32-279.1.1.el6"
        "2.6.32-279.2.1.el6"
        "2.6.32-279.5.1.el6"
        "2.6.32-279.5.2.el6"
        "2.6.32-279.9.1.el6"
        "2.6.32-279.11.1.el6"
        "2.6.32-279.14.1.bgq.el6"
        "2.6.32-279.14.1.el6"
        "2.6.32-279.19.1.el6"
        "2.6.32-279.22.1.el6"
        "2.6.32-279.23.1.el6"
        "2.6.32-279.25.1.el6"
        "2.6.32-279.25.2.el6"
        "2.6.32-279.31.1.el6"
        "2.6.32-279.33.1.el6"
        "2.6.32-279.34.1.el6"
        "2.6.32-279.37.2.el6"
        "2.6.32-279.39.1.el6"
        "2.6.32-279.41.1.el6"
        "2.6.32-279.42.1.el6"
        "2.6.32-279.43.1.el6"
        "2.6.32-279.43.2.el6"
        "2.6.32-279.46.1.el6"
        "2.6.32-358.el6"
        "2.6.32-358.0.1.el6"
        "2.6.32-358.2.1.el6"
        "2.6.32-358.6.1.el6"
        "2.6.32-358.6.2.el6"
        "2.6.32-358.6.3.p7ih.el6"
        "2.6.32-358.11.1.bgq.el6"
        "2.6.32-358.11.1.el6"
        "2.6.32-358.14.1.el6"
        "2.6.32-358.18.1.el6"
        "2.6.32-358.23.2.el6"
        "2.6.32-358.28.1.el6"
        "2.6.32-358.32.3.el6"
        "2.6.32-358.37.1.el6"
        "2.6.32-358.41.1.el6"
        "2.6.32-358.44.1.el6"
        "2.6.32-358.46.1.el6"
        "2.6.32-358.46.2.el6"
        "2.6.32-358.48.1.el6"
        "2.6.32-358.49.1.el6"
        "2.6.32-358.51.1.el6"
        "2.6.32-358.51.2.el6"
        "2.6.32-358.55.1.el6"
        "2.6.32-358.56.1.el6"
        "2.6.32-358.59.1.el6"
        "2.6.32-358.61.1.el6"
        "2.6.32-358.62.1.el6"
        "2.6.32-358.65.1.el6"
        "2.6.32-358.67.1.el6"
        "2.6.32-358.68.1.el6"
        "2.6.32-358.69.1.el6"
        "2.6.32-358.70.1.el6"
        "2.6.32-358.71.1.el6"
        "2.6.32-358.72.1.el6"
        "2.6.32-358.73.1.el6"
        "2.6.32-358.111.1.openstack.el6"
        "2.6.32-358.114.1.openstack.el6"
        "2.6.32-358.118.1.openstack.el6"
        "2.6.32-358.123.4.openstack.el6"
        "2.6.32-431.el6"
        "2.6.32-431.1.1.bgq.el6"
        "2.6.32-431.1.2.el6"
        "2.6.32-431.3.1.el6"
        "2.6.32-431.5.1.el6"
        "2.6.32-431.11.2.el6"
        "2.6.32-431.17.1.el6"
        "2.6.32-431.20.3.el6"
        "2.6.32-431.20.5.el6"
        "2.6.32-431.23.3.el6"
        "2.6.32-431.29.2.el6"
        "2.6.32-431.37.1.el6"
        "2.6.32-431.40.1.el6"
        "2.6.32-431.40.2.el6"
        "2.6.32-431.46.2.el6"
        "2.6.32-431.50.1.el6"
        "2.6.32-431.53.2.el6"
        "2.6.32-431.56.1.el6"
        "2.6.32-431.59.1.el6"
        "2.6.32-431.61.2.el6"
        "2.6.32-431.64.1.el6"
        "2.6.32-431.66.1.el6"
        "2.6.32-431.68.1.el6"
        "2.6.32-431.69.1.el6"
        "2.6.32-431.70.1.el6"
        "2.6.32-431.71.1.el6"
        "2.6.32-431.72.1.el6"
        "2.6.32-431.73.2.el6"
        "2.6.32-431.74.1.el6"
        "2.6.32-504.el6"
        "2.6.32-504.1.3.el6"
        "2.6.32-504.3.3.el6"
        "2.6.32-504.8.1.el6"
        "2.6.32-504.8.2.bgq.el6"
        "2.6.32-504.12.2.el6"
        "2.6.32-504.16.2.el6"
        "2.6.32-504.23.4.el6"
        "2.6.32-504.30.3.el6"
        "2.6.32-504.30.5.p7ih.el6"
        "2.6.32-504.33.2.el6"
        "2.6.32-504.36.1.el6"
        "2.6.32-504.38.1.el6"
        "2.6.32-504.40.1.el6"
        "2.6.32-504.43.1.el6"
        "2.6.32-504.46.1.el6"
        "2.6.32-504.49.1.el6"
        "2.6.32-504.50.1.el6"
        "2.6.32-504.51.1.el6"
        "2.6.32-504.52.1.el6"
        "2.6.32-573.el6"
        "2.6.32-573.1.1.el6"
        "2.6.32-573.3.1.el6"
        "2.6.32-573.4.2.bgq.el6"
        "2.6.32-573.7.1.el6"
        "2.6.32-573.8.1.el6"
        "2.6.32-573.12.1.el6"
        "2.6.32-573.18.1.el6"
        "2.6.32-573.22.1.el6"
        "2.6.32-573.26.1.el6"
        "2.6.32-573.30.1.el6"
        "2.6.32-573.32.1.el6"
        "2.6.32-573.34.1.el6"
        "2.6.32-642.el6"
        "2.6.32-642.1.1.el6"
        "2.6.32-642.3.1.el6"
        "2.6.32-642.4.2.el6"
        "2.6.32-642.6.1.el6"

        # RHEL7
        "3.10.0-123.el7"
        "3.10.0-123.1.2.el7"
        "3.10.0-123.4.2.el7"
        "3.10.0-123.4.4.el7"
        "3.10.0-123.6.3.el7"
        "3.10.0-123.8.1.el7"
        "3.10.0-123.9.2.el7"
        "3.10.0-123.9.3.el7"
        "3.10.0-123.13.1.el7"
        "3.10.0-123.13.2.el7"
        "3.10.0-123.20.1.el7"
        "3.10.0-229.el7"
        "3.10.0-229.1.2.el7"
        "3.10.0-229.4.2.el7"
        "3.10.0-229.7.2.el7"
        "3.10.0-229.11.1.el7"
        "3.10.0-229.14.1.el7"
        "3.10.0-229.20.1.el7"
        "3.10.0-229.24.2.el7"
        "3.10.0-229.26.2.el7"
        "3.10.0-229.28.1.el7"
        "3.10.0-229.30.1.el7"
        "3.10.0-229.34.1.el7"
        "3.10.0-229.38.1.el7"
        "3.10.0-229.40.1.el7"
        "3.10.0-229.42.1.el7"
        "3.10.0-327.el7"
        "3.10.0-327.3.1.el7"
        "3.10.0-327.4.4.el7"
        "3.10.0-327.4.5.el7"
        "3.10.0-327.10.1.el7"
        "3.10.0-327.13.1.el7"
        "3.10.0-327.18.2.el7"
        "3.10.0-327.22.2.el7"
        "3.10.0-327.28.2.el7"
        "3.10.0-327.28.3.el7"
        "3.10.0-327.36.1.el7"
        "3.10.0-327.36.2.el7"
        "3.10.0-229.1.2.ael7b"
        "3.10.0-229.4.2.ael7b"
        "3.10.0-229.7.2.ael7b"
        "3.10.0-229.11.1.ael7b"
        "3.10.0-229.14.1.ael7b"
        "3.10.0-229.20.1.ael7b"
        "3.10.0-229.24.2.ael7b"
        "3.10.0-229.26.2.ael7b"
        "3.10.0-229.28.1.ael7b"
        "3.10.0-229.30.1.ael7b"
        "3.10.0-229.34.1.ael7b"
        "3.10.0-229.38.1.ael7b"
        "3.10.0-229.40.1.ael7b"
        "3.10.0-229.42.1.ael7b"
        "4.2.0-0.21.el7"

        # RHEL5
        "2.6.24.7-74.el5rt"
        "2.6.24.7-81.el5rt"
        "2.6.24.7-93.el5rt"
        "2.6.24.7-101.el5rt"
        "2.6.24.7-108.el5rt"
        "2.6.24.7-111.el5rt"
        "2.6.24.7-117.el5rt"
        "2.6.24.7-126.el5rt"
        "2.6.24.7-132.el5rt"
        "2.6.24.7-137.el5rt"
        "2.6.24.7-139.el5rt"
        "2.6.24.7-146.el5rt"
        "2.6.24.7-149.el5rt"
        "2.6.24.7-161.el5rt"
        "2.6.24.7-169.el5rt"
        "2.6.33.7-rt29.45.el5rt"
        "2.6.33.7-rt29.47.el5rt"
        "2.6.33.7-rt29.55.el5rt"
        "2.6.33.9-rt31.64.el5rt"
        "2.6.33.9-rt31.67.el5rt"
        "2.6.33.9-rt31.86.el5rt"

        # RHEL6
        "2.6.33.9-rt31.66.el6rt"
        "2.6.33.9-rt31.74.el6rt"
        "2.6.33.9-rt31.75.el6rt"
        "2.6.33.9-rt31.79.el6rt"
        "3.0.9-rt26.45.el6rt"
        "3.0.9-rt26.46.el6rt"
        "3.0.18-rt34.53.el6rt"
        "3.0.25-rt44.57.el6rt"
        "3.0.30-rt50.62.el6rt"
        "3.0.36-rt57.66.el6rt"
        "3.2.23-rt37.56.el6rt"
        "3.2.33-rt50.66.el6rt"
        "3.6.11-rt28.20.el6rt"
        "3.6.11-rt30.25.el6rt"
        "3.6.11.2-rt33.39.el6rt"
        "3.6.11.5-rt37.55.el6rt"
        "3.8.13-rt14.20.el6rt"
        "3.8.13-rt14.25.el6rt"
        "3.8.13-rt27.33.el6rt"
        "3.8.13-rt27.34.el6rt"
        "3.8.13-rt27.40.el6rt"
        "3.10.0-229.rt56.144.el6rt"
        "3.10.0-229.rt56.147.el6rt"
        "3.10.0-229.rt56.149.el6rt"
        "3.10.0-229.rt56.151.el6rt"
        "3.10.0-229.rt56.153.el6rt"
        "3.10.0-229.rt56.158.el6rt"
        "3.10.0-229.rt56.161.el6rt"
        "3.10.0-229.rt56.162.el6rt"
        "3.10.0-327.rt56.170.el6rt"
        "3.10.0-327.rt56.171.el6rt"
        "3.10.0-327.rt56.176.el6rt"
        "3.10.0-327.rt56.183.el6rt"
        "3.10.0-327.rt56.190.el6rt"
        "3.10.0-327.rt56.194.el6rt"
        "3.10.0-327.rt56.195.el6rt"
        "3.10.0-327.rt56.197.el6rt"
        "3.10.33-rt32.33.el6rt"
        "3.10.33-rt32.34.el6rt"
        "3.10.33-rt32.43.el6rt"
        "3.10.33-rt32.45.el6rt"
        "3.10.33-rt32.51.el6rt"
        "3.10.33-rt32.52.el6rt"
        "3.10.58-rt62.58.el6rt"
        "3.10.58-rt62.60.el6rt"

        # RHEL7
        "3.10.0-229.rt56.141.el7"
        "3.10.0-229.1.2.rt56.141.2.el7_1"
        "3.10.0-229.4.2.rt56.141.6.el7_1"
        "3.10.0-229.7.2.rt56.141.6.el7_1"
        "3.10.0-229.11.1.rt56.141.11.el7_1"
        "3.10.0-229.14.1.rt56.141.13.el7_1"
        "3.10.0-229.20.1.rt56.141.14.el7_1"
        "3.10.0-229.rt56.141.el7"
        "3.10.0-327.rt56.204.el7"
        "3.10.0-327.4.5.rt56.206.el7_2"
        "3.10.0-327.10.1.rt56.211.el7_2"
        "3.10.0-327.13.1.rt56.216.el7_2"
        "3.10.0-327.18.2.rt56.223.el7_2"
        "3.10.0-327.22.2.rt56.230.el7_2"
        "3.10.0-327.28.2.rt56.234.el7_2"
        "3.10.0-327.28.3.rt56.235.el7"
        "3.10.0-327.36.1.rt56.237.el7"
    )

    KPATCH_MODULE_NAMES=(
        "kpatch_3_10_0_327_36_1_1_1"
        "kpatch_3_10_0_327_36_2_1_1"
    )

    VALID_OS=(
        "precise"
        "trusty"
        "xenial"
        "5"
        "6"
        "7"
    )

    getKernel()
    {
        # Get current Kerenl
        running_kernel=$( uname -r )
    }

    collectSystemStats()
    {
        # 获取系统详细信息
        if [ -f /etc/lsb-release ]; then
            # 如果存在 /etc/lsb-release 文件，则加载该文件
            . /etc/lsb-release
            # 设置操作系统名称
            OS=$DISTRIB_ID
            # 设置操作系统版本代号
            VER=$DISTRIB_CODENAME
            # 获取可更新的内核版本（适用于基于Debian的系统，如Ubuntu）
            UPDATE_VERSION=$(apt-cache policy linux-image-server | grep Candidate | awk -F': ' '{print $2}' | awk -F'.' '{print $1 "." $2 "." $3 "-" $4 "-generic"}')
        elif [ -f /etc/os-release ]; then
            # 如果存在 /etc/os-release 文件，则加载该文件
            . /etc/os-release
            # 设置操作系统名称（对于Red Hat系统）
            OS=$REDHAT_SUPPORT_PRODUCT
            # 设置操作系统版本
            VER=$REDHAT_SUPPORT_PRODUCT_VERSION
            # 获取可更新的内核版本（适用于基于Red Hat的系统，如CentOS）
            # UPDATE_VERSION=$(yum info kernel | grep -A4 'Available Packages' | tail -2 | awk 'BEGIN { ORS="-" }; {print $3}' | sed 's/.$//')
        fi
    }

    checkOS()
    {
        # Validate OS is Supported for this Scan
        for check_os in "${VALID_OS[@]}"; do
            if [[ "$VER" == *"$check_os"* ]]; then
            VALID="true"
            break
            fi
        done
    }

    validateOS()
    {
        # If invalid OS is found, notify and exit
        if [[ ! $VALID ]]; then
            echo -e "${red}This script is only meant to detect vulnerable kernels on Ubuntu 12.04, 14.04, and 16.04.${reset}"
            echo -e "${red}This script is only meant to detect vulnerable kernels on Red Hat Enterprise Linux 5, 6 and 7.${reset}"
            exit 4
        fi
    }

    checkCurrentKernel()
    {
        # Check kernel if it is vulnerable
        for tested_kernel in "${VULNERABLE_VERSIONS[@]}"; do
            if [[ "$running_kernel" == *"$tested_kernel"* ]]; then
                vulnerable_kernel=${running_kernel}
                break
            fi
        done
    }

    checkUpdateKernel()
    {
        # Check updated kernel if it is vulnerable
        for update_kernel in "${VULNERABLE_VERSIONS[@]}"; do
            if [[ "$UPDATE_VERSION" == *"$update_kernel"* ]]; then
                vulnerable_update_kernel=${UPDATE_VERSION}
                break
            fi
        done
    }

    checkKPatch()
    {
        # Check if kpatch is installed
        modules=$( lsmod )
        for tested_kpatch in "${KPATCH_MODULE_NAMES[@]}"; do
            if [[ "$modules" == *"$tested_kpatch"* ]]; then
                applied_kpatch=${tested_kpatch}
                break
            fi
        done
    }

    checkMitigation()
    {
        # Check mitigation
        mitigated=0
        while read -r line; do
            if [[ "$line" == *"$MITIGATION_ON"* ]]; then
                mitigated=1
            elif [[ "$line" == *"$MITIGATION_OFF"* ]]; then
                mitigated=0
            fi
        done < <( dmesg )
    }

    checkResult()
    {
        # Result interpretation
        result=${VULNERABLE}
        if (( mitigated )); then
            result=${MITIGATED}
        fi
        if [[ ! "$vulnerable_kernel" ]]; then
            result=${SAFE_KERNEL}
        elif [[ "$applied_kpatch" ]]; then
            result=${SAFE_KPATCH}
        fi
    }

    getKernel
    collectSystemStats
    checkOS
    validateOS
    checkCurrentKernel
    checkUpdateKernel
    checkKPatch
    checkMitigation
    checkResult

    # 打印结果
    echo -e "${red}9. CVE-2016–5195（Dirty Cow 脏牛Linux内核提权漏洞）${reset}"
    if [[ ${result} == "$SAFE_KERNEL" ]]; then

        echo -e "${green}您的内核版本为 $running_kernel，不受该漏洞影响。${reset}"
        echo -e "-------------------------------------------------------------------------------------"
        exit 0
    elif [[ ${result} == "$SAFE_KPATCH" ]]; then
        echo -e "您的内核版本为 $running_kernel，通常情况下是易受攻击的。"
        echo -e "${green}但是，您已经应用了 kpatch$applied_kpatch，该补丁修复了该漏洞。${reset}"
        echo -e "-------------------------------------------------------------------------------------"
        EXITCODE=1
    elif [[ ${result} == "$MITIGATED" ]]; then
        echo -e "${yellow}您的内核版本为 $running_kernel，存在该漏洞。${reset}"
        echo -e "${yellow}您已应用了部分缓解措施。${reset}"
        echo -e "该缓解措施可防范大多数已被利用的常见攻击向量，"
        echo -e "但无法防范所有可能的攻击向量。"
        echo -e "建议您尽快更新内核。"
        echo -e "-------------------------------------------------------------------------------------"
        EXITCODE=2
    else
        echo -e "${red}您的内核版本为 $running_kernel，存在该漏洞。${reset}"
        echo -e "建议您更新内核。或者，您可以应用部分缓解措施，"
        echo -e "-------------------------------------------------------------------------------------"
        EXITCODE=3
    fi
    if [[ -n $vulnerable_update_kernel ]]; then
        echo -e "${red}可供更新的内核版本为 $UPDATE_VERSION，该版本同样存在漏洞。${reset}"
        echo -e "-------------------------------------------------------------------------------------"
    fi
    exit $EXITCODE


}

function dirty_pipe
{
    # 获取当前内核版本
    kernel_version=$(uname -r)

    # 定义受影响的内核版本范围
    affected_version_start="5.8"
    affected_version_end1="5.16.11"
    affected_version_end2="5.15.25"
    affected_version_end3="5.10.102"

    # 比较版本号的函数
    version_lt() {
        [ "$1" = "$(echo -e "$1\n$2" | sort -V | head -n1)" ] && [ "$1" != "$2" ]
    }

    # 检测是否受影响
    if version_lt "$affected_version_start" "$kernel_version" && \
    (version_lt "$kernel_version" "$affected_version_end1" || \
        version_lt "$kernel_version" "$affected_version_end2" || \
        version_lt "$kernel_version" "$affected_version_end3"); then
        echo "当前内核版本为 $kernel_version，可能存在 DirtyPipe（CVE-2022-0847）漏洞。"
    else
        echo "当前内核版本为 $kernel_version，不在受影响范围内。"
    fi
}

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
    echo "---------------"
    grep -E "admin123|test|123456|admin|root|12345678|111111|p@ssw0rd|test|qwerty|zxcvbnm|123123|12344321|123qwe|password|1qaz|000000|666666|888888|foobared" pass.tmp | awk '{print "[+] "$1}'

    sed "s/\x1B\[[0-9;]*[JKmsu]//g" vuln.log > $OUTPUT/vuln.txt
    rm -f vuln.log pass.tmp
    echo -e "-------------------------------------------------------------------------------------"

    # 检测 CVE-2018-15473 (OpenSSH用户名枚举)
    if which sshd &> /dev/null; then
        ssh_version=$(sshd -v 2>&1 | grep -oP 'OpenSSH_\K[0-9]+\.[0-9]+')
        version_major=${ssh_version%%.*}
        version_minor=${ssh_version#*.}
        if [[ "$version_major" -ge 2 && "$version_major" -le 7 ]] && [[ "$version_minor" -le 7 ]]; then
            openssh_risk="OpenSSH版本 $ssh_version 受漏洞影响"
        else
            openssh_risk="${green}OpenSSH版本 $ssh_version 不受漏洞影响${reset}}"
        fi
    else
        openssh_risk="无"
    fi
    echo -e "${red}3. CVE-2018-15473(OpenSSH用户名枚举)${reset} ${purple}${openssh_risk}${reset}"
    echo -e "-------------------------------------------------------------------------------------"


    # 检测 CVE-2024-6387 (OpenSSH远程代码执行)
    if which sshd &> /dev/null; then
        ssh_version=$(sshd -v 2>&1 | grep -oP 'OpenSSH_\K[0-9]+\.[0-9]+')
        version_major=${ssh_version%%.*}
        version_minor=${ssh_version#*.}
        if [[ "$version_major" -eq 8 && "$version_minor" -ge 5 ]] || [[ "$version_major" -eq 9 && "$version_minor" -lt 8 ]]; then
            openssh_risk="OpenSSH版本 $ssh_version 受漏洞影响"
        else
            openssh_risk="${green}OpenSSH版本 $ssh_version 不受漏洞影响${reset}"
        fi
    else
        openssh_risk="无"
    fi
    echo -e "${red}4. CVE-2024-6387(OpenSSH远程代码执行)${reset} ${purple}${openssh_risk}${reset}"
    echo -e "-------------------------------------------------------------------------------------"

    # --- | risk --> sudo  | ---

    # 检测 CVE-2019-18634, CVE-2021-3156, CVE-2023-22809 (Sudo漏洞)
    if which sudo &> /dev/null; then
        sudo_version=$(sudo -V 2>&1 | grep -oP 'Sudo version \K[0-9]+\.[0-9]+\.[0-9]+')
        version_major=${sudo_version%%.*}
        version_minor=${sudo_version#*.}
        version_minor=${version_minor%.*}
        version_patch=${sudo_version##*.}

        # 检测 CVE-2019-18634 (Sudo本地提权漏洞)
        if [[ "$version_major" -eq 1 && "$version_minor" -ge 7 && "$version_minor" -le 8 && "$version_patch" -le 30 ]]; then
            sudo_risk_2019="Sudo版本 $sudo_version 受漏洞影响"
        else
            sudo_risk_2019="${green}Sudo版本 $sudo_version 不受漏洞影响${reset}"
        fi

        # 检测 CVE-2021-3156 (Sudo溢出提权漏洞)
        if { [[ "$version_major" -eq 1 && "$version_minor" -eq 8 && "$version_patch" -ge 2 && "$version_patch" -le 31 ]]; } || { [[ "$version_major" -eq 1 && "$version_minor" -eq 9 && "$version_patch" -ge 0 && "$version_patch" -le 5 ]]; }; then
            sudo_risk_2021="Sudo版本 $sudo_version 受漏洞影响"
        else
            sudo_risk_2021="${green}Sudo版本 $sudo_version 不受漏洞影响${reset}"
        fi

        # 检测 CVE-2023-22809 (Sudo本地提权漏洞)
        if [[ "$version_major" -eq 1 && "$version_minor" -ge 8 && "$version_minor" -le 9 && "$version_patch" -le 12 ]]; then
            sudo_risk_2023="Sudo版本 $sudo_version 受漏洞影响"
        else
            sudo_risk_2023="${green}Sudo版本 $sudo_version 不受漏洞影响${reset}"
        fi
    else

        sudo_risk_2019="无"
        sudo_risk_2021="无"
        sudo_risk_2023="无"
    fi

    echo -e "${red}5. CVE-2019-18634(Sudo本地提权漏洞)${reset} ${purple}${sudo_risk_2019}${reset}"
    echo -e "-------------------------------------------------------------------------------------"

    echo -e "${red}6. CVE-2021-3156 (Sudo溢出提权漏洞)${reset} ${purple}${sudo_risk_2021}${reset}"
    echo -e "-------------------------------------------------------------------------------------"

    echo -e "${red}7. CVE-2023-22809(Sudo本地提权漏洞)${reset} ${purple}${sudo_risk_2023}${reset}"
    echo -e "-------------------------------------------------------------------------------------"

    # --- | risk --> xz utils 漏洞 | ---
    # 检测 CVE-2024-3094 XZ Utils 漏洞
    if which xz &> /dev/null; then
        xz_version=$(xz --version 2>&1 | grep -oP 'xz.* \K[0-9]+\.[0-9]+\.[0-9]+')
        version_major=${xz_version%%.*}
        version_minor=${xz_version#*.}
        version_minor=${version_minor%.*}
        version_patch=${xz_version##*.}

        if [[ "$version_major" -eq 5 && "$version_minor" -eq 6 && ( "$version_patch" -eq 0 || "$version_patch" -eq 1 ) ]]; then
            xz_risk="XZ Utils版本 $xz_version 受漏洞影响"
        else
            xz_risk="${green}XZ Utils版本 $xz_version 不受漏洞影响${reset}"
        fi
    else
        xz_risk="未安装 XZ Utils"
    fi

    echo -e "${red}8. CVE-2024-3094（XZ投毒植入恶意后门压缩命令）${reset} ${purple}${xz_risk}${reset}"
    echo -e "-------------------------------------------------------------------------------------"

    # --- | risk --> linux kernel 漏洞 | ---
    # CVE-2016–5195 dirty cow
    dirty_cow

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

    base_section() {
        local section=$1
        local title=$2
        local expected_result=$3
        local check_command=$4
        local rectification_suggestion=$5

        echo
        echo -e "${blue}${section} ${title}${reset}\n"
        echo "预期结果："
        echo "${expected_result}"
        echo -e "${red}${check_command}${reset}"
        eval "${check_command}"
        echo
        echo "整改建议："
        echo "${rectification_suggestion}"
        echo
    }



    echo -e  "${purple}${bold}1. 身份鉴别${reset}\n"

    base_section "1.1" "应对登录操作系统和数据库系统的用户进行身份标识和鉴别" \
    "     1)操作系统使用口令鉴别机制对用户进行身份标识和鉴别；
     2)登录时提示输入用户名和口令；以错误口令或空口令登录时提示登录失败，验证了登录控制功能的有效性；
     3)操作系统不存在密码为空的用户。" \
    "cat /etc/passwd | tail ; cat /etc/shadow | tail" \
    "操作系统和数据库每个用户都必须设置登录用户名和登录密码，不能存在空密码。"

    base_section "1.2" "操作系统和数据库系统管理用户身份标识应具有不易被冒用的特点，口令应有复杂度要求并定期更换" \
    "     密码策略如下：
     PASS_MAX_DAYS   90（生命期最大为90天）
     PASS_MIN_DAYS   0（密码最短周期0天）
     PASS_MIN_LEN   10（密码最小长度10位）
     PASS_WARN_AGE 7（密码到期前7天提醒）

        口令复杂度：
        口令长度8位以上，并包含数字、字母、特殊字符三种形式" \
    "more /etc/login.defs | grep 'PASS'" \
    "     密码最大生存周期为90天
     密码最短修改周期为0天，可以随时修改密码
     密码最小长度为10位，包含数字，特殊字符，字母（大小写）三种形式
     密码到期前7天必须提醒"

    base_section "1.3" "应启用登录失败处理功能，可采取结束会话、限制非法登录次数和自动退出等措施" \
    "     1)操作系统已启用登陆失败处理、结束会话、限制非法登录次数等措施；
    2)当超过系统规定的非法登陆次数或时间登录操作系统时，系统锁定或自动断开连接" \
    "cat \$PAM_FILE | grep '^auth' ;  cat /etc/shadow | tail" \
    "建议限制，密码过期后重设的密码不能和前三次的密码相同。"

    base_section "1.4" "当对服务器进行远程管理时，应采取必要措施，防止鉴别信息在网络传输过程中被窃听" \
    "     1)操作系统使用SSH协议进行远程连接；
     2)若未使用SSH方式进行远程管理，则查看是否使用telnet方式进行远程管理；" \
    "systemctl is-active 'ssh*' ;  systemctl is-active 'telnet*'" \
    "系统远程登录时要采取SSH方式登录或采用密文传输信息，保障信息的安全性。"

    base_section "1.5" "为操作系统和数据库的不同用户分配不同的用户名，确保用户名具有唯一性" \
    "用户的标识唯一，若系统允许用户名相同，UID不同，则UID是唯一性标识；若系统允许UID相同，则用户名是唯一性标识。" \
    "awk -F: '{print \$1, \$3}' /etc/passwd | sort -k2 | column -t ;  systemctl is-active telnet*" \
    "UID是唯一性标识，每个用户必须采用不同的UID来区分。"

    # ----------------------------------------------------------------------
    echo -e  "${purple}${bold}2. 访问控制${reset}\n"

    base_section "2.1" "应启用访问控制功能，依据安全策略控制用户对资源的访问" \
    "root用户：
        passwd文件夹只有rw-r-r权限
        shadow文件夹只有r- - -权限

        r=4 w=2 x=1" \
    "ls -l /etc/passwd ;  ls -l /etc/shadow" \
    "根据实际需求，对每个用户的访问权限进行限制，对敏感的文件夹限制访问用户的权限。"

    base_section "2.2" "应根据管理用户的角色分配权限，实现管理用户的权限分离，仅授予管理用户所需的最小权限" \
    "询问管理员，了解每个用户的作用、权限" \
    "awk -F: '\$3==0 {print \$1}' /etc/passwd" \
    "给予账户所需最小权限，避免出现特权用户。"

    base_section "2.3" "应实现操作系统和数据库系统特权用户的权限分离" \
    "操作系统和数据库的特权用户的权限必须分离，避免一些特权用户拥有过大的权限，减少人为误操作" \
    "awk -F: '\$3==0 {print \$1}' /etc/passwd" \
    "分离数据库和操作系统的特权用户，不能使一个用户权限过大。"
    echo -e "${cyan}ps:具体情况还是得询问管理员是否存在数据库用户权限分离。${reset}"

    base_section "2.4" "应严格限制默认帐户的访问权限，重命名系统默认帐户，修改这些帐户的默认口令" \
    "默认账户已更名，或已被禁用" \
    "cat /etc/passwd | head" \
    "严格限制默认账户的访问权限，对存在的默认账户的用户名和口令进行修改。使用[usermod -l <新账户名> root]来修改用户名，使用 [ usermod -L 用户名]，来锁定默认用户。"
    echo -e "${cyan}ps: 更改root名称可能导致telnet无法使用，是否配置按具体情况，具体等级分析。${reset}"

    base_section "2.5" "应及时删除多余的、过期的帐户，避免共享帐户的存在" \
    "不存在多余、过期和共享账户" \
    "cat /etc/passwd | awk -F: '{print \$1}' | paste -sd," \
    "整改建议：删除、禁用例如uucp，ftp等多余账户。"

    # ----------------------------------------------------------------------
    echo -e  "${purple}${bold}3. 安全审计${reset}\n"

    base_section "3.1" "审计范围应覆盖到服务器和重要客户端上的每个操作系统用户和数据库用户" \
    "系统开启了安全审计功能或部署了第三方安全审计设备" \
    "systemctl is-active auditd" \
    "开启系统本身的安全审计功能，完整记录用户对操作系统和文件访问情况，或采用第三方的安全审计设备。"

    base_section "3.2" "审计内容应包括重要用户行为、系统资源的异常使用和重要系统命令的使用等系统内重要的安全相关事件" \
    "审计功能已开启，包括：用户的添加和删除、审计功能的启动和关闭、审计策略的调整、权限变更、系统资源的异常使用、重要的系统操作（如用户登录、退出）等设置" \
    "ps -ef | grep auditd" \
    "开启审计功能，记录用户的添加和删除、审计功能的启动和关闭、审计策略的调整、权限变更、系统资源的异常使用、重要的系统操作（如用户登录、退出）等操作。"

    base_section "3.3" "审计记录应包括事件的日期、时间、类型、主体标识、客体标识和结果等" \
    "审计记录包括事件的日期、时间、类型、主体标识、客体标识和结果等内容" \
    "ps -ef | grep auditd" \
    "记录事件产生的时间，日期，类型，主客体标识等"
    echo -e "${cyan}ps:具体查看cat /etc/audit/auditd.conf | cat /etc/audit/audit.rules。${reset}"

    base_section "3.4" "操作系统应遵循最小安装的原则，仅安装需要的组件和应用程序，并通过设置升级服务器等方式保持系统补丁及时得到更新" \
    "     1)系统安装的组件和应用程序遵循了最小安装的原则；
     2)不必要的服务没有启动；
     3)不必要的端口没有打开；" \
    "ss -tulpn ; service --status-all | grep running " \
    "在不影响系统的正常使用的前提下，对系统的一些端口和服务可以进行关闭，避免这些端口或服务的问题导致系统问题。"

    # ----------------------------------------------------------------------
    echo -e  "${purple}${bold}4. 资源控制${reset}\n"

    base_section "4.1" "应通过设定终端接入方式、网络地址范围等条件限制终端登录" \
    "已设定终端登录安全策略及措施，非授权终端无法登录管理。" \
    "cat /etc/hosts.deny; cat /etc/hosts.allow" \
    "建议配置固定的终端、特定的网络范围内才能进行终端登录。"

    base_section "4.2" "应根据安全策略设置登录终端的操作超时锁定" \
    "已在/etc/profile中为TMOUT设置了合理的操作超时时间。" \
    "cat /etc/profile | grep 'TMOUT'" \
    "超时时间建议设置为300秒。"
}

# [ ++ Function HTTP_STATUS_CODE ++ ]
## 扫描web页面存活
function fk_http_scan
{
    color
    bar
    echo
    printf "%s\n" "$bar_http_scan"
    echo
    mkdir -p output
    useragent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
    if [ -f "$LIST" ]; then
        url_list=$LIST
        while IFS= read -r url_list; do
            response=$(curl -k  -A "${useragent}" --connect-timeout 10 --silent --location  "${url_list}")
            http_code=$(curl -k -A "${useragent}" --connect-timeout 10 --location --write-out "%{http_code}" --silent --output /dev/null "${url_list}")
            title=$(echo "$response" | grep -oP '<title>\K(.*?)(?=<)')
            bytes=$(echo -n "$response" | wc -c)
            echo -e "[INFO] ${url_list} [${http_code}] [${bytes}] [${purple}${title}${reset}]" | tee -a output/http_info.txt
        done < "$url_list"
        echo
    else
        url=$LIST
        response=$(curl -k -A "${useragent}" --connect-timeout 10 --silent --location "${url}")
        http_code=$(curl -k -A "${useragent}" --connect-timeout 10 --location --write-out "%{http_code}" --silent --output /dev/null "${url}")
        title=$(echo "$response" | grep -oP '<title>\K(.*?)(?=<)')
        bytes=$(echo -n "$response" | wc -c)
        echo -e "[INFO] ${url} [${http_code}] [${bytes}] [${purple}${title}${reset}]" | tee -a output/http_info.txt
        echo
    fi

}

# [ ++ Function TERMINAL_PROXY ++ ]
## 终端代理
function fk_terminal_proxy
{
    color
    # 设置代理端口
    PORT=7897
    STAT=$INPUT
    if [ -z "$STAT" ]; then
        echo "Usage: $0 on|off"
        echo $STAT
        exit 1
    fi

    if [ "$STAT" = "on" ]; then
        echo 'export https_proxy=http://127.0.0.1:7897'> ~/.clash
        echo 'export http_proxy=http://127.0.0.1:7897' >> ~/.clash
        echo 'export all_proxy=socks5://127.0.0.1:7897' >> ~/.clash
        source ~/.clash
        echo -e ${green}"Proxy enabled"${reset}
        curl cip.cc
               ping google.com -c 3
    elif [ "$STAT" = "off" ]; then
        unset https_proxy
        unset http_proxy
        unset all_proxy
        echo -e ${redx}"Proxy disabled"${reset}
        curl cip.cc
        > ~/.clash
        source ~/.clash
    else
        echo "Invalid option. Usage: $0 on|off"
        exit 1
    fi
}

# [ ++ Function ROOTKIT_ANALYSIS ++ ]
## Rookit后门查杀
function fk_rookit_analysis
{

    color
    bar

    echo
    printf "%s\n" "$bar_find_rkit"
    echo
    # ----------------------------------------------------------------------

    i "chkrootkit"
    i "rkhunter"

    mkdir -p "./output"

    # 运行 chkrootkit 并保存结果
    CHKROOTKIT_RESULTS="./output/chkrootkit_results.txt"
    echo "正在运行 chkrootkit..."
    sudo chkrootkit > "$CHKROOTKIT_RESULTS"
    echo "chkrootkit 扫描结果已保存到 $CHKROOTKIT_RESULTS"

    # 运行 rkhunter 并保存结果
    RKHUNTER_RESULTS="./output/rkhunter_results.txt"
    echo "正在运行 rkhunter..."
    sudo rkhunter --check --sk > "$RKHUNTER_RESULTS"
    echo "rkhunter 扫描结果已保存到 $RKHUNTER_RESULTS"
}

# [ ++ Function SQL_INJECTION_ANALYSIS ++ ]
## 日志分析-SQL注入分析专项
function fk_sqlianalysis
{
    FILE=$1
    echo "[+] sql注入盲注'>'判断类"
    sed -n -E 's/.*,([0-9]+),1\)\)>([0-9]+).*HTTP\/1.1" (404|200).*/\1 \2 \3/p' $FILE | awk '($3 == 404 && ($1 not in max || $2 > max[$1])) || ($3 == 200 && ($1 not in min || $2 < min[$1])) {max[$1] = ($3 == 404 ? $2 : max[$1]); min[$1] = ($3 == 200 ? $2 : min[$1]);} END {for (i in max) if ((i in max) && (i in min) && (max[i] - min[i] == 1)) print max[i]}' | while read -r line;do printf "\x$(printf '%x' "$line")"; done
    echo;echo "[+] sql注入盲注'!='判断类"
    sed -n -E 's/.*,([0-9]+),1\)\)!=([0-9]+).*HTTP\/1.1" (404|200).*/\2/p' $FILE | while read -r line;do printf "\x$(printf '%x' "$line")"; done
    echo;echo "[+] sql注入盲注time延时类"
    delay=$(sed -n -E "s/.*sleep\(([0-9]+)\).*HTTP\/1.1\" 200.*/\1/p" $FILE) ; sed -n -E "s/.*([0-9][0-9])\/([A-Z][a-z]+)\/([12]0[0-9]+):([0-9]+:[0-9]+:[0-9]+).*\)=[a-z0-9A-Z]+\('(.?)'\).*sleep\(([0-9]+)\).*HTTP\/1.1\" 200.*/\3-\2-\1 \4 \5 \6/p" $FILE | awk 'BEGIN{m=split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec",a," ")} {for(i=1;i<=m;i++) {if(index($0,a[i])) {gsub(a[i],i,$0)}}} {print}'  | awk '{split($2, a, ":"); t=mktime($1 " " a[1] " " a[2] " " a[3]); diff=t-prev; if (diff<$delay) print prev_line; prev_line=$3; prev=t}' | awk '{printf "%s", $0}'
    echo;echo
}

## 日志分析-SQL注入分析专项
function fk_weblog_sqlianalysis
{

    color
    bar
    printf "%s\n" "$bar_sqli_anal"


    if [ -z $ACCESS_PATH ]; then
        apache="/var/log/apache*/access.log"
        nginx="/var/log/nginx/access.log"
        echo
        echo "[+] check /var/log/apache*/access.log"
        echo
        if [ -f $apache ]; then
            fk_sqlianalysis "$apache"
        else
            echo "未找到该文件"
        fi
        echo
        echo "[+] check /var/log/nginx/access.log"
        echo
        if [ -f $nginx ]; then
            fk_sqlianalysis "$nginx"
        else
            echo "未找到该文件"
        fi
    else
        echo
        echo "[+] check $ACCESS_PATH"
        echo
        if [ -f $ACCESS_PATH ]; then
            fk_sqlianalysis "$ACCESS_PATH"
        else
            echo "未找到该文件"
        fi
    fi


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

# [ ++ Function AUTO_RUN ++ ]
## 定时运行
function fk_auto_run
{
    color
    stats
    # path
    SCRIPT_DIR=$(cd "$(dirname "$0")"; pwd)
    DIR="${SCRIPT_DIR}/$(basename "$0")"
    DIR_E="${SCRIPT_DIR}/courier"
    EXT_FILE=$CONF_PATH/$CONF_FILE
    OK_HTML=$OUTPUT_M/$COURIER

    # 先判断配置文件是否存在，如果存在则进入用户自定义命令
    if [ -f $EXT_FILE ]; then
        printf "$OK 配置文件已找到，请正确配置文件${green}%s${reset}邮件信息！\n" "$EXT_FILE"
        source $EXT_FILE
        if [ -z $EMAIL ] ; then
            printf "$NO 未配置EMAIL开关。\n"
            echo "EMAIL=\"false\"" >> $EXT_FILE
            printf "$OK 已将EMAIL开关导入配置文件，默认关闭。\n"
            EMAIL_STAT="$WAR 信使未开启。"
        else
            if [ $EMAIL = "true" ]; then
                EMAIL_STAT="$SUC 信使已开启。"
            elif [ $EMAIL = "false" ];then
                EMAIL_STAT="$WAR 信使未开启。"
            else
                EMAIL_STAT="$WAR EMAIL配置错误，只能是true或false。"
            fi
    fi
    else
        printf "$ERR 配置文件%s未找到。\n" "$CONF_FILE"
        mkdir -p $CONF_PATH
        echo "EMAIL=\"false\"" > $EXT_FILE
        echo "# 信使 - 邮箱配置，抄送CC可选"  >>$EXT_FILE
        echo "FROM=\"Your Email\"" >>$EXT_FILE
        echo "KEY=\"Your Email Auth Code\"" >>$EXT_FILE
        echo "TO=\"to Email\"" >>$EXT_FILE
        echo "CC=\"to Email\"" >>$EXT_FILE
        echo "SERVER=\"Your Email SERVER\"" >>$EXT_FILE
        echo "EXT=\"false\"" >> $EXT_FILE
        echo "# 以命令 + 描述的方式增加"  >>$EXT_FILE
        echo "commands=(" >>$EXT_FILE
        echo "#    \"cat /etc/passwd | grep -v nologin | cut -d: -f1 | paste -sd,;列出所有用户\""  >>$EXT_FILE
        echo ")" >>$EXT_FILE
        printf "$OK 配置文件已生成，请前往配置文件${green}%s${reset}填写信息！\n" "$EXT_FILE"
        source $EXT_FILE
    fi

    printf "$EMAIL_STAT\n"

    if [[ -z "$HOUR" ]]; then
        hour=0
        printf "$INFO 可使用 -e c 清除whoamifuck的所有日志。\n"
        printf "$INFO 可使用 -e 时 分 设置每天的执行时间（default: 0:0）。\n"
    else
        if [[ "$HOUR" == "c" ]]; then
            crontab -l 2>/dev/null | grep -v $DIR | crontab -
            printf "$SUC 清除成功\n\n"
            echo -e "${cyan}------------- | ${reset}${purple}crontab${reset}${cyan} | --------------${reset}"
            crontab -l
            exit 1
        else
            hour=$HOUR
        fi
    fi

    if [[ -z "$MINUTE" ]]; then
        minute=0
    else
        if [[ "$HOUR" == "c" ]]; then
            crontab -l 2>/dev/null | grep -v $DIR | crontab -
            printf "$SUC 清除成功\n\n"
            echo -e "${cyan}------------- | ${reset}${purple}crontab${reset}${cyan} | --------------${reset}"
            crontab -l
            exit 1
        else
            minute=$MINUTE
        fi
    fi

    # 0-23时
    if ! [[ "$hour" =~ ^[0-9]+$ ]] || [ "$hour" -lt 0 ] || [ "$hour" -gt 23 ]; then
        printf "$ERR 请填写范围0到23小时之间的整数。\n"
        exit 1
    fi

    # 0-59分
    if ! [[ "$minute" =~ ^[0-9]+$ ]] || [ "$minute" -lt 0 ] || [ "$minute" -gt 59 ]; then
        printf "$ERR 请填写范围0到59分钟之间的整数。\n"
        exit 1
    fi

    # 设置 cron 作业
    if [[ "$EMAIL" == "false" ]] ; then
        (crontab -l 2>/dev/null; echo "$minute $hour * * * $DIR -m") | crontab -
    elif [[ "$EMAIL" == "true" ]] ; then
        # 判断信使是否存在
        if [ -f "courier" ]; then
            printf "$SUC 信使已到达。\n"
            # 是否抄送
            if [ -z $CC ] ; then
                (crontab -l 2>/dev/null; echo "$minute $hour * * * $DIR -m && $DIR_E -u $FROM -s $SERVER -t $TO -r $OK_HTML -k $KEY ") | crontab -
            else
                (crontab -l 2>/dev/null; echo "$minute $hour * * * $DIR -m && $DIR_E -u $FROM -s $SERVER -t $TO -r $OK_HTML -k $KEY -c $CC") | crontab -
            fi
        else
            printf "$WAR 信使已失踪。\n"
            (crontab -l 2>/dev/null; echo "$minute $hour * * * $DIR -m") | crontab -
        fi
    else
        printf "$ERR 邮件配置错误。\n"
    fi
    printf "$INFO Whoamifuck的计划任务日志模块将在每天 $hour:$minute 执行一次。\n"
    echo -e "${cyan}------------- | ${reset}${purple}crontab${reset}${cyan} | --------------${reset}"
    crontab -l


    # rm -f $OUTPUT/courier-*.html

}

# [ ++ Function EXTENTION_CMD ++ ]
## 扩展命令 - 属于你自己的工具
function fk_extention
{
    bar
    color
    stats
    printf "%s\n" "$bar_conf_file"
    echo
    # 先判断自定义路径参数是否存在
    if [ -z $EXT_PATH ]; then
        EXT_FILE=$CONF_PATH/$CONF_FILE
    else
        EXT_FILE=$EXT_PATH
    fi

    # 先判断配置文件是否存在，如果存在则进入用户自定义命令
    if [ -f $EXT_FILE ]; then
        source $EXT_FILE
        if [ $EXT = "true" ]; then
            EXT_STAT="$SUC 扩展命令已开启。"
        elif [ $EXT = "false" ];then
            EXT_STAT="$WAR 扩展命令已关闭。"
        else
            EXT_STAT="$ERR config error."
        fi
        printf "$EXT_STAT\n"
        for command_info in "${commands[@]}"; do
            IFS=";" read -r command desc <<<"$command_info"
            printf "$OK $desc\n"
            echo "-----------------"
            bash -c "$command"
        done
    else
        printf "$ERR 配置文件%s未找到。\n" "$CONF_FILE"
        mkdir -p $CONF_PATH
        echo "EMAIL=\"false\"" > $EXT_FILE
        echo "# 信使 - 邮箱配置，抄送CC可选"  >>$EXT_FILE
        echo "FROM=\"Your Email\"" >>$EXT_FILE
        echo "KEY=\"Your Email Auth Code\"" >>$EXT_FILE
        echo "TO=\"to Email\"" >>$EXT_FILE
        echo "CC=\"to Email\"" >>$EXT_FILE
        echo "SERVER=\"Your Email SERVER\"" >>$EXT_FILE
        echo "EXT=\"false\"" >> $EXT_FILE
        echo "# 以命令 + 描述的方式增加"  >>$EXT_FILE
        echo "commands=(" >>$EXT_FILE
        echo "#    \"cat /etc/passwd | grep -v nologin | cut -d: -f1 | paste -sd,;列出所有用户\""  >>$EXT_FILE
        echo ")" >>$EXT_FILE
        printf "$OK 配置文件已生成！${green}%s${reset}\n" "$EXT_FILE"
    fi

}

# [ ++ Function BINHASH_FILE ++ />m/ ]
## 重点目录下的文件hash值
function fk_hashfile
{
    # 定义要遍历的目录
    dirs=("/usr/bin" "/usr/local/bin" "/bin")
    HASH=""
    # 遍历每个目录
    for dir in "${dirs[@]}"; do
    # 检查目录是否存在
    if [ -d "$dir" ]; then
        # 遍历目录中的每个文件
        for file in "$dir"/*; do
        # 检查文件是否存在并且是普通文件
        if [ -f "$file" ]; then
        # 计算文件的 MD5 哈希值并追加到变量中
        HASH+=$(md5sum "$file")
        HASH+=$'\n'
        fi
        done
    fi
    done
}

# [ ++ OPTIONS OUTPUT ++ ]
## 打印文本输出 - text
function fk_output
{
    # > 文本思路：Html仅用于较为短的查询，如日志超长达几十万条则推荐采用文本输出进行全量保持并使用自己喜爱的编辑器查看
    color
    bar
    stats
    fk_hashfile

    printf "%s\n" "$bar_repo_rest"

    FILENAME=$OUT_NAME
    mkdir -p $OUTPUT_T

    current_time=$(date "+%Y%m%d%H%M%S")
    OUTPUT_DEFAULT=$OUTPUT/chief_output.txt
    OUTPUT_OPTIONS=$OUTPUT/chief_$FILENAME

    # --- | User Login | ---
    userinfo=userlogin.txt
    userloginfo=chief_userlogin_info.txt
    userloginfo_all=chief_userlogin_info_all.txt
    fk_userlogin > output/$userinfo
    sed "s/\x1B\[[0-9;]*[JKmsu]//g" $OUTPUT/$userinfo > $OUTPUT/$userloginfo
    rm -f $OUTPUT/$userinfo
    userlogin=$(cat $OUTPUT/$userloginfo)

    if [[ $OSTYPE == "T_Debian" ]]; then
        $(cat $AUTHLOG_FILE 2>/dev/null| tail -20000 > $OUTPUT/$userloginfo_all)
    else
        $(cat $SECURE_FILE 2>/dev/null | tail -20000 > $OUTPUT/$userloginfo_all)
    fi

    # --- | History | ---
    # current 这个失效
    $(cat ~/.*sh_history > chief_history_current.txt )
    # all users
    who_history_file=chief_history_allusers.txt
    $(> output/$who_history_file)
    for userdir in /home/*; do
        if [ -d "$userdir" ]; then
            his_f=(".bash_history" ".zsh_history" ".csh_history" ".tcsh_history" ".fish_history")
            for file in "${his_f[@]}"; do
                if [ -f "$userdir/$file" ]; then
                    echo "-------------| $userdir history | ----------------" >> output/$who_history_file
                    cat  "$userdir/$file"  >> output/$who_history_file
                fi
            done
        fi
    done

    # --- | Crontab | ---
    cronpath="/var/spool/cron/"
    crond_file="chief_crond.txt"
    cron_file_spool="chief_cron_spool.txt"
    # 这条也失效，不过命令展示可以看见
    crontab -l 2>/dev/null > chief_crontab.txt
    find "$cronpath" -type f -exec cat {} > $OUTPUT/$cron_file_spool \;
    cat /etc/cron.*/* 2>/dev/null > $OUTPUT/$crond_file


    # HASH

    # 定义要遍历的目录
    dirs=("/usr/bin" "/usr/local/bin" "/bin")
    # 遍历每个目录
    for dir in "${dirs[@]}"; do
    # 检查目录是否存在
    if [ -d "$dir" ]; then
        # 遍历目录中的每个文件
        for file in "$dir"/*; do
        # 检查文件是否存在并且是普通文件
        if [ -f "$file" ]; then
        # 计算文件的 MD5 哈希值并追加到变量中
        md5sum "$file" >> $OUTPUT/chief_binhashfile.txt
        fi
        done
    fi
    done


    # --- | SSHPUBLICKEY FILE | ---
    sshpubkey_outfile="chief_sshpublickey.txt"
    SSHKEY_FILE="$HOME/.ssh/authorized_keys"
    if [ -f $SSHKEY_FILE ]; then
        cat $SSHKEY_FILE 2>/dev/null > $OUTPUT/$sshpubkey_outfile
    else
        status="no find file"
    fi

    # --- | SERVICEINFO FILE | ---
    serviceinfo_outfile="chief_serviceinfo.txt"
    serivceshow=$(for service in $(systemctl list-units --all | grep -v "inactive" | awk '/\S+\.service/ {gsub(/^[^[:alnum:]]+/, ""); print $1}' | grep -v UNIT); do   echo -e "\n-------------\n服务: $service\n-------------";   systemctl show "$service" | grep -E "path|ActiveState="; done)
    if [ -z "$serivceshow" ]; then
        status="no find service"
    else
        echo "$serivceshow" > $OUTPUT/$serviceinfo_outfile
    fi

    # --- | PROCESSING FILE | ---
    processinfo_file="processinfo.txt"
    processshow=$(ps -ef)
    if [ -z "$processshow" ]; then
        status="no find process"
    else
        echo "$processshow" > $OUTPUT/$processinfo_file
    fi

    # --- | NETWORK FILE | ---
    networkinfo_file="networkinfo.txt"
    if command -v lsof > /dev/null; then
        networkshow=$(netstat -antp)
        lsofshow=$(lsof -i -L 2>/dev/null)
        echo "$processshow" "$lsofshow"> $OUTPUT/$processinfo_file
    else
        networkshow=$(netstat -antp)
        echo "$networkshow"> $OUTPUT/$processinfo_file
    fi



    # --- | OUTPUT - TEXT | ---

    if [ -z "$FILENAME" ]; then
        ./"$0" -n > output.txt
        sed "s/\x1B\[[0-9;]*[JKmsu]//g" output.txt > $OUTPUT_DEFAULT
        rm -f output.txt
        tar -czf $OUTPUT_T/report-${current_time}.tar.gz $OUTPUT/chief_*
        printf "\n$SUC 导出结果成功。路径：$OUTPUT_T/report-${current_time}.tar.gz\n"
        rm -f $OUTPUT/chief_*
    else
        ./"$0" -n > "$FILENAME"
        sed "s/\x1B\[[0-9;]*[JKmsu]//g" $FILENAME > $OUTPUT_OPTIONS
        rm -f $FILENAME
        tar -czf $OUTPUT_T/report-${current_time}.tar.gz $OUTPUT/chief_*
        printf "\n$SUC 导出结果成功。路径：$OUTPUT_T/report-${current_time}.tar.gz\n"
        rm -f $OUTPUT/chief_*
    fi



}

# [ ++ Function REPORT_HTML ++ ]
## 打印报告 - html
function fk_reporthtml
{
    bar
    printf "%s\n" "$bar_repo_rest"
    fk_hashfile // 计算hash值
    mkdir -p $OUTPUT_M

    current_time=$(date "+%Y%m%d%H%M%S")
    event_date=$(date "+%Y年%m月%d日 %H:%M:%S")

    if [ -z $REPORT_NAME ]; then
        html_name="report-${current_time}.html"
    else
        html_name=$REPORT_NAME
    fi

    show=0  # 控制调用的函数，简称 显控

    # |        Import  Funtion     |
    # ------------------------------
    fk_baseinfo "$show"
    fk_devicestatus "$show"
    os_name
    stats

    # --- | Port and process | ---
    # 细节点：netstat没有怎么办，ss来代替
    # 补充：发现很多系统lsof也是不存在的，需要先确保lsof存在，否则无法使用；lsof是用来判断端口号对于的服务的。
    if command -v netstat > /dev/null &&  command -v lsof > /dev/null; then
        network_info=$(netstat -anltu)
        portsvt_info=$(netstat -tunlp | awk '/^tcp/ {print $4,$7}; /^udp/ {print $4,$6}' | sed -r 's/.*:(.*)\/.*/\1/' | sort -un | awk '{cmd = "sudo lsof -w -i :" $1 " | awk '\''NR==2{print $1}'\''"; cmd | getline serviceName; close(cmd); print $1 "\t" serviceName}')
    else
        network_info=$(ss -anltu)
        portsvt_info=$(ss -antup)
    fi


    # 7.0 补充 - 网络连接信息
    if command -v lsof > /dev/null; then
        lsof_info=$(lsof -i -L 2>/dev/null | sed -e 's/</\&lt;/g; s/>/\&gt;/g')
    else
        lsof_info="无lsof命令。"
    fi

    process_info=$(ps aux | sed -e 's/</\&lt;/g; s/>/\&gt;/g')
    service_info=$(systemctl | grep -E "\.service.*running" | awk -F. '{print $1}')

    # 7.0 补充  - 添加服务的具体信息
    service_show=$(for service in $(systemctl list-units --all | awk '/\S+\.service/ {gsub(/^[^[:alnum:]]+/, ""); print $1}' | grep -v UNIT); do   echo -e "\n-------------\n服务: $service\n-------------";   systemctl show "$service" | grep -E "path|ActiveState="; done)

    # --- | User Group | ---
    user_info=$(cat /etc/passwd)
    pass_info=$(cat /etc/shadow)
    grop_info=$(cat /etc/group)


    # --- | History | ---
    # current
    histcurrent_info=$(cat ~/.*sh_history 2>/dev/null | sed -e 's/</\&lt;/g; s/>/\&gt;/g' )
    # all user
    who_history_file=who_history.txt
    $(> output/$who_history_file)
    for userdir in /home/*; do
        if [ -d "$userdir" ]; then
            his_f=(".bash_history" ".zsh_history" ".csh_history" ".tcsh_history" ".fish_history")
            for file in "${his_f[@]}"; do
                if [ -f "$userdir/$file" ]; then
                    echo "-------------| $userdir history | ----------------" >> output/$who_history_file
                    cat  "$userdir/$file" | sed -e 's/</\&lt;/g; s/>/\&gt;/g' >> output/$who_history_file
                fi
            done
            histcmd_info=$(cat output/$who_history_file)

        fi
    done


    # --- | Crontab | ---
    cronpath="/var/spool/cron/"
    cron_file="who_cron.txt"
    cron_file1="who_cron1.txt"
    crontab1_info=$(crontab -l 2>/dev/null)
    find "$cronpath" -type f -print0 | xargs -0 file --mime-type | grep -v 'application/' | awk -F: '{print $1}' | xargs cat > $OUTPUT/$cron_file1
    crontab2_info=$(cat $OUTPUT/$cron_file1 2>/dev/null | sed -e 's/</\&lt;/g; s/>/\&gt;/g' | tr -d '\0')
    cat /etc/cron.*/* 2>/dev/null >> $OUTPUT/$cron_file
    crontab3_info=$(cat $OUTPUT/$cron_file 2>/dev/null | sed -e 's/</\&lt;/g; s/>/\&gt;/g' | tr -d '\0')
    crontab4_info=$(cat /etc/crontab  2>/dev/null | sed -e 's/</\&lt;/g; s/>/\&gt;/g')
    # /var/spool/cron/'
    # /etc/cron.d/'
    # /etc/cron.daily/'
    # /etc/cron.weekly/'
    # /etc/cron.hourly/'
    # /etc/cron.monthly/'


    # --- | init | ---
    initpid_info=$(systemctl list-unit-files --type=service)
    initd_info=$(cat /etc/init.d/* 2>/dev/null | sed -e 's/</\&lt;/g; s/>/\&gt;/g')
    initrc_info=$(cat /etc/rc*/* 2>/dev/null | sed -e 's/</\&lt;/g; s/>/\&gt;/g')


    # --- | User Login | ---
    userinfo=userlogin.txt
    userloginfo=who_userlogin_info.txt
    fk_userlogin > output/$userinfo
    sed "s/\x1B\[[0-9;]*[JKmsu]//g" $OUTPUT/$userinfo > $OUTPUT/$userloginfo
    rm -f $OUTPUT/$userinfo
    userlogin=$(cat $OUTPUT/$userloginfo)

    if [[ $OSTYPE == "T_Debian" ]]; then
        userlog_info=$(cat $AUTHLOG_FILE 2>/dev/null | tail -2000)
        userlog_file=$AUTHLOG_FILE
    else
        userlog_info=$(cat $SECURE_FILE 2>/dev/null | tail -2000)
        userlog_file=$SECURE_FILE
    fi

    # --- | File Stat | ---
    fk_filemove "$show"
    fk_fileinfo "$show"


    fileinfo_file=fileinfo.txt
    fileinfo_deal_file=fileinfolog.txt
    echo -e "$file_output" > $OUTPUT/$fileinfo_file
    sed "s/\x1B\[[0-9;]*[JKmsu]//g" $OUTPUT/$fileinfo_file > $OUTPUT/$fileinfo_deal_file
    rm -f $OUTPUT/$fileinfo_file
    fileinfo_output=$(cat $OUTPUT/$fileinfo_deal_file)

    # --- | env profile | ---
    env_alias_info=$(cat ~/.bashrc | grep alias 2>/dev/null | sed -e 's/</\&lt;/g; s/>/\&gt;/g')
    env_profile1=$(cat /root/.bashrc 2>/dev/null | sed -e 's/</\&lt;/g; s/>/\&gt;/g')
    env_profile2=$(cat /root/.*shrc 2>/dev/null | sed -e 's/</\&lt;/g; s/>/\&gt;/g')
    env_profile3=$(cat /etc/bashrc 2>/dev/null | sed -e 's/</\&lt;/g; s/>/\&gt;/g')
    env_profile4=$(cat /root/.bash_profile 2>/dev/null | sed -e 's/</\&lt;/g; s/>/\&gt;/g')

    env_homefile=who_envprofile.txt
    echo "-------------| environment variable | ----------------" > output/$env_homefile
    for userdir in /home/*; do
        echo "-------------| $userdir | ----------------" >> output/$env_homefile
        if [ -d "$userdir" ]; then
            bashrc_path="$userdir/.bashrc"
            profile1_path="$userdir/.profile"
            profile2_path="$userdir/.bash_profile"
            profile3_path="$userdir/.bash_logout"
            if [ -f "$bashrc_path" ]; then
                cat "$bashrc_path" >> output/$env_homefile
            fi
            if [ -f "$profile1_path" ]; then
                cat "$profile1_path" >> output/$env_homefile
            fi
            if [ -f "$profile2_path" ]; then
                cat "$profile2_path" >> output/$env_homefile
            fi
            if [ -f "$profile3_path" ]; then
                cat "$profile3_path" >> output/$env_homefile
            fi
        fi
    done
    env_homeprofile_info=$(cat output/$env_homefile)


    # --- | risk --> die process | ---
    kill_process=$(ps -al | awk '{print $2,$4}' | grep -e '^[Zz]')
    if [ -z "$kill_process" ]; then
        kill_process="无"
    fi

    # --- | risk --> redis vul | ---
    redis_risk=$(find / -name "redis.conf" -exec grep --color=none -H "# requirepass " {} \; 2>/dev/null)
    if [ -z "$redis_risk" ]; then
        redis_risk="无"
    fi

    # --- | risk --> CVE-2018-15473 | ---
    # CVE-2018-15473 / 这里采用了先探测命令是否存在，提高健壮性 呜呼
    if  which ssh &> /dev/null; then
        # ssh_version=$(ssh -V 2>&1 | awk 'match($0, /OpenSSH_([0-9]+\.[0-9]+)/, m) { print m[1] }') # 某些机器报错
        ssh_version=$(ssh -V 2>&1 | grep -oP 'OpenSSH_\K[0-9]+\.[0-9]+')
        version_major=${ssh_version%%.*}    # 这个语法第一次学，有点意思  意思是不要包括点及后面的
        version_minor=${ssh_version#*.}     # 不要包括点前面的
        if [[ "$version_major" -gt 7 ]] || ([[ "$version_major" -eq 7 ]] && [[ "$version_minor" -gt 7 ]]); then
            openssh_risk="OpenSSH版本 $ssh_version 不受漏洞影响"
        else
            openssh_risk="OpenSSH版本 $ssh_version 受漏洞影响"
        fi
    else
        openssh_risk="无"
    fi

    # --- | risk --> CVE-2024-6387 | ---
    # CVE-2024-6387 Exist!!! 核弹级别 这个是采用@ahlfors老哥的，语法很紧凑
    vc(){ [[ "$(printf '%s\n' "$1" "$3"|sort -V|head -n1)" != "$1" || "$1" == "$3" ]]&&[[ "$2" == "<" ]]&&return 1;[[ "$(printf '%s\n' "$1" "$3"|sort -V|head -n1)" != "$3" || "$1" == "$3" ]]&&[[ "$2" == ">" ]]&&return 1;return 0;}
    gov(){ if command -v apt-get>/dev/null;then dpkg -s openssh-server|grep '^Version:'|awk '{print $2}';elif command -v yum>/dev/null||command -v dnf>/dev/null;then rpm -qi openssh-server|grep '^Version'|awk '{print $3}';elif command -v pacman>/dev/null;then pacman -Qi openssh|grep 'Version'|awk '{print $3}';else echo "未知的Linux发行版或不支持的包管理器。"&&return 1;fi;}
    ov=$(gov)
    [ $? -eq 0 ]&&sv="OpenSSH版本 $ov "&&vc "$ov" ">=" "8.5p1"&&vc "$ov" "<" "9.8p1"&&opensshvul="受漏洞影响"||opensshvul="不受漏洞影响"||echo "Fail to get OpenSSH version."

    # 检测 CVE-2024-6387 (OpenSSH远程代码执行)
    if which sshd &> /dev/null; then
        ssh_version=$(sshd -v 2>&1 | grep -oP 'OpenSSH_\K[0-9]+\.[0-9]+')
        version_major=${ssh_version%%.*}
        version_minor=${ssh_version#*.}
        if [[ "$version_major" -eq 8 && "$version_minor" -ge 5 ]] || [[ "$version_major" -eq 9 && "$version_minor" -lt 8 ]]; then
            opensshvul="OpenSSH版本 $ssh_version 受漏洞影响"
        else
            opensshvul="OpenSSH版本 $ssh_version 不受漏洞影响"
        fi
    else
        opensshvul="无"
    fi
    # --- | backdoor --> SSH | ---
    fk_sshlink
    sshfileinfo=who_sshbackdoor.txt
    echo -e $sshbackdoor_info > output/$sshfileinfo
    ssh_info=$(cat output/$sshfileinfo)

    # --- | backdoor --> SSH Public key | ---
    SSHKEY_FILE=$HOME/.ssh/authorized_keys
    if [ -f $SSHKEY_FILE ]; then
        publickey_perm=$(stat -c %a $SSHKEY_FILE)
        publickey_modi=$(stat -c %y $SSHKEY_FILE)
        sshpubkey="$publickey_modi($publickey_perm)"
    else
        sshpubkey="未找到该文件"
    fi

    # -----------------------------------------------------------
    #                   HTML Report Format
    #                   Hi Whoamifuck 6.0
    # -----------------------------------------------------------

    cat << EOF | tee $OUTPUT_M/$html_name $OUTPUT_M/$COURIER > /dev/null
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>应急响应报告</title>
        <style>
            .highlighted-text {
                color: rgb(246, 0, 0);
                background-color: rgb(250, 252, 202);
            }
            body {
                font-family: Arial, sans-serif;
                margin: 0;
                padding: 0;
                background-color: #f4f4f4;
                color: #333;
            }
            .container {
                max-width: 800px;
                margin: 20px auto;
                padding: 20px;
                background-color: #fff;
                border-radius: 5px;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            }
            h1 {
                text-align: center;
                color: #b22222;
            }
            h2 {
                color: #000000;
            }
            .section {
                margin-bottom: 20px;
            }
            .section-title {
                border-bottom: 1px solid #ccc;
                padding-bottom: 10px;
                margin-bottom: 10px;
            }
            .section-content {
                padding-left: 20px;
            }
            #searchForm {
                margin-bottom: 20px;
            }
            .copyright {
                color: #666;
                font-size: 12px;
                text-align: center;
                margin-top: 10px;
                margin-bottom: 1px;
            }
            .line {
                margin-top: 10px;
                border-top: 1px solid #ccc;
            }
            .section-content select {
                margin-bottom: 10px;
            }
            .bold {
                font-weight: bold;
            }
            /* 样式 */
            table {
                width: calc(100% - 40px); /* 减去左右各 20px 的留边 */
                border-collapse: collapse;
                margin-left: 20px; /* 左留边 20px */
                margin-right: 20px; /* 右留边 20px */
            }
            th, td {
                border: 1px solid #ddd;
                padding: 8px;
                text-align: left;
            }
            th {
                background-color: #f2f2f2;
            }
            .code-block {
                background-color: #f4f4f4;
                border: 1px solid #ddd;
                border-left: 3px solid #4CAF50;
                padding: 10px;
                margin: 10px 0;
                overflow-x: auto;
                white-space: nowrap; /* 防止换行 */
            }
            .rush-code{
                background: linear-gradient(to bottom, #D5DEE7 0%, #E8EBF2 50%, #E2E7ED 100%), linear-gradient(to bottom, rgba(0,0,0,0.02) 50%, rgba(255,255,255,0.02) 61%, rgba(0,0,0,0.02) 73%), linear-gradient(33deg, rgba(255,255,255,0.20) 0%, rgba(0,0,0,0.20) 100%); background-blend-mode: normal,color-burn;
                border: 1px solid #b70303;
                border-left: 3px solid #4808ae;
                padding: 10px;
                margin: 10px 0;
                overflow-x: auto;
                white-space: nowrap; /* 防止换行 */
            }
            .rusha {
                color: rgb(217, 72, 15); /* 设置链接文字颜色为蓝色 */
                text-decoration: none; /* 去除链接下划线 */
                /* 其他样式 */
            }
            .code-block pre {
                margin: 0;
            }
            .code-block-container {
                overflow: hidden;
                max-height: 92px; /* 初始高度为一行 */
                transition: max-height 0.6s ease; /* 添加过渡效果 */
            }
            .toggle-button {
                cursor: pointer;
                color: rgb(0, 0, 0);
                border-width: 1px;
                font-size: 12px;
                border-style: solid;
                border-color: #D2D4D4 #6B778C #6B778C #D2D4D4;
                padding: 3px 5px 3px 5px;
                margin-bottom: 3px;
                background: linear-gradient(to bottom, #D5DEE7 0%, #E8EBF2 50%, #E2E7ED 100%), linear-gradient(to bottom, rgba(0,0,0,0.02) 50%, rgba(255,255,255,0.02) 61%, rgba(0,0,0,0.02) 73%), linear-gradient(33deg, rgba(255,255,255,0.20) 0%, rgba(0,0,0,0.20) 100%); background-blend-mode: normal,color-burn;
            }
            .toggle-button:hover {
                color: #FF7F00;

            }
            .toggle-button:active {
                color: #c11310;

            }
            .highlighted-command {
                background-color: yellow;
            }
            .highlighted-info {
                font-weight: bold;
                margin-bottom: 10px;
            }
            .highlighted-number {
                color: red;
            }
            li {
                font-size: 14px;
            }
            .container {
                position: relative;
            }

            #searchForm {
                position: absolute;
                top: 0;
                right: 0;
            }
            .t1 {
                color: #162eca;
                padding-left: 80px;
                line-height: 22px;
                position: relative;
                border-bottom: 2px solid linear-gradient(to right, #1c9294, rgba(255, 255, 255, 0));
            }

            .t1::after {
                content: "";
                position: absolute;
                bottom: 0;
                top: 0;
                left: 18px;
                width: 50px;
                height: 18px;
                transform: skewX(35deg);
                background: linear-gradient(to right,
                        #2d83fa,
                        #2af0ed);
            }


            .t3 {
                padding-left: 20px;
                position: relative; /* 添加这一行 */
                &:after {
                    content: " ";
                    width: 8px;
                    height: 8px;
                    border-radius: 50%;
                    background: #12a3f5;
                    position: absolute;
                    left: 0;
                    top: 3px;
                }
            }
            .t2 {
                color: rgb(0, 0, 0);
                border-width: 1px;
                font-size: 12px;
                border-style: solid;
                border-color: #D2D4D4 #6B778C #6B778C #D2D4D4;
                padding: 3px 5px 3px 5px;
                margin-bottom: 3px;
                border-radius: 16px;
                /* border: 1px solid #0b0720; */
                box-shadow: 0 0 10px #C0C0C0;
                text-align: center;
                width: 240px;
                position: relative;
                color: #000000;
                font-weight: bold;
                background: linear-gradient(to bottom, #D5DEE7 0%, #E8EBF2 50%, #E2E7ED 100%), linear-gradient(to bottom, rgba(0,0,0,0.02) 50%, rgba(255,255,255,0.02) 61%, rgba(0,0,0,0.02) 73%), linear-gradient(33deg, rgba(255,255,255,0.20) 0%, rgba(0,0,0,0.20) 100%); background-blend-mode: normal,color-burn;

                &:before {
                    content: "";
                    width: 210%;
                    height: 2px;
                    background: #f8f8f9;
                    position: absolute;
                    top: 10px;
                    left: 102%;
                    /* background: linear-gradient(to right, #967312, rgba(255, 255, 255, 0)); */
                    background: linear-gradient(to right, #D5DEE7 0%, #E8EBF2 50%, #E2E7ED 100%), linear-gradient(to right, rgba(0,0,0,0.02) 50%, rgba(255,255,255,0.02) 61%, rgba(0,0,0,0.02) 73%), linear-gradient(33deg, rgba(255,255,255,0.20) 0%, rgba(0,0,0,0.20) 100%); background-blend-mode: normal,color-burn;
                }
            }
            #infoTable {
                width: 100%;
                border-collapse: collapse;
                font-family: Arial, sans-serif;
                margin: 20px 0;
                box-shadow: 0 2px 3px rgba(0, 0, 0, 0.1);
            }
            #infoTable th, #infoTable td {
                padding: 12px 15px;
                text-align: left;
                border-bottom: 1px solid #ddd;
            }
            #infoTable th {
                background-color: #0ea9eb;
                color: #ffffff;
                text-transform: uppercase;
            }
            #infoTable tr:nth-child(even) {
                background-color: #f3f3f3;
            }
            #infoTable tr:hover {
                background-color: #f1f1f1;
            }
            #infoTable td {
                color: #333;
            }
            #toggleAllBlocksButton {
                cursor: pointer;
                color: #fff;
                background-color: #007BFF; /* 按钮背景颜色 */
                border: none;
                padding: 10px 20px;
                margin-bottom: 3px;
                font-size: 14px;
                border-radius: 5px; /* 圆角 */
                transition: background-color 0.3s ease; /* 过渡效果 */
            }

            #toggleAllBlocksButton:hover {
                background-color: #48abe8; /* 悬停时背景颜色 */
            }
            #toggleAllBlocksButton:active {
                background-color: #003d80; /* 点击时背景颜色 */
            }

        </style>
    </head>
    <body>
        <div class="container">
            <h1>Linux应急响应报告</h1>
                <!-- 搜索表单 -->
                <div id="searchFormContainer">
                    <form id="searchForm">
                        <input type="text" id="searchInput" name="searchInput" placeholder="请输入关键字" onkeypress="handleKeyPress(event)">
                        <button type="button" id="searchButton" class="toggle-button" onclick="searchText()">搜索</button>
                        <button type="button" id="clearButton" class="toggle-button" onclick="clearSearch()">清空</button>
                    </form>
                </div>
                <!-- 其他页面内容 -->


            <!-- 匹配结果容器 -->
            <div id="searchResult" class="rush-code"></div>

            <div class="section">
                <h2 class="t1">T0001 事件概要</h2><hr />
                <div class="section-content">
                    <p><strong>事件日期：</strong> $event_date</p>
                    <label for="eventType"><strong>事件类型：</strong></label>
                        <select id="eventType" onchange="updateDescriptionAndSuggestion()">
                            <option value="网络攻击" selected>网络攻击</option>
                            <option value="web攻击">web攻击</option>
                            <option value="数据泄露">数据泄露</option>
                            <option value="恶意软件">恶意软件</option>
                            <option value="网页篡改">网页篡改</option>
                            <option value="挖矿病毒">挖矿病毒</option>
                            <option value="勒索病毒">勒索病毒</option>
                            <option value="社工钓鱼">社工钓鱼</option>
                            <!-- 其他事件类型选项 -->
                        </select>
                    <br>
                    <span class="bold">事件描述：</span>
                    <span id="eventDescription"></span>
                </div>
            </div>
            <div class="section">
                <h2 class="t1">T0002 调查结果</h2><hr />
                <div class="section-content">
                    <p><strong>受影响系统：</strong> 内部服务器</p>
                    <span class="bold">攻击方式：</span>
                    <span id="eventAttackTypes"></span>
                    <p><strong>攻击者身份：</strong> 未知</p>
                    <p><strong>攻击源IP地址：</strong> <input type="text" id="attackerIP" value="192.168.0.1"></p>
                    <p class="highlighted-info" id="highlightedCommandsInfo"></p>
                    <p class="highlighted-info" id="highlightedUsersInfo"></p>
                    <p class="highlighted-info" id="total"></p>
                </div>
            </div>
            <div class="section">
                <h2 class="t1">T0003 响应措施</h2><hr />
                <div class="section-content">
                    <p><strong>应急响应团队：</strong> <input type="text" id="team" value="Eonian Sharp Team"></p>
                    <p><strong>处理步骤：</strong></p>

                    <h5 class="t3">临时处置</h5>
                    <ul>
                        <li>物理隔离 - 禁用网卡，线路隔离</li>
                        <li>访问控制 - 限制端口，对用户、权限、文件的访问控制</li>
                        <li>更新病毒库、开启防火墙、关闭高危端口、打补丁</li>
                    </ul>
                    <h5 class="t3">应急分析</h5>
                    <ul>
                        <li>分析攻击流量信息</li>
                        <li>阻止攻击流量</li>
                        <li>定位攻击源</li>
                        <li>确定感染范围</li>
                        <li>加强网络安全配置</li>
                    </ul>
                    <h5 class="t3">应急排查</h5>
                    <ul>
                        <li>端口</li>
                        <li>进程</li>
                        <li>网络外联</li>
                        <li>用户</li>
                        <li>计划任务</li>
                        <li>开机启动项</li>
                        <li>敏感目录</li>
                        <li>历史命令</li>
                        <li>系统/Web日志</li>
                    </ul>
                </div>
            </div>
            <div class="section">
                <h2 class="t1">T0004 取证内容</h2><hr />
                <div class="section-content">
                    <p class="t2">系统信息：</p>
                    <table id="infoTable">
                        <tr>
                            <th>名称</th>
                            <th>详细信息</th>
                        </tr>
                        <tr>
                            <td>本机IP地址</td>
                            <td>$IP</td>
                        </tr>
                        <tr>
                            <td>本机子网掩码</td>
                            <td>$ZW</td>
                        </tr>
                        <tr>
                            <td>本机网关</td>
                            <td>$GW</td>
                        </tr>
                        <tr>
                            <td>当前在线用户</td>
                            <td>$TUN</td>
                        </tr>
                        <tr>
                            <td>本机主机名</td>
                            <td>$HN</td>
                        </tr>
                        <tr>
                            <td>本机DNS</td>
                            <td>$DNS</td>
                        </tr>
                        <tr>
                            <td>系统版本</td>
                            <td>$OS</td>
                        </tr>
                        <tr>
                            <td>系统内核</td>
                            <td>$OSNAME</td>
                        </tr>
                        <tr>
                            <td>时间戳[本地]</td>
                            <td>$M_TIME</td>
                        </tr>
                    </table>
                    <p class="t2">系统状态：</p>
                    <table id="infoTable">
                        <tr>
                            <th>名称</th>
                            <th>详细信息</th>
                        </tr>
                        <tr>
                            <td>内存</td>
                            <td>$TA</td>
                        </tr>
                        <tr>
                            <td>磁盘</td>
                            <td>$TB</td>
                        </tr>
                        <tr>
                            <td>CPU</td>
                            <td>$TC</td>
                        </tr>
                    </table>
                    <p class="t2">风险排查：</p>
                    <table id="infoTable">
                        <tr>
                            <th>名称</th>
                            <th>详细信息</th>
                        </tr>
                        <tr>
                            <td>僵尸进程</td>
                            <td>$kill_process</td>
                        </tr>
                        <tr>
                            <td>Redis未授权</td>
                            <td>$redis_risk</td>
                        </tr>
                        <tr>
                            <td>CVE-2018-15473(OpenSSH用户名枚举)</td>
                            <td>$openssh_risk</td>
                        </tr>
                        <tr>
                            <td>CVE-2024-6387(OpenSSH远程代码执行)</td>
                            <td>$sv$opensshvul</td>
                        </tr>
                        <tr>
                            <td>SSH软链接后门</td>
                            <td>$sshlink</td>
                        </tr>
                        <tr>
                            <td>SSH Wrapper后门</td>
                            <td>$sshwrapper</td>
                        </tr>
                        <tr>
                            <td>SSH PublicKey修改时间与权限</td>
                            <td>$sshpubkey</td>
                        </tr>
                    </table>
                    <button id="toggleAllBlocksButton"  onclick="toggleAllBlocks()">全部收起/展开</button>
                    <p class="t2">进程、端口服务、网络外联：</p>
                    <h5 class="t3">进程</h5>
                    <span class="toggle-button" onclick="toggleBlock('processInfoBlock')">收起/展开</span><span class="toggle-button" id="backToTopButton" onclick="scrollToTop()">↑</span><span class="toggle-button" onclick="toggleAllBlocks()">A</span>
                    <div id="processInfoBlockParent" class="code-block-container">
                        <div class="code-block" id="processInfoBlock">
                        <pre>$process_info</pre>
                        </div>
                    </div>
                    <h5 class="t3">端口-服务</h5>
                    <span class="toggle-button" onclick="toggleBlock('portserviceInfoBlock')">收起/展开</span><span class="toggle-button" id="backToTopButton" onclick="scrollToTop()">↑</span><span class="toggle-button" onclick="toggleAllBlocks()">A</span>
                    <div id="portserviceInfoBlockParent" class="code-block-container">
                        <div class="code-block" id="portserviceInfoBlock">
                        <pre>$portsvt_info</pre>
                        <pre>$service_info</pre>
                        </div>
                    </div>
                    <h5 class="t3">服务具体信息</h5>
                    <span class="toggle-button" onclick="toggleBlock('serviceinfoInfoBlock')">收起/展开</span><span class="toggle-button" id="backToTopButton" onclick="scrollToTop()">↑</span><span class="toggle-button" onclick="toggleAllBlocks()">A</span>
                    <div id="serviceinfoInfoBlockParent" class="code-block-container">
                        <div class="code-block" id="serviceinfoInfoBlock">
                        <pre>$service_show</pre>
                        </div>
                    </div>
                    <h5 class="t3">网络</h5>
                    <span class="toggle-button" onclick="toggleBlock('networkInfoBlock')">收起/展开</span><span class="toggle-button" id="backToTopButton" onclick="scrollToTop()">↑</span><span class="toggle-button" onclick="toggleAllBlocks()">A</span>
                    <div id="networkInfoBlockParent" class="code-block-container">
                        <div class="code-block" id="networkInfoBlock">
                        <pre>$network_info</pre>
                        <pre>$lsof_info</pre>
                        </div>
                    </div>
                    <p class="t2">用户：</p>
                    <h5 class="t3">/etc/passwd</h5>
                    <span class="toggle-button" onclick="toggleBlock('userInfoBlock')">收起/展开</span><span class="toggle-button" id="backToTopButton" onclick="scrollToTop()">↑</span><span class="toggle-button" onclick="toggleAllBlocks()">A</span>
                    <div id="userInfoBlockParent" class="code-block-container">
                        <div class="code-block" id="userInfoBlock">
                        <pre id=passwdContent>$user_info</pre>
                        </div>
                    </div>
                    <h5 class="t3">/etc/shadow</h5>
                    <span class="toggle-button" onclick="toggleBlock('passInfoBlock')">收起/展开</span><span class="toggle-button" id="backToTopButton" onclick="scrollToTop()">↑</span><span class="toggle-button" onclick="toggleAllBlocks()">A</span>
                    <div id="passInfoBlockParent" class="code-block-container">
                        <div class="code-block" id="passInfoBlock">
                        <pre>$pass_info</pre>
                        </div>
                    </div>
                    <h5 class="t3">/etc/group</h5>
                    <span class="toggle-button" onclick="toggleBlock('groupInfoBlock')">收起/展开</span><span class="toggle-button" id="backToTopButton" onclick="scrollToTop()">↑</span><span class="toggle-button" onclick="toggleAllBlocks()">A</span>
                    <div id="groupInfoBlockParent" class="code-block-container">
                        <div class="code-block" id="groupInfoBlock">
                        <pre>$grop_info</pre>
                        </div>
                    </div>
                    <p class="t2">历史命令：</p>
                    <h5 class="t3">当前用户</h5>
                    <span class="toggle-button" onclick="toggleBlock('historycInfoBlock')">收起/展开</span><span class="toggle-button" id="backToTopButton" onclick="scrollToTop()">↑</span><span class="toggle-button" onclick="toggleAllBlocks()">A</span>
                    <div id="historycInfoBlockParent" class="code-block-container">
                        <div class="code-block" id="historycInfoBlock">
                        <pre id="commandHistory">$histcurrent_info</pre>
                        </div>
                    </div>
                    <h5 class="t3">普通用户</h5>
                    <span class="toggle-button" onclick="toggleBlock('historyInfoBlock')">收起/展开</span><span class="toggle-button" id="backToTopButton" onclick="scrollToTop()">↑</span><span class="toggle-button" onclick="toggleAllBlocks()">A</span>
                    <div id="historyInfoBlockParent" class="code-block-container">
                        <div class="code-block" id="historyInfoBlock">
                        <pre id="commandHistory">$histcmd_info</pre>
                        </div>
                    </div>

                    <p class="t2">计划任务：</p>
                    <h5 class="t3">crontab -l</h5>
                    <span class="toggle-button" onclick="toggleBlock('c1Block')">收起/展开</span><span class="toggle-button" id="backToTopButton" onclick="scrollToTop()">↑</span><span class="toggle-button" onclick="toggleAllBlocks()">A</span>
                    <div id="c1BlockParent" class="code-block-container">
                        <div class="code-block" id="c1Block">
                        <pre>$crontab1_info</pre>
                        </div>
                    </div>
                    <h5 class="t3">/var/spool/cron/*</h5>
                    <span class="toggle-button" onclick="toggleBlock('c2Block')">收起/展开</span><span class="toggle-button" id="backToTopButton" onclick="scrollToTop()">↑</span><span class="toggle-button" onclick="toggleAllBlocks()">A</span>
                    <div id="c2BlockParent" class="code-block-container">
                        <div class="code-block" id="c2Block">
                        <pre>$crontab2_info</pre>
                        </div>
                    </div>
                    <h5 class="t3">/etc/cron.*/*</h5>
                    <span class="toggle-button" onclick="toggleBlock('c3Block')">收起/展开</span><span class="toggle-button" id="backToTopButton" onclick="scrollToTop()">↑</span><span class="toggle-button" onclick="toggleAllBlocks()">A</span>
                    <div id="c3BlockParent" class="code-block-container">
                        <div class="code-block" id="c3Block">
                        <pre>$crontab3_info</pre>
                        </div>
                    </div>
                    <h5 class="t3">/etc/crontab</h5>
                    <span class="toggle-button" onclick="toggleBlock('c4Block')">收起/展开</span><span class="toggle-button" id="backToTopButton" onclick="scrollToTop()">↑</span><span class="toggle-button" onclick="toggleAllBlocks()">A</span>
                    <div id="c4BlockParent" class="code-block-container">
                        <div class="code-block" id="c4Block">
                        <pre>$crontab4_info</pre>
                        </div>
                    </div>
                    <p class="t2">启动项：</p>
                    <h5 class="t3">list-unit-files</h5>
                    <span class="toggle-button" onclick="toggleBlock('initpidInfoBlock')">收起/展开</span><span class="toggle-button" id="backToTopButton" onclick="scrollToTop()">↑</span><span class="toggle-button" onclick="toggleAllBlocks()">A</span>
                    <div id="initpidInfoBlockParent" class="code-block-container">
                        <div class="code-block" id="initpidInfoBlock">
                        <pre>$initpid_info</pre>
                        </div>
                    </div>
                    <h5 class="t3">cat /etc/init.d</h5>
                    <span class="toggle-button" onclick="toggleBlock('initpid1InfoBlock')">收起/展开</span><span class="toggle-button" id="backToTopButton" onclick="scrollToTop()">↑</span><span class="toggle-button" onclick="toggleAllBlocks()">A</span>
                    <div id="initpid1InfoBlockParent" class="code-block-container">
                        <div class="code-block" id="initpid1InfoBlock">
                        <pre>$initd_info</pre>
                        </div>
                    </div>
                    <h5 class="t3">cat /etc/rc*/*</h5>
                    <span class="toggle-button" onclick="toggleBlock('initpid2InfoBlock')">收起/展开</span><span class="toggle-button" id="backToTopButton" onclick="scrollToTop()">↑</span><span class="toggle-button" onclick="toggleAllBlocks()">A</span>
                    <div id="initpid2InfoBlockParent" class="code-block-container">
                        <div class="code-block" id="initpid2InfoBlock">
                        <pre>$initrc_info</pre>
                        </div>
                    </div>
                    <p class="t2">用户登录排查：</p>
                    <h5 class="t3">全量登录日志 $userlog_file</h5>
                    <span class="toggle-button" onclick="toggleBlock('userlogInfoBlock')">收起/展开</span><span class="toggle-button" id="backToTopButton" onclick="scrollToTop()">↑</span><span class="toggle-button" onclick="toggleAllBlocks()">A</span>
                    <div id="userlogInfoBlockParent" class="code-block-container">
                        <div class="code-block" id="userlogInfoBlock">
                        <pre>$userlog_info</pre>
                        </div>
                    </div>
                    <h5 class="t3">用户登录分析</h5>
                    <span class="toggle-button" onclick="toggleBlock('testInfoBlock')">收起/展开</span><span class="toggle-button" id="backToTopButton" onclick="scrollToTop()">↑</span><span class="toggle-button" onclick="toggleAllBlocks()">A</span>
                    <div id="testInfoBlockParent" class="code-block-container">
                        <div class="code-block" id="testInfoBlock">
                        <pre>$userlogin</pre>
                        </div>
                    </div>
                    <p class="t2">文件操作：</p>
                    <h5 class="t3">近3天操作的文件</h5>
                    <span class="toggle-button" onclick="toggleBlock('fileInfoBlock')">收起/展开</span><span class="toggle-button" id="backToTopButton" onclick="scrollToTop()">↑</span><span class="toggle-button" onclick="toggleAllBlocks()">A</span>
                    <div id="fileInfoBlockParent" class="code-block-container">
                        <div class="code-block" id="fileInfoBlock">
                        <pre>$M_FILE</pre>
                        <pre>$M_FILE_VAR</pre>
                        <pre>$C_FILE</pre>
                        </div>
                    </div>
                    <h5 class="t3">创建文件位置文件信息</h5>
                    <span class="toggle-button" onclick="toggleBlock('fileinfoInfoBlock')">收起/展开</span><span class="toggle-button" id="backToTopButton" onclick="scrollToTop()">↑</span><span class="toggle-button" onclick="toggleAllBlocks()">A</span>
                    <div id="fileinfoInfoBlockParent" class="code-block-container">
                        <div class="code-block" id="fileinfoInfoBlock">
                        <pre>$fileinfo_output</pre>
                        </div>
                    </div>
                    <p class="t2">SSH后门排查：</p>
                    <h5 class="t3">SSH后门进程排查</h5>
                    <span class="toggle-button" onclick="toggleBlock('sshInfoBlock')">收起/展开</span><span class="toggle-button" id="backToTopButton" onclick="scrollToTop()">↑</span><span class="toggle-button" onclick="toggleAllBlocks()">A</span>
                    <div id="sshBlockParent" class="code-block-container">
                        <div class="code-block" id="sshInfoBlock">
                        <pre>$ssh_info</pre>
                        </div>
                    </div>
                    <p class="t2">环境变量后门排查：</p>
                    <h5 class="t3">alias别名后门</h5>
                    <span class="toggle-button" onclick="toggleBlock('aliasInfoBlock')">收起/展开</span><span class="toggle-button" id="backToTopButton" onclick="scrollToTop()">↑</span><span class="toggle-button" onclick="toggleAllBlocks()">A</span>
                    <div id="aliasBlockParent" class="code-block-container">
                        <div class="code-block" id="aliasInfoBlock">
                        <pre>$env_alias_info</pre>
                        </div>
                    </div>
                    <h5 class="t3">/root/.bashrc</h5>
                    <span class="toggle-button" onclick="toggleBlock('profile1InfoBlock')">收起/展开</span><span class="toggle-button" id="backToTopButton" onclick="scrollToTop()">↑</span><span class="toggle-button" onclick="toggleAllBlocks()">A</span>
                    <div id="profile1BlockParent" class="code-block-container">
                        <div class="code-block" id="profile1InfoBlock">
                        <pre>$env_profile1</pre>
                        </div>
                    </div>
                    <h5 class="t3">/root/.*shrc</h5>
                    <span class="toggle-button" onclick="toggleBlock('profile2InfoBlock')">收起/展开</span><span class="toggle-button" id="backToTopButton" onclick="scrollToTop()">↑</span><span class="toggle-button" onclick="toggleAllBlocks()">A</span>
                    <div id="profile2BlockParent" class="code-block-container">
                        <div class="code-block" id="profile2InfoBlock">
                        <pre>$env_profile2</pre>
                        </div>
                    </div>
                    <h5 class="t3">/etc/bashrc</h5>
                    <span class="toggle-button" onclick="toggleBlock('profile3InfoBlock')">收起/展开</span><span class="toggle-button" id="backToTopButton" onclick="scrollToTop()">↑</span><span class="toggle-button" onclick="toggleAllBlocks()">A</span>
                    <div id="profile3BlockParent" class="code-block-container">
                        <div class="code-block" id="profile3InfoBlock">
                        <pre>$env_profile3</pre>
                        </div>
                    </div>
                    <h5 class="t3">/root/.bash_profile</h5>
                    <span class="toggle-button" onclick="toggleBlock('profile4InfoBlock')">收起/展开</span><span class="toggle-button" id="backToTopButton" onclick="scrollToTop()">↑</span><span class="toggle-button" onclick="toggleAllBlocks()">A</span>
                    <div id="profile4BlockParent" class="code-block-container">
                        <div class="code-block" id="profile4InfoBlock">
                        <pre>$env_profile4</pre>
                        </div>
                    </div>
                    <h5 class="t3">普通用户环境变量配置文件</h5>
                    <span class="toggle-button" onclick="toggleBlock('profilehomeInfoBlock')">收起/展开</span><span class="toggle-button" id="backToTopButton" onclick="scrollToTop()">↑</span><span class="toggle-button" onclick="toggleAllBlocks()">A</span>
                    <div id="profilehomeBlockParent" class="code-block-container">
                        <div class="code-block" id="profilehomeInfoBlock">
                        <pre>$env_homeprofile_info</pre>
                        </div>
                    </div>
                    <p class="t2">恶意文件排查：</p>
                    <h5 class="t3">bin文件hash</h5>
                    <span class="toggle-button" onclick="toggleBlock('hashInfoBlock')">收起/展开</span><span class="toggle-button" id="backToTopButton" onclick="scrollToTop()">↑</span><span class="toggle-button" onclick="toggleAllBlocks()">A</span>
                    <div id="hashBlockParent" class="code-block-container">
                        <div class="code-block" id="hashInfoBlock">
                        <pre>$HASH</pre>
                        </div>
                    </div>
                </div>
            </div>
            <div class="section">
                <h2 class="t1">T0005 总结与建议</h2><hr />
                <div class="section-content">
                    <p><strong>总结：</strong> 成功防止了进一步损害，但系统仍需进一步检查和加固。</p>
                    <span class="bold">建议：</span>
                    <span id="repairSuggestion"></span>
                </div>
            </div>

            <!-- 技术支持和版权声明 -->
            <div class="line"></div>
            <div class="copyright">
                Supported by: 永恒之锋实验室 - $VER<br>
                Copyright © 2024 Eonian Sharp Security Team
            </div>
        </div>

        <!-- 计数器逻辑 -->
        <script>
            // 该我正则上场啦，原谅我一生放浪不羁爱自由，checkit~~~now~
            var totalHighlightedCommands = 0; // 用于统计命令标记的全局计数器
            var totalHighlightedUsers = 0; // 用于统计用户标记的全局计数器

            // 标记命令
            function highlightCommands() {
                var preElement = document.getElementById('commandHistory');
                var lines = preElement.textContent.split('\n');

                var keywords = ['curl', 'wget', 'useradd', 'ping', 'rm', 'chmod', 'nc', 'exec'];

                var regex = new RegExp('(' + keywords.join('|') + ')', 'g');
                var counter = 0; // 命令计数器

                for (var i = 0; i < lines.length; i++) {
                    var line = lines[i];
                    var matches = line.match(regex); // 获取匹配项数组

                    if (matches) {
                        counter += matches.length; // 增加计数器数量
                        lines[i] = line.replace(regex, '<span class="highlighted-command">$&</span>');
                    }
                }

                preElement.innerHTML = lines.join('\n');

                totalHighlightedCommands += counter; // 累加到全局计数器

                return counter; // 返回当前函数的计数器结果
            }
            window.addEventListener('load', function() {
                highlightCommands();
            });

            // 标记权限为 0 的用户
            function highlightUsers() {
                var preElement = document.getElementById('passwdContent');
                var lines = preElement.textContent.split('\n');

                var regex = /(\S+:x:0:\d+?)/g;
                var counter = 0; // 用户计数器

                for (var i = 0; i < lines.length; i++) {
                    var line = lines[i];
                    var matches = line.match(regex); // 获取匹配项数组

                    if (matches) {
                        counter += matches.length; // 增加计数器数量
                        lines[i] = line.replace(regex, '<span class="highlighted-command">$&</span>');
                    }
                }

                preElement.innerHTML = lines.join('\n');

                totalHighlightedUsers += counter; // 累加到全局计数器

                return counter; // 返回当前函数的计数器结果
            }

            // 在页面加载完成后执行标记命令的函数
            window.addEventListener('load', function() {
                totalHighlightedCommands += highlightCommands();
                totalHighlightedUsers += highlightUsers();
                total = totalHighlightedCommands + totalHighlightedUsers;
                // 在页面中显示标记的总数
                document.getElementById('highlightedCommandsInfo').innerHTML= '可疑命令计数: <span class="highlighted-number">' + totalHighlightedCommands + '</span>';
                document.getElementById('highlightedUsersInfo').innerHTML = '可疑用户计数: <span class="highlighted-number">' + totalHighlightedUsers + '</span>';
                document.getElementById('total').innerHTML = '可疑标记总数: <span class="highlighted-number">' + total + '</span>';
                highlightUsers();
            });

        </script>
        <!-- 搜索逻辑 -->
        <script>
            // 处理回车键
            function handleKeyPress(event) {
                if (event.key === 'Enter') {
                    event.preventDefault();
                    if (searchText !== '') {
                        searchText();
                    } else {
                        // var resultContainer = document.getElementById('searchResult');
                        // resultContainer.innerHTML = '<p>未输入搜索文本。</p>';
                    }
                }
            }

            // 页面加载完成时执行
            document.addEventListener('DOMContentLoaded', function() {
                // 获取结果容器
                var resultContainer = document.getElementById('searchResult');

                // 初始状态下结果容器不显示
                resultContainer.style.display = 'none';

                // 获取搜索按钮
                var searchButton = document.getElementById('searchButton');

                // 点击搜索按钮时执行搜索函数
                searchButton.addEventListener('click', function() {
                    searchText();
                });
            });

    // 搜索核心代码
    function searchText() {
        var searchText = document.getElementById('searchInput').value;
        if (searchText === '' || searchText === ' ') {
            searchText = 'Eno&Eoniansharp';
        }

        var resultContainer = document.getElementById('searchResult');
        resultContainer.innerHTML = ''; // 清空搜索结果容器

        var searchRegex = new RegExp(searchText, 'gi'); // 正则的模式，别不认识 g就算全局， i就是忽略大小写
        var matchFound = false;

        // 查找所有包含 pre 元素的父级 div
        var preElements = document.querySelectorAll('div > div > pre');

        preElements.forEach(function(preElement) {
            // 移除已有的标记
            removeHighlight(preElement);

            var content = preElement.innerHTML;
            var lines = content.split('\n'); // 拆分成行
            lines.forEach(function(line, index) {
                if (line.match(searchRegex)) {
                    matchFound = true;
                    var highlightedLine = line.replace(searchRegex, '<span class="highlighted-text">$&</span>');
                    var matchLine = document.createElement('p');
                    matchLine.innerHTML = highlightedLine;
                    var matchLink = document.createElement('a');
                    matchLink.innerHTML = '  rush';
                    matchLink.href = '#'; // 设置链接的 href 为 '#'，以便点击时不跳转
                    matchLink.classList.add('rusha');
                    matchLink.onclick = function() {
                        expandAndScrollToPosition(preElement, searchText, index); // 点击链接时调用 expandAndScrollToPosition 函数，并传入搜索文本和行号
                        return false; // 阻止默认行为
                    };
                    matchLine.appendChild(matchLink);
                    resultContainer.appendChild(matchLine);
                }
            });
        });

        if (matchFound) {
            resultContainer.style.display = 'block'; // 显示结果容器
            resultContainer.classList.add('rush-code'); // 添加匹配时的样式类
        } else {
            resultContainer.classList.add('rush-code'); // 添加匹配时的样式类
            resultContainer.innerHTML = '<p>内容未匹配。</p>'; // 在结果容器中显示提示信息
        }
    }

    // 展开并滚动且标记
    function expandAndScrollToPosition(preElement, searchText, lineIndex) {
        console.log('expandAndScrollToPosition called');
        console.log('preElement:', preElement);
        console.log('searchText:', searchText);
        console.log('lineIndex:', lineIndex);

        // 清理所有已有的标记样式
        clearAllHighlights();

        // 先滚动到 pre 元素的位置
        preElement.scrollIntoView({ behavior: 'smooth', block: 'start' });

        // 展开包含 pre 元素的父级容器
        var container = preElement.parentElement;
        var blockId = container.id;

        // 标记搜索到的内容
        highlightSearchResults(preElement, searchText);

        // 等待滚动完成后再展开
        setTimeout(function() {
            // 创建 MutationObserver 以监听元素变化
            var observer = new MutationObserver(function(mutations) {
                mutations.forEach(function(mutation) {
                    if (mutation.type === 'attributes' && mutation.attributeName === 'style') {
                        // 检查容器是否已经展开
                        if (container.style.maxHeight === container.scrollHeight + 'px') {
                            console.log('Container expanded');
                            // 滚动到具体的行
                            scrollToLine(preElement, lineIndex);
                            observer.disconnect(); // 完成滚动后断开观察器
                        }
                    }
                });
            });

            observer.observe(container, { attributes: true });

            // 调用 toggleBlock 函数展开父级容器
            toggleBlock(blockId);
        }, 1000); // 等待滚动完成
    }

    function scrollToLine(preElement, lineIndex) {
        console.log('scrollToLine called');
        console.log('lineIndex:', lineIndex);

        // 获取所有行
        var lines = preElement.innerText.split('\n'); // 使用 innerText 获取文本内容
        console.log('lines:', lines);

        // 获取目标行
        var targetLine = lines[lineIndex].trim(); // 去除目标行的前后空格
        console.log('targetLine:', targetLine);

        // 直接在目标行上添加标记类
        lines[lineIndex] = \`<span class="highlighted-text">${targetLine}</span>\`;
        preElement.innerHTML = lines.join('\n');

        // 获取目标元素
        var targetElement = preElement.querySelector('.highlighted-text');

        // 滚动到目标元素
        targetElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }

    // 清理所有已有的标记样式
    function clearAllHighlights() {
        var highlightedElements = document.querySelectorAll('.highlighted-text');
        highlightedElements.forEach(function(element) {
            var parent = element.parentNode;
            parent.replaceChild(document.createTextNode(element.innerText), element);
        });
    }
    // 标记函数
    function highlightSearchResults(preElement, searchText) {
        var searchRegex = new RegExp(searchText, 'gi');
        var content = preElement.innerHTML;
        var highlightedContent = content.replace(searchRegex, '<span class="highlighted-text">$&</span>');
        preElement.innerHTML = highlightedContent;
    }



    // 清空函数
    function clearSearch() {
        // 清空搜索输入框
        document.getElementById('searchInput').value = '';

        // 清空搜索结果容器
        var resultContainer = document.getElementById('searchResult');
        resultContainer.innerHTML = '';
        resultContainer.style.display = 'none';

        // 移除所有已标记的内容
        var preElements = document.querySelectorAll('div > div > pre');
        preElements.forEach(function(preElement) {
            removeHighlight(preElement);
        });
        // 刷新页面
        location.reload();
    }

    // 移除高亮（下一次搜索）
    function removeHighlight(preElement) {
        var content = preElement.innerHTML;
        var cleanedContent = content.replace(/<span class="highlighted-text">(.*?)<\/span>/gi, '$1');
        preElement.innerHTML = cleanedContent;
    }



    // 展开、收起、展开、收起、展开、收起
    function toggleBlock(id) {
        var block = document.getElementById(id).parentElement;
        console.log('Toggling block:', id);
        var currentHeight = block.clientHeight;
        var targetHeight = block.scrollHeight;

        if (currentHeight === targetHeight) {
            block.style.maxHeight = '92px';
        } else {
            block.style.maxHeight = targetHeight + 'px';
        }

        // 确保展开动画完成后再进行滚动
        setTimeout(function() {
            console.log('Block toggled:', id);
        }, 600); // 确保与 CSS 中的过渡时间一致
    }

    // 控制所有展开、收起（A）
    function toggleAllBlocks() {
        var blocks = document.querySelectorAll('.code-block-container');
        var allExpanded = Array.from(blocks).every(function(block) {
            return block.clientHeight === block.scrollHeight;
        });

        blocks.forEach(function(block) {
            if (allExpanded) {
                block.style.maxHeight = '92px';
            } else {
                block.style.maxHeight = block.scrollHeight + 'px';
            }
        });
    }

    // 滚动到最顶部（↑）
    function scrollToTop() {
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }
        </script>
        <!-- 类型逻辑 -->
        <script>
            window.onload = function() {
                updateDescriptionAndSuggestion(); // 页面加载时调用函数更新描述和建议
            };

            function updateDescriptionAndSuggestion() {
                var eventType = document.getElementById('eventType').value;
                var eventDescription = '';
                var repairSuggestion = '';
                var eventAttackTypes = '';

                switch (eventType) {
                    case '网络攻击':
                        eventDescription = '公司内部网络遭受DDoS攻击，计算机资源被占用造成网络服务不可用。';
                        repairSuggestion = '封锁攻击源IP地址，增加防火墙规则，更新安全策略。';
                        eventAttackTypes = 'DDoS攻击';
                        break;
                    case 'web攻击':
                        eventDescription = '公司官网遭受SQL注入攻击，用户个人信息被泄露。';
                        repairSuggestion = '修复SQL注入漏洞，增加用户输入校验。';
                        eventAttackTypes = 'SQL注入';
                        break;
                    case '数据泄露':
                        eventDescription = '公司数据库遭受数据泄露，用户个人信息外泄。';
                        repairSuggestion = '修复数据库漏洞，加强数据加密措施。';
                        eventAttackTypes = '数据库攻击';
                        break;
                    case '恶意软件':
                        eventDescription = '公司部分计算机感染勒索软件，文件被加密勒索。';
                        repairSuggestion = '隔离感染计算机，更新杀毒软件，恢复文件备份。';
                        eventAttackTypes = '勒索软件';
                        break;
                    case '网页篡改':
                        eventDescription = '公司官网首页被篡改，显示恶意广告链接。';
                        repairSuggestion = '恢复网站备份，增强网站安全防护措施。';
                        eventAttackTypes = '网站篡改';
                        break;
                    case '挖矿病毒':
                        eventDescription = '公司服务器感染挖矿病毒，CPU资源被挖矿程序占用。';
                        repairSuggestion = '清除挖矿病毒，增加系统安全监控。';
                        eventAttackTypes = '挖矿病毒';
                        break;
                    case '勒索病毒':
                        eventDescription = '公司部分计算机感染勒索病毒，文件被加密勒索。';
                        repairSuggestion = '隔离感染计算机，更新杀毒软件，恢复文件备份。';
                        eventAttackTypes = '勒索病毒';
                        break;
                    case '社工钓鱼':
                        eventDescription = '公司员工收到钓鱼邮件，泄露公司内部账号密码。';
                        repairSuggestion = '加强员工网络安全意识培训，设置安全邮件过滤规则。';
                        eventAttackTypes = '社工攻击';
                        break;
                    default:
                        eventDescription = '未知事件类型';
                        repairSuggestion = '建议增加对未知事件类型的处理方案。';
                        eventAttackTypes = '未知攻击类型';
                }

                document.getElementById('eventDescription').innerText = eventDescription;
                document.getElementById('repairSuggestion').innerText = repairSuggestion;
                document.getElementById('eventAttackTypes').innerText = eventAttackTypes;
                // window.addEventListener('load', function() {
                //     updateDescriptionAndSuggestion();
                // });
            }
        </script>
    </body>
    </html>
EOF
    printf "$SUC 导出Html结果成功。路径：$OUTPUT_M/$html_name\n"
    rm -f $OUTPUT/who_*
}

# [ ++ OPTIONS PARAMETE ++ ]

function fk_options
{
    op="${1}"
    case ${op} in
        -a | --all)
            fk_baseinfo     # 基本消息
            fk_devicestatus # 基本状态
            fk_userlogin    # 登录日志
            ;;
        -b | --baseline)
            fk_baseline
            ;;
        -c | --code) LIST="$2"
            fk_http_scan "$LIST"
            ;;
        -e | --auto-run) HOUR="$2" MINUTE="$3"
            fk_auto_run "$HOUR" "$MINUTE"
            ;;
        -h | --help)
            help_cn
            ;;
        -i | --sqletlog) ACCESS_PATH="$2"
            fk_weblog_sqlianalysis "$ACCESS_PATH"
            ;;
        -k | --rootkitcheck)
            fk_rookit_analysis
            ;;
        -l | --login) FILE="$2"
            fk_userlogin "$FILE" "$SECURE_FILE"
            ;;
        -m | --html) REPORT_NAME="$2"
            fk_reporthtml "$REPORT_NAME"
            ;;
        -n | --nomal)
            fk_baseinfo
            fk_history
            fk_crontab
            fk_filemove
            fk_fileinfo
            fk_userinfo
            ;;
        -o | --output) OUT_NAME="$2"
            fk_output "$OUT_NAME"
            ;;
        -p | --port)
            fk_portstatus
            ;;
        -r | --risk)
            fk_vulcheck
            ;;
        -s | --os-status)
            fk_devicestatus
            ;;
        -t | --terminalproxy) INPUT="$2"
            fk_terminal_proxy "$INPUT"
            ;;
        -u | --user-device)
            fk_baseinfo
            ;;
        -v | --version)
            echo "$VER"
            ;;
        -w | --webshell) WEBSHELL_PATH="$2"
            fk_wsfinder "$WEBSHELL_PATH"
            ;;
        -x | --proc-serv)
            fk_procserv
            ;;
        -y | --whoamifuck)
            fk_autofuck
            ;;
        -z | --ext) EXT_PATH="$2"
            fk_extention "$EXT_PATH"
            ;;
        *)
            help_en
            ;;
    esac
}

# --------------------------------------
#        | Whoamifuck Main |
# --------------------------------------

function fk_main
{
    color
    if [ "$EUID" -ne 0 ]; then
        printf "${redx}[-] This script must be run as root${reset}\n"
        exit 1
    else
        fk_command
        fk_options "$@"
    fi
}

###################
fk_main "$@"
###################

# --------------------------------------
#        | Futher |
# --------------------------------------


