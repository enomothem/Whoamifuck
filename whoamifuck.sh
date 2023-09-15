#!/bin/bash
# Linux入侵检测报告工具-Whoamifuck5.2.0
# Author:Enomothem
# Time:2021年2月8日
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

# [ ++ 基本信息 ++ ]

VER="2023.9.15@whoamifuck-version 5.2.0"

# [ ++ 颜色变量预定义 ++ ]

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

# [ ++ 标量变量声明区 ++ ]

# ;; File Statement

AUTHLOG_FILE="/var/log/auth.log" # 默认访问的用户日志路径
SECURE_FILE="/var/log/secure" 	 # Centos默认用户日志
RESOLV_FILE="/etc/resolv.conf" 	 # DNS文件



WHOAMIFUCK=`whoami`

M_TIME=`date +"%Y-%m-%d %H:%M:%S %s"`
ETH=`ifconfig -s | grep ^e | awk '{print $1}'`
IP=`ifconfig $ETH | head -2 | tail -1 | awk '{print $2}'`
ZW=`ifconfig $ETH | head -2 | tail -1 | awk '{print $4}'`
GW=`route -n | tail -1 | awk '{print $1}'`
HN=`hostname`
# DNS=`head -1 /etc/resolv.conf | awk '{print $2}'` # v5.0.1 匹配不准确已被修复
DNS=`cat $RESOLV_FILE | grep nameserver | awk '{print $2}' | paste -sd,`
OS=`uname --kernel-name --kernel-release`
HI=`cat ~/.*sh_history | tail -10` # 查看用户的历史命令，适用通配符的方式
# H=`history 10` # 在脚本中，history不适用
CRON=`crontab -l 2>/dev/null`
M_FILE=`find -type f -mtime -3`
M_FILE_VAR=`find /var/ -type f -mtime -3 | xargs ls -la`
C_FILE=`find -type f -ctime -3`
USER=`cat /etc/passwd | tail -10`
SHADOW=`cat /etc/shadow | tail -10`
ROOT=`awk -F: '$3==0{print $1}' /etc/passwd`
TELNET=`awk '/$1|$6/{print $1}' /etc/shadow`
SUDO=`more /etc/sudoers | grep -v "^#|^$" | grep "ALL=(ALL)"`
# VM=`lscpu | grep "Hypervisor" | awk '{print $3}'` # 5.1.19修复各服务器存在的差异
# VM=`lscpu | grep "Hypervisor\|Virtualization\|超管理器厂商" | awk '{print $2}'`   # 修复bug
VM=`lscpu | grep "Hyper.*:\|Virtu\|超管理器厂商" | grep -oP "(?<=:)\s*\K.*" | paste -sd,`


# [ ++ 5.0 Functions options ++ ]
# 端口开放
# netstat -plant | awk '{print $4}' | grep -oE '[0-9]+' | sort -un | paste -sd ',' # 列表显示
PORT=`netstat -tunlp | awk '/^tcp/ {print $4,$7}; /^udp/ {print $4,$6}' | sed -r 's/.*:(.*)\/.*/\1/' | sort -un | awk '{cmd = "sudo lsof -w -i :" $1 " | awk '\''NR==2{print $1}'\''"; cmd | getline serviceName; close(cmd); print $1 "\t" serviceName}'`

# 系统状态
# 查看内存、磁盘、CPU状态
TA=$(free -m | awk 'NR==2{printf "%.2f%%\t\t",$3*100/$2}' ;echo;)
TB=$(df -h| awk '$NF=="/"{printf "%s\t\t",$5}')
TC=$(top - bn1 | grep load | awk '{printf "%.2f%%\t\t\n",2$(NF2)}')

# 查找僵尸进程
TKILL=`ps -al | gawk '{print $2,$4}' | grep -e '^[Zz]'`
# 查看在线用户数
TUN=`uptime | sed 's/user.*$//' | gawk '{print $NF}'`


# [ ++ 6.0 Functions options ++ ]

# 更新用户登录相关，智能匹配系统内核给出相应的正则命令
# 更新一键导出，应急更方便，取出日志到本地分析，自己的电脑工具多，效率高，环境更友好。



# EnoCmd_ssh_v3
#EnoCmd_ssh_v3=$($SECURE | grep "Failed password for invalid user" | awk '{print $13 " --> " $11}' | sort | uniq -c | sort -rn | awk 'BEGIN {print "\n# 攻击次数Top20 攻击者IP --> 枚举用户名\n"}{print "[+] 用户名不存在 "$0}' | head -20 &&  $SECURE | grep "Failed password for invalid user" | awk '{print $11 " --> " $13}' | sort | uniq -c | sort -rn | awk '{print $4}' | sort | uniq -c | awk 'BEGIN {print "\n# 攻击者IP次数TOP10 \n"}{print "[+] "$2" 攻击次数 "$1"次"}';echo && $SECURE | grep Accepted  | awk 'BEGIN {print "# 登录成功IP地址\n"}{print "时间:"$1"-"$2"-"$3"\t登录成功\t "$11" --> "$9 " 使用方式: "$7}';echo && $SECURE | grep "Failed password for" | grep -v invalid | awk 'BEGAN{print "# 对用户名爆破次数\n"}{print $11"—->"$9}'| uniq -c | sort -rn | awk 'BEGIN {print "# 对用户名进行密码爆破次数\n"}{print "攻击次数: " $1   " 详情:   "$2}' | head -20;echo)

# [ ++ Function user ++ ]

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

# [ ++ Function LOGO ++ ]

function logo
{

    echo
    echo
    printf "${red} ██╗    ██╗██╗  ██╗ ██████╗  █████╗ ███╗   ███╗██╗    ███████╗██╗   ██╗ ██████╗██╗  ██╗ ${reset}\n"
    printf "${red} ██║    ██║██║  ██║██╔═══██╗██╔══██╗████╗ ████║██║    ██╔════╝██║   ██║██╔════╝██║ ██╔╝ ${reset}\n"
    printf "${red} ██║ █╗ ██║███████║██║   ██║███████║██╔████╔██║██║    █████╗  ██║   ██║██║     █████╔╝  ${reset}\n"
    printf "${red} ██║███╗██║██╔══██║██║   ██║██╔══██║██║╚██╔╝██║██║    ██╔══╝  ██║   ██║██║     ██╔═██╗  ${reset}\n"
    printf "${red} ╚███╔███╔╝██║  ██║╚██████╔╝██║  ██║██║ ╚═╝ ██║██║    ██║     ╚██████╔╝╚██████╗██║  ██╗ ${reset}\n"
    printf "${red}  ╚══╝╚══╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝    ╚═╝      ╚═════╝  ╚═════╝╚═╝  ╚═╝ ${reset}\n"
    printf "                        \t\t\t                                             by ${blue}Enomothem${reset}\n"

}


# [ ++ 标题栏定义区 ++ ]

bar_user_logi=`printf "${red}                    [\t用户登录信息\t]                                    ${reset}\n"`
bar_base_info=`printf "${red}                    [\t用户基本信息\t]                                    ${reset}\n"`
bar_logs_hist=`printf "${red}                    [\t用户历史命令\t]                                    ${reset}\n"`
bar_user_info=`printf "${red}                    [\t用户信息排查\t]                                    ${reset}\n"`
bar_cron_task=`printf "${red}                    [\t用户计划任务\t]                                    ${reset}\n"`
bar_osys_stat=`printf "${red}                    [\t系统状态信息\t]                                    ${reset}\n"`
bar_port_open=`printf "${red}                    [\t显示开启端口\t]                                    ${reset}\n"`
bar_port_proc=`printf "${red}                    [\t进程状态信息\t]                                    ${reset}\n"`
bar_port_serv=`printf "${red}                    [\t服务状态信息\t]                                    ${reset}\n"`
bar_file_move=`printf "${red}                    [\t文件信息排查\t]                                    ${reset}\n"`


# [ ++ Function HELP_CN ++ ]

function help_cn
{
        
        printf "usage:  \n\n"
        printf "\t -v --version\t\t\t版本信息\n "
        printf "\t -h --help\t\t\t帮助指南\n"
        printf "\t -l --login [FILEPATH]\t\t\t用户登录信息\n"
        printf "\t -n --nomal\t\t\t基本输出模式\n"
        printf "\t -a --all\t\t\t全量输出模式\n"
        printf "\t -u --user-device\t\t查看设备基本信息\n"
        printf "\t -x --process-and-servic\t检查用户进程与开启服务状态\n"
        printf "\t -p --port\t\t\t查看端口开放状态\n"
        printf "\t -s --os-status\t\t\t查看系统状态信息\n"
        printf "\t -o --output\t\t\t导出全量输出模式文件\n"
}

function help_en
{
        logo
        printf "usage:  \n\n"
        printf "\t -v --version\t\t\tshow version.\n "
        printf "\t -h --help\t\t\tshow help guide.\n"
        printf "\t -l --login \t\t\tuser login log.\n"
        printf "\t -n --nomal\t\t\tnomal show.\n"
        printf "\t -a --all\t\t\tall show.\n"
        printf "\t -x --process-and-service\tcheck service and process information.\n"
        printf "\t -u --user-device\t\tcheck device information.\n"
        printf "\t -p --port\t\t\tshow port information.\n"
        printf "\t -s --os-status\t\t\tshow os status information\n"
        printf "\t -o --output\t\t\toutput to file.\n"
}

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# [ ++ Function zone ++ ]
        # Run the appropriate script based on the distribution name

# [ ++ Function OS_NAME ++ ]

function os_name
{
    if [ -e /etc/os-release ]; then
        # Get the name of the current Linux distribution
        # 如果不存在这个文件呢？待改进 TODO
        os_name=$(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
        if [[ "$os_name" == *"Debian"* ]]; then
            OSNAME="Debian"
        elif [[ "$os_name" == *"CentOS"* ]]; then
            OSNAME="CentOS"
        elif [[ "$os_name" == *"Ubuntu"* ]]; then
            OSNAME="Ubuntu"
        elif [[ "$os_name" == *"Kali"* ]]; then
            OSNAME="Kali"
        else
            OSNAME="Unknown distribution"
        fi
    fi
}

# [  ++ Function User_Login pro ++ ]

function fk_userlogin
{
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
                os_name
                IP_C=`echo -e "${cyan}$IP${reset}"`
                HN_C=`echo -e "${yellow}$HN${reset}「 ${white}$WHOAMIFUCK${reset} 」"`
                OSNAME_C=`echo -e "${bg_purple}$OSNAME${reset}「 ${blue}$VM${reset} 」"`
                TUN_C=`echo -e "${white}$TUN${reset}"`
                M_TIME_C=`echo -e "${green}$M_TIME${reset}"`
                        
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
                echo $bar_osys_stat
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
                
                echo $bar_proc_port
                printf "%s" "`ps aux`"
                echo
                echo $bar_port_serv
                echo
                printf "%s" "`service --status-all`"
                echo
}

# [ ++ Function OPENPORT_INFORMATION ++ ]
## 开启端口列表

function fk_portstatus
{
                echo
                echo $bar_port_open
                echo
                printf "%s\n" "$PORT"
}

# [ ++ Function HISTORY_INFORMSTION ++ ]
# 历史命令

function fk_history
{
                echo
                echo $bar_logs_hist
                echo
                printf "%s" "$HI"
                echo
                echo
}

# [ ++ Function CRONTAB_INFORMSTION ++ ]
## 计划任务

function fk_crontab
{
                echo
                echo $bar_cron_task               
                echo
                printf "%s" "$CRON"
                echo
}

# [ ++ Function FILEMOVE_INFORMSTION ++ ]
## 文件修改信息

function fk_filemove
{
                echo
                echo $bar_file_move
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
## 用户基本信息

function fk_userinfo
{
                echo
                echo $bar_user_info
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
                fk_userlogin
                echo
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
                if [ -z "$1" ]; then
                    ./"$0" -n> output.txt
                else
                    ./"$0" -n> "$2"
                fi
                ;;
        -v | --version)
                echo "$VER"
                ;;
        *)
            help_en
            ;;
esac
