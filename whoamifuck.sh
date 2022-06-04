#!/bin/bash
# 入侵检测报告工具-Whoamifuck4.0
# Author:Enomothem
# Time:2021年2月8日
# update: 2021年6月3日 优化格式
# update: 2021年6月6日 加入用户基本信息，发布3.0版本
# update: 2022年6月3日 增加新功能
# update: 2022年6月6日 发布4.0版本

# [ ++ 标量变量声明区 ++ ]

AUTHLOG=/var/log/auth.log # 默认访问的用户日志路径
IP=`ifconfig eth0 | head -2 | tail -1 | awk '{print $2}'`
ZW=`ifconfig eth0 | head -2 | tail -1 | awk '{print $4}'`
GW=`route -n | tail -1 | awk '{print $1}'`
HN=`hostname`
DNS=`head -1 /etc/resolv.conf | awk '{print $2}'`
OS=`uname --kernel-name --kernel-release`
HI=`cat ~/.bash_history | tail -10`
H=`history 10`
CRON=`crontab -l`
M_FILE=`find -type f -mtime -3`
C_FILE=`find -type f -ctime -3`
USER=`cat /etc/passwd | tail -10`
SHADOW=`cat /etc/shadow | tail -10`
ROOT=`awk -F: '$3==0{print $1}' /etc/passwd`
TELNET=`awk '/$1|$6/{print $1}' /etc/shadow`
SUDO=`more /etc/sudoers | grep -v "^#|^$" | grep "ALL=(ALL)"`
#FW=`service --status-all`
#JC=`ps aux`



# [ ++ LOGO ++ ]

echo
echo
printf "\e[1;31m ██╗    ██╗██╗  ██╗ ██████╗  █████╗ ███╗   ███╗██╗    ███████╗██╗   ██╗ ██████╗██╗  ██╗ \e[0m\n"
printf "\e[1;31m ██║    ██║██║  ██║██╔═══██╗██╔══██╗████╗ ████║██║    ██╔════╝██║   ██║██╔════╝██║ ██╔╝ \e[0m\n"
printf "\e[1;31m ██║ █╗ ██║███████║██║   ██║███████║██╔████╔██║██║    █████╗  ██║   ██║██║     █████╔╝  \e[0m\n"
printf "\e[1;31m ██║███╗██║██╔══██║██║   ██║██╔══██║██║╚██╔╝██║██║    ██╔══╝  ██║   ██║██║     ██╔═██╗  \e[0m\n"
printf "\e[1;31m ╚███╔███╔╝██║  ██║╚██████╔╝██║  ██║██║ ╚═╝ ██║██║    ██║     ╚██████╔╝╚██████╗██║  ██╗ \e[0m\n"
printf "\e[1;31m  ╚══╝╚══╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝    ╚═╝      ╚═════╝  ╚═════╝╚═╝  ╚═╝ \e[0m\n"
printf "                        \t\t\t                                            by Enomothem \n"

op="${1}"
case ${op} in
        -v) VER="2022.6.6@whoamifuck-version 4.0"
                echo "$VER"
                ;;
	-h)
		printf "usage:  \n\n"
		printf "\t -v              版本信息\n "
		printf "\t -h              帮助指南\n"
		printf "\t -f [filepath]   选择需要查看用户信息的文件，默认文件: /var/log/auth.log\n"
		printf "\t -n              基本信息输出\n"
		printf "\t -u              查看设备基本信息\n"
		printf "\t -a              检查用户进程与开启服务状态\n"
		;;
        -f) FILE="${2}"
                echo "你使用的文件是$FILE"
                printf "\e[1;31m                    [\t用户登入信息\t]                                    \e[0m\n"
                echo



                T='11'

                LOG=/tmp/valid.$$.log
                grep -v "invalid" $AUTHLOG > $LOG
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

                rm /tmp/valid.$$.log/tmp/$$.log $$.time/tmp/temp.$$.log 2>/dev/null
                rm *.time
                ;;
        -u)     
                printf "\e[1;31m                    [\t用户基本信息\t]                                    \e[0m\n"
                echo


                printf "%-21s|\t%-25s\t" "本机IP地址是" "$IP"
                printf "%-17s|\t%s\n" "本机子网掩码是    " "$ZW"
                printf "%-21s|\t%s\n" "本机网关是" "$GW"
                printf "%-22s|\t%s\n" "本机主机名是" "$HN"
                printf "%-19s|\t%s\n" "本机DNS是" "$DNS"
                printf "%-20s|\t%s\n" "系统版本" "$OS"
                echo
		;;
	-a)
		printf "\e[1;31m                    [\t进程状态\t]                                    \e[0m\n"
		echo
		printf "%s" "`ps aux`"
		echo
		printf "\e[1;31m                    [\t服务状态\t]                                    \e[0m\n"
		echo
		printf "%s" "`service --status-all`"
		echo
		;;
        -n)
                printf "\e[1;31m                    [\t用户基本信息\t]                                    \e[0m\n"
                echo


                printf "%-21s|\t%-25s\t" "本机IP地址是" "$IP"
                printf "%-17s|\t%s\n" "本机子网掩码是    " "$ZW"
                printf "%-21s|\t%s\n" "本机网关是" "$GW"
                printf "%-22s|\t%s\n" "本机主机名是" "$HN"
                printf "%-19s|\t%s\n" "本机DNS是" "$DNS"
                printf "%-20s|\t%s\n" "系统版本" "$OS"
                echo
                printf "\e[1;31m                    [\t用户历史命令\t]                                    \e[0m\n"
                echo
                printf "%s%s" "$HI,$H"
                echo
                echo
                printf "\e[1;31m                    [\t用户计划任务\t]                                    \e[0m\n"
                echo
                printf "%s" "$CRON"
                echo
                echo
                printf "\e[1;31m                    [\t文件信息排查\t]                                    \e[0m\n"
                echo
                echo "[+] 最近三天更改的文件"
                printf "%s\n\n" "$M_FILE"
                echo "[+] 最近三天创建的文件"
                printf "%s\n\n" "$C_FILE"
                echo
                printf "\e[1;31m                    [\t用户信息排查\t]                                    \e[0m\n"
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

                printf "\e[1;31m                    [\t用户登入信息\t]                                    \e[0m\n"
                echo



                T='11'

                LOG=/tmp/valid.$$.log
                grep -v "invalid" $AUTHLOG > $LOG
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

                rm /tmp/valid.$$.log/tmp/$$.log $$.time/tmp/temp.$$.log 2>/dev/null
                rm *.time
                ;;
        *)
                printf "usage:  \n\n"
                printf "\t -v              show version.\n "
		printf "\t -h              show help guide.\n"
                printf "\t -f [filepath]   select file path, Default file: /var/log/auth.log\n"
                printf "\t -n              nomal show.\n"
		printf "\t -a              check service and process information.\n"
		printf "\t -u              check device information.\n"
                ;;
esac