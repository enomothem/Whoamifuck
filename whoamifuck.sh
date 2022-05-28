#! /bin/bash
# 入侵检测报告工具-Whoamifuck3.0
# Author:Enomothem
# Time:2021年2月8日
# update: 2021年6月3日 优化格式
# update: 2021年6月6日 加入用户基本信息
echo
echo
printf "\e[1;31m ██╗    ██╗██╗  ██╗ ██████╗  █████╗ ███╗   ███╗██╗    ███████╗██╗   ██╗ ██████╗██╗  ██╗ \e[0m\n"
printf "\e[1;31m ██║    ██║██║  ██║██╔═══██╗██╔══██╗████╗ ████║██║    ██╔════╝██║   ██║██╔════╝██║ ██╔╝ \e[0m\n"
printf "\e[1;31m ██║ █╗ ██║███████║██║   ██║███████║██╔████╔██║██║    █████╗  ██║   ██║██║     █████╔╝  \e[0m\n"
printf "\e[1;31m ██║███╗██║██╔══██║██║   ██║██╔══██║██║╚██╔╝██║██║    ██╔══╝  ██║   ██║██║     ██╔═██╗  \e[0m\n"
printf "\e[1;31m ╚███╔███╔╝██║  ██║╚██████╔╝██║  ██║██║ ╚═╝ ██║██║    ██║     ╚██████╔╝╚██████╗██║  ██╗ \e[0m\n"
printf "\e[1;31m  ╚══╝╚══╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝    ╚═╝      ╚═════╝  ╚═════╝╚═╝  ╚═╝ \e[0m\n"
printf "                        \t\t\t  2021.6.6@whoamifuck-version 3.0     by Enomothem \n"
printf "usage:  \n"
printf "        \t./whoamifuck [filepath]  \n"
echo
echo
printf "\e[1;31m                    [\t用户基本信息\t]                                    \e[0m\n"
echo
IP=`ifconfig eth0 | head -2 | tail -1 | awk '{print $2}'`
ZW=` ifconfig eth0 | head -2 | tail -1 | awk '{print $4}'`
GW=`route -n | tail -1 | awk '{print $1}'`
HN=`hostname`
DNS=`head -1 /etc/resolv.conf | awk '{print $2}'`
printf "%-21s|\t%-20s\t" "本机IP地址是" "$IP"
printf "%-21s    |\t%s\n" "本机子网掩码是" "$ZW"
printf "%-21s|\t%s\n" "本机网关是" "$GW"
printf "%-21s |\t%s\n" "本机主机名是" "$HN"
printf "%-19s|\t%s\n" "本机DNS是" "$DNS"
echo
printf "\e[1;31m                    [\t用户登入信息\t]                                    \e[0m\n"
echo
AUTHLOG=/var/log/auth.log

if [[ -n $1 ]];
then
        AUTHLOG=$1
        echo 您使用的文件是: $AUTHLOG
fi

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
