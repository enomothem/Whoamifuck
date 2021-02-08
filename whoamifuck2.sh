#! /bin/bash
# 入侵检测报告工具-Whoamifuck2.0【汉化】
# Author:Enomothem
# Time:2021年2月8日
echo
echo
printf "\e[1;31m ██╗    ██╗██╗  ██╗ ██████╗  █████╗ ███╗   ███╗██╗    ███████╗██╗   ██╗ ██████╗██╗  ██╗ \e[0m\n"
printf "\e[1;31m ██║    ██║██║  ██║██╔═══██╗██╔══██╗████╗ ████║██║    ██╔════╝██║   ██║██╔════╝██║ ██╔╝ \e[0m\n"
printf "\e[1;31m ██║ █╗ ██║███████║██║   ██║███████║██╔████╔██║██║    █████╗  ██║   ██║██║     █████╔╝  \e[0m\n"
printf "\e[1;31m ██║███╗██║██╔══██║██║   ██║██╔══██║██║╚██╔╝██║██║    ██╔══╝  ██║   ██║██║     ██╔═██╗  \e[0m\n"
printf "\e[1;31m ╚███╔███╔╝██║  ██║╚██████╔╝██║  ██║██║ ╚═╝ ██║██║    ██║     ╚██████╔╝╚██████╗██║  ██╗ \e[0m\n"
printf "\e[1;31m  ╚══╝╚══╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝    ╚═╝      ╚═════╝  ╚═════╝╚═╝  ╚═╝ \e[0m\n"
printf "			\t\t\t	2021.2.8@whoamifuck-version 2.0     by Enomothem \n"
printf "usage: 	\n"
printf "	\t./whoamifuck [filepath]  \n"
printf "\e[1;36m\t微信公众号：Eonian Sharp \e[0m\n"
echo
echo
AUTHLOG=/var/log/auth.log

if [[ -n $1 ]];
then
	AUTHLOG=$1
	echo 您使用的文件是: $AUTHLOG
fi

LOG=/tmp/valid.$$.log
grep -v "invalid" $AUTHLOG > $LOG
users=$(grep "Failed password" $LOG | awk '{ print $(NF-5) }' | sort | uniq)

printf "\e[4;34m%-5s|%-10s|%-14s|%-16s|%-33s|%s\n\e[0m" "Sr#" "登入用户名" "尝试次数" "IP地址" "虚拟主机映射" "时间范围"

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

	printf "%-5s|%-10s|%-10s|%-10s|%-27s|%-s\n" "$ucount" "$user" "$ATTEMPTS" "$IP" "$HOST" "$TIME_RANGE";
	fi
done
done

rm /tmp/valid.$$.log/tmp/$$.log $$.time/tmp/temp.$$.log 2>/dev/null
