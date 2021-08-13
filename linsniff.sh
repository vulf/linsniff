#!/bin/bash

# Init terminal colours
C=$(printf "\e")
RST="$C[0m"
W="$C[1;40m"
LB="$C[1;94m"
CY="$C[1;96m"
nbG="$C[92m"
GR="$C[1;92m"
dGR="$C[1;32m"
LR="$C[1;91m"
M="$C[95m"
Y="$C[1;33m"
bgR="$C[1;101;97m"

# PE Groups
declare -A pegroups
pegroups=(
	[sudo]="https://www.hackingarticles.in/linux-privilege-escalation-using-exploiting-sudo-rights/ https://book.hacktricks.xyz/linux-unix/privilege-escalation/interesting-groups-linux-pe#sudo-admin-groups"
	[shadow]="https://book.hacktricks.xyz/linux-unix/privilege-escalation/interesting-groups-linux-pe#shadow-group"
	[wheel]="https://book.hacktricks.xyz/linux-unix/privilege-escalation/interesting-groups-linux-pe#wheel-group"
	[disk]="https://book.hacktricks.xyz/linux-unix/privilege-escalation/interesting-groups-linux-pe#disk-group"
	[video]="https://book.hacktricks.xyz/linux-unix/privilege-escalation/interesting-groups-linux-pe#video-group"
	[root]="https://book.hacktricks.xyz/linux-unix/privilege-escalation/interesting-groups-linux-pe#root-group"
	[docker]="https://book.hacktricks.xyz/linux-unix/privilege-escalation/interesting-groups-linux-pe#docker-group"
	[lxc]="https://book.hacktricks.xyz/linux-unix/privilege-escalation/interesting-groups-linux-pe#lxc-lxd-group"
	[lxd]="https://book.hacktricks.xyz/linux-unix/privilege-escalation/interesting-groups-linux-pe#lxc-lxd-group"
	[adm]="https://book.hacktricks.xyz/linux-unix/privilege-escalation/interesting-groups-linux-pe#adm-group"
)

# Vulnerable kernels
vkerns="3.9.6 3.9.0 3.9 3.8.9 3.8.8 3.8.7 3.8.6 3.8.5 3.8.4 3.8.3 3.8.2 3.8.1 3.8.0 3.8 3.7.6 3.7.0 3.7 3.6.0 3.6 3.5.0 3.5 3.4.9 3.4.8 3.4.6 3.4.5 3.4.4 3.4.3 3.4.2 3.4.1 3.4.0 3.4 3.3 3.2 3.19.0 3.16.0 3.15 3.14 3.13.1 3.13.0 3.13 3.12.0 3.12 3.11.0 3.11 3.10.6 3.10.0 3.10 3.1.0 3.0.6 3.0.5 3.0.4 3.0.3 3.0.2 3.0.1 3.0.0 2.6.9 2.6.8 2.6.7 2.6.6 2.6.5 2.6.4 2.6.39 2.6.38 2.6.37 2.6.36 2.6.35 2.6.34 2.6.33 2.6.32 2.6.31 2.6.30 2.6.3 2.6.29 2.6.28 2.6.27 2.6.26 2.6.25 2.6.24.1 2.6.24 2.6.23 2.6.22 2.6.21 2.6.20 2.6.2 2.6.19 2.6.18 2.6.17 2.6.16 2.6.15 2.6.14 2.6.13 2.6.12 2.6.11 2.6.10 2.6.1 2.6.0 2.4.9 2.4.8 2.4.7 2.4.6 2.4.5 2.4.4 2.4.37 2.4.36 2.4.35 2.4.34 2.4.33 2.4.32 2.4.31 2.4.30 2.4.29 2.4.28 2.4.27 2.4.26 2.4.25 2.4.24 2.4.23 2.4.22 2.4.21 2.4.20 2.4.19 2.4.18 2.4.17 2.4.16 2.4.15 2.4.14 2.4.13 2.4.12 2.4.11 2.4.10 2.2.24"

# Pattern highlights
groups1="\(root\)|\(shadow\)|\(admin\)|\(video\)|\(adm\)"
groups2="\(sudo\)|\(docker\)|\(lxd\)|\(wheel\)|\(disk\)|\(lxc\)"

not_found(){
	echo -e "$1 not found"
}

title(){
	local c=`echo -n "[+] $1" | wc -m` 
	printf "\n${Y}[+]${RST} ${nbG}${1}${RST}\n"; for i in $(seq `expr $c + 1`);do printf "-"; done
	echo
}

peVectors(){
	if [[ $pevflag -eq 0 && $1 != "stop" ]]; then
		printf "\n${GR}[+] ${RST}${LR}Possible techniques for PE${RST}\n-------------------------------\n"
		pevflag=1
		sugflag=1
	fi
	if [[ $1 == "stop" ]]; then
		pevflag=0
		sugflag=0
		printf "\n"
	elif [[ ! -z $1 ]]; then
		if [[ $1 == "group" ]]; then
			if [[ ! -z $2 ]]; then
				for line in ${pegroups[$2]}; do
					printf "${Y}[i]${RST} $line\n"
				done
			fi
		elif [[ $1 == "kernel" ]]; then
			printf "{Y}[i]${RST} https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits\n"
			printf "{Y}[i]${RST} https://github.com/lucyoa/kernel-exploits\n"
		elif [[ $1 == "sudo" ]]; then
			printf "${Y}[i]${RST}${LR} Sudo is vulnerable ${RST}${Y}(https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-version)"${RST}
		elif [[ $1 == "acl" ]]; then
			printf "${Y}[i]${RST} https://book.hacktricks.xyz/linux-unix/privilege-escalation#acls\n"

		fi	
	fi
}

sug(){
	#if [[ $sugflag -eq 1 ]]; then
		if [[ $1 == "groups" ]]; then
			printf ""
		elif [[ $1 == "kernel" ]]; then
			printf "\n${M}Manual Checks${RST}\n--------------\n"
			printf "${LB}[i]${RST} https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits\n"
		fi

	#fi
}

banner(){
	echo "
  ██       ██           ████████          ██   ████   ████
 ░██      ░░           ██░░░░░░          ░░   ░██░   ░██░ 
 ░██       ██ ███████ ░██        ███████  ██ ██████ ██████
 ░██      ░██░░██░░░██░█████████░░██░░░██░██░░░██░ ░░░██░ 
 ░██      ░██ ░██  ░██░░░░░░░░██ ░██  ░██░██  ░██    ░██  
 ░██      ░██ ░██  ░██       ░██ ░██  ░██░██  ░██    ░██  
 ░████████░██ ███  ░██ ████████  ███  ░██░██  ░██    ░██  
 ░░░░░░░░ ░░ ░░░   ░░ ░░░░░░░░  ░░░   ░░ ░░   ░░     ░░   

"
}

userInfo(){
	printf $CY"\n====================================| ${GR}Basic User Information${RST}${CY} |====================================\n"$RST
	myuid=`id -u`
	if [ $myuid -eq 0 ]; then
		root=1
		printf ${GR}"User has root privileges.\n"${RST}
	elif [ $myuid -gt 0 ]; then
		root=0
		mygroups=`groups`
		groupids=`id | sed -E "s/$groups1/${C}[1;31m&${C}[0m/g" | sed -E "s/$groups2/$bgR&${RST}/g"`
		echo "${W}User: ${RST}"`whoami`
		echo "${W}Groups: ${RST}"$groupids
		for g in $mygroups;
		do
			if [[ ${!pegroups[@]} == *$g* ]]; then
	       			peVectors group $g
			fi
		done
		peVectors stop
		printf "${W}PATH: ${RST}${PATH}\n"
	else
		echo "Could not fetch EUID, exiting.."
		exit
	fi
}

sysInfo(){
	printf $CY"\n====================================| ${GR}System Information${RST}${CY} |====================================\n"$RST
	echo "${W}OS: ${RST}"`uname -a`
	lsb_release -a 2>/dev/null | sed -E "s/^.*:/${W}&${RST}/g"
	kver=`uname -r | cut -d '-' -f1`
	printf ${W}"Kernel: \t"${RST}${kver}"\n"
	printf "${W}Hostname: \t${RST}"`hostname 2>/dev/null`"\n"	
	if [[ $vkerns == *"$kver"* ]]; then
		peVectors kernel
	else
		sug kernel
	fi
	peVectors stop
	# check sudo
	sudover=`sudo -V | grep 'Sudo version' | cut -d ' ' -f 3`
	sudoV=`sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"`
	title "Sudo version"
	if [[ ! -z $sudoV ]]; then
		printf "${bgR}${sudover}${RST}\n"
		peVectors sudo
	else
		printf "$sudover\n"
	fi
	peVectors stop
	title "System Statistics"
	df -h || lsblk
	title "CPU Architecture Information"
	lscpu
	title "Environment Variables"
	env
}

secFramewrks(){
	title "Security Frameworks"
	if [ `command -v aa-status 2>/dev/null` ]; then
		aa-status 2>&1 | sed "s,disabled,${C}[1;31m&${C}[0m,"
		elif [ `command -v apparmor_status 2>/dev/null` ]; then
			apparmor_status 2>&1 | sed "s,disabled,${C}[1;31m&${C}[0m,"
		elif [ `ls -d /etc/apparmor* 2>/dev/null` ]; then
			ls -d /etc/apparmor*
		else
			not_found "AppArmor"
	fi

	printf $Y"[+] "$GREEN"grsecurity present? ............ "$NC
	((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || not_found "grsecurity")

	printf $Y"[+] "$GREEN"PaX bins present? .............. "$NC
	(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || not_found "PaX")

	#-- SY) Execshield
	printf $Y"[+] "$GREEN"Execshield enabled? ............ "$NC
	(grep "exec-shield" /etc/sysctl.conf 2>/dev/null || not_found "Execshield") | sed "s,=0,${C}[1;31m&${C}[0m,"

	#-- SY) SElinux
	printf $Y"[+] "$GREEN"SELinux enabled? ............... "$NC
	(sestatus 2>/dev/null || not_found "sestatus") | sed "s,disabled,${C}[1;31m&${C}[0m,"

	#-- SY) ASLR
	printf $Y"[+] "$GREEN"Is ASLR enabled? ............... "$NC
	ASLR=`cat /proc/sys/kernel/randomize_va_space 2>/dev/null`
	if [ -z "$ASLR" ]; then 
		not_found "/proc/sys/kernel/randomize_va_space"; 
		else
		if [ "$ASLR" -eq "0" ]; then printf $RED"No"$NC; else printf $GREEN"Yes"$NC; fi
			echo ""
	fi

}

fileChecks(){
	printf $CY"\n====================================| ${GR}File Permission Checks${RST}${CY} |====================================\n"$RST
	title "World Writable Directories"
	find / -perm -222 -type d 2>/dev/null
	find / \( -perm -o w -perm -o x \) -type d 2>/dev/null
	title "SUID Files"
	find / -perm -4000 -type f 2>/dev/null | xargs ls -lahtr
	title "SGID Files"
	find / -perm -2000 -type f 2>/dev/null | xargs ls -lahtr
	title "Files with ACLs"
	badacls=`getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null`
	if [[ -z $badacls ]]; then
		printf "No files with ACLs found.\n"
	else
		getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null	
		peVectors acl
	fi
	peVectors stop
	title "Files with Capabilities"
	getcap -r / 2>/dev/null

}

serviceScan(){
	printf $CY"\n====================================| ${GR}Service and Process Scan${RST}${CY} |====================================\n"$RST
	title "Sandbox Settings"
	if [[ `command -v systemd-analyze` ]]; then
		systemd-analyze security | grep '^.*\.service.*$' | awk '{ if($3=="UNSAFE"){printf("%-40s [\033[1;101;97m%s\033[0m]\n", $1, $3)} else if($3=="MEDIUM"){printf("%-40s [\033[33m%s\033[0m]\n", $1, $3)} else if($3=="EXPOSED"){printf("%-40s [\033[91m%s\033[0m]\n", $1, $3)} else if($3=="OK"){printf("%-40s [\033[32m%s\033[0m]\n", $1, $3)} }'
	fi
	title "Running processes"
	if [[ `command -v ps` ]]; then
		ps aux
	else
		not_found ps
	fi

	title "Cron jobs"
	command -v crontab 2>/dev/null || not_found "crontab"
	crontab -l 2>/dev/null | tr -d "\r" | sed -E "s,$Wfolders,${C}[1;31;103m&${C}[0m,g" | sed -E "s,$sh_usrs,${C}[1;96m&${C}[0m," | sed "s,$USER,${C}[1;95m&${C}[0m," | sed -E "s,$nosh_usrs,${C}[1;34m&${C}[0m," | sed "s,root,${C}[1;31m&${C}[0m,"
	command -v incrontab 2>/dev/null || not_found "incrontab"
	incrontab -l 2>/dev/null
	ls -al /etc/cron* 2>/dev/null 
	cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs /var/spool/cron/crontabs/* /var/spool/anacron /etc/incron.d/* /var/spool/incron/* 2>/dev/null | tr -d "\r" | grep -v "^#\|test \-x /usr/sbin/anacron\|run\-parts \-\-report /etc/cron.hourly\| root run-parts /etc/cron." | sed "s,$USER,${C}[1;95m&${C}[0m," | sed "s,root,${C}[1;31m&${C}[0m,"
	crontab -l -u "$USER" 2>/dev/null | tr -d "\r"
	ls -l /usr/lib/cron/tabs/ /Library/LaunchAgents/ /Library/LaunchDaemons/ ~/Library/LaunchAgents/ 2>/dev/null #MacOS paths
	echo ""
}

netScan(){
	printf $CY"\n====================================| ${GR}Network Scan${RST}${CY} |====================================\n"$RST
	title Hosts
	if [[ -f /etc/hosts ]];then 
		cat /etc/hosts 
	else 
		echo 'No /etc/hosts' 
	fi
	title Interfaces
	cat /etc/networks 2>/dev/null
	(ifconfig || ip a) 2>/dev/null
	title "Active Ports"
	(netstat -tupln || netstat -lntu || ss -lntu) 2>/dev/null
	title "Iptables rules"
	(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Ev "\W+\#|^#" 2>/dev/null) 2>/dev/null || not_found "iptables rules"

}

main() {
	banner
	userInfo	
	sysInfo
	secFramewrks
	fileChecks
	serviceScan
	netScan
}

main
