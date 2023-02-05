#!/bin/bash

# Install packages and dependencies
yum install -y gcc flex bison zlib libpcap pcre libdnet tcpdump
yum install -y http://mirror.centos.org/centos/7/extras/x86_64/Packages/epel-release-7-11.noarch.rpm
yum install -y libnghttp2
yum install -y http://www6.atomicorp.com/channels/atomic/centos/7/x86_64/RPMS/daq-2.0.6-1.el7.art.x86_64.rpm
wget https://www.snort.org/downloads/snort/snort-2.9.20-1.centos.x86_64.rpm
rpm -ivh snort-2.9.20-1.centos.x86_64.rpm

# load config libraries
ldconfig

#Setting up username and folder structure
groupadd snort
useradd snort -r -s /sbin/nologin -c SNORT_IDS -g snort

mkdir -p /etc/snort/rules 2>/dev/null
mkdir /var/log/snort 2>/dev/null
mkdir /usr/local/lib/snort_dynamicrules 2>/dev/null

chmod -R 5775 /etc/snort
chmod -R 5775 /var/log/snort
chmod -R 5775 /usr/local/lib/snort_dynamicrules
chown -R snort:snort /etc/snort
chown -R snort:snort /var/log/snort
chown -R snort:snort /usr/local/lib/snort_dynamicrules

touch /etc/snort/rules/white_list.rules
touch /etc/snort/rules/black_list.rules
touch /etc/snort/rules/local.rules


# edit snort.confg
cp /etc/snort/snort.conf /etc/snort/snort.conf.backup
sed -i 's/include $RULE_PATH/#include $RULE_PATH/' /etc/snort/snort.conf
sed -i 's/var WHITE_LIST_PATH ..\/rules/var WHITE_LIST_PATH \/etc\/snort\/rules/' /etc/snort/snort.conf
sed -i 's/var BLACK_LIST_PATH ..\/rules/var BLACK_LIST_PATH \/etc\/snort\/rules/' /etc/snort/snort.conf
sed -i 's/#include $RULE_PATH\/local.rules/include $RULE_PATH\/local.rules/' /etc/snort/snort.conf
sed -i 's/# output log_unified2: filename snort.log, limit 128, nostamp/output log_unified2: filename snort.log, limit 128/' /etc/snort/snort.conf

ln -s /usr/lib64/libdnet.so.1.0.1 /usr/lib64/libdnet.1

# Test snort configuration
snort -T -c /etc/snort/snort.conf


# Create the Snort local rules file
cat > /etc/snort/rules/local.rules << EOF
# Detect ICMP packets
alert icmp any any -> any any (msg:"ICMP Packet"; sid:1000001; rev:1;)

# SYN Flood scan
alert tcp \$HOME_NET any -> any any (flags: S; msg:"SYN Flood"; sid:1000002; rev:1; threshold: type both, track by_src, count 10, seconds 10;)

# Nmap XMAS Attack
alert tcp \$EXTERNAL_NET any -> \$HOME_NET any (msg:"NMAP Xmas Scan"; flags:FPU; threshold: type both, track by_src, count 1, seconds 60; sid:1000005; rev:1;)
EOF


# Launching snort
snort -A console -i ens33 -u snort -g snort -c /etc/snort/snort.conf
