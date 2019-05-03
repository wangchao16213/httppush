yum -y install gcc-c++
yum -y install flex
yum -y install bison
yum -y install git
yum -y install ncurses-devel
yum -y install wget
yum -y install libstdc++.so.6
yum -y install libcurl
yum -y install tcpdump
yum -y install libcurl-devel
yum install openssl-devel

cd /home/httppushplus/software/app
tar -zxvf htop-1.0.2.tar.gz
tar -zxvf libpcap-1.8.1.tar.gz
tar -zxvf nload-0.7.4.tar.gz

cd /home/httppushplus/software/app/htop-1.0.2
./configure
make
make install

cd /home/httppushplus/software/app/libpcap-1.8.1
./configure
make
make install

cd /home/httppushplus/software/app/nload-0.7.4
./configure
make
make install

cp /home/httppushplus/software/centos_7.4/lib64/libstdc++.so.6.0.21 /usr/lib64/
cd /usr/lib64
rm -rf libstdc++.so.6
chmod 777 libstdc++.so.6.0.21
ln -s libstdc++.so.6.0.21 libstdc++.so.6

cp /usr/local/lib/libpcap.so.1.8.1 /usr/lib64
rm -rf libpcap.so.1
ln -s libpcap.so.1.8.1 libpcap.so.1

cd /home/httppushplus/software/
mkdir download
cd download
yum -y install python-setuptools

git clone https://github.com/Supervisor/meld3
cd meld3
python setup.py install
cd ..

wget --no-check-certificate https://pypi.python.org/packages/31/7e/788fc6566211e77c395ea272058eb71299c65cc5e55b6214d479c6c2ec9a/supervisor-3.3.3.tar.gz
tar -zxvf supervisor-3.3.3.tar.gz
cd supervisor-3.3.3
python setup.py install
cd ..

echo_supervisord_conf > /etc/supervisord.conf

mkdir /etc/supervisord.d
mkdir /var/log/httpPushPlus/
mkdir /home/log/
mkdir /home/log/RecordUrl/

cp /root/httppushplus/supervisord/etc/supervisord.d/supervisor_httpPushPlus.conf /etc/supervisord.d/
cp /root/httppushplus/supervisord/etc/supervisord.d/supervisor_RecordUrl.conf /etc/supervisord.d/
cp /root/httppushplus/supervisord/etc/init.d/supervisord /etc/init.d

sudo firewall-cmd --zone=public --add-port=9001/tcp --permanent
sudo firewall-cmd --reload
firewall-cmd --list-all

cp /root/httppushplus/supervisord/etc/supervisord.conf /etc/supervisord.conf