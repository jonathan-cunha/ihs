apt update
apt install ftp vsftpd -y
cat vsftpd_template.conf > /etc/vsftpd.conf
service vsftpd restart

echo "ADICIONAR SENHA 12345"
adduser test
