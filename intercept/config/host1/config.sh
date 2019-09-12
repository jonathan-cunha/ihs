apt update
apt install ftp -y

echo $(printf "machine 10.0.0.10\nlogin test\npassword 12346\n") > /root/.netrc

