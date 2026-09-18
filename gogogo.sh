cd
if [ -e "/data/data/com.termux/files/home/storage" ]; then
	rm -rf /data/data/com.termux/files/home/storage
fi
termux-setup-storage
yes | pkg update
yes | pkg upgrade
yes | pkg i python
yes | pkg i termux-api
yes | pkg i clang
yes | pkg i python-pip
pip install requests pytz colorama datetime logsnag pycryptodome
export CFLAGS="-Wno-error=implicit-function-declaration"
pkg install python-psutil -y
pkg install python-cryptography -y
curl -Ls "https://raw.githubusercontent.com/TenKoCo/avcs/refs/heads/main/concac.py" -o /sdcard/Download/concac.py
