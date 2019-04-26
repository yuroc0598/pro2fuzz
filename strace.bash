strace -tt -yy -y -f -e trace=open,read,write,pipe,socket,dup2,clone,close -s 10000 -o ~/tmp/fuzz/strace `cat ./run1.bash`
