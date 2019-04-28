strace -tt -yy -y -f -e trace=open,read,write,pipe,socket,dup2,clone,close,ipc,signal,desc -s 10000 -o ~/tmp/fuzz/strace-pro2 `cat ./run1.bash`
