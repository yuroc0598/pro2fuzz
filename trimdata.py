#!/usr/bin/env python
import sys
fn = sys.argv[1]
fnout = sys.argv[1]+'.cov'
fout = open(fnout,"w+")
ln = 0
first = 0

curh = 0
curm = 0

with open(fn) as f:
	for line in f:

		ln += 1
		if ln == 1: continue
		line = line.strip().split(',')
		t = line[0]
		if not first:
			first = int(t)
			t = 0
		else:
			t = int(t)-first

		if ln % 2:
			h=t/60/60
			m=(t/60)%60
			if curh or curm:
				if h==curh and m==curm: continue
				curh = h
				curm = m
				fout.write(str(t/60)+','+line[6])
				fout.write("\n")
		fout.write(str(t/60)+','+line[6])
		fout.write("\n")



		

	
