#!/usr/bin/env python3

import sys
import csv
import matplotlib.pyplot as plt

time = []
min_flt = []
maj_flt = []
util = []

if len(sys.argv) < 3:
	print(f'Usage: {sys.argv[0]} <profile.csv> <plot>')
	exit(0)

with open(sys.argv[1]) as csvfile:
	csvreader = csv.reader(csvfile)
	for row in csvreader:
		time.append(int(row[0]))
		min_flt.append(int(row[1]))
		maj_flt.append(int(row[2]))
		util.append(int(row[3]))

base_time = time[0]
for i in range(len(time)):
	time[i] -= base_time

faults = [a + b for a, b in zip(min_flt, maj_flt)]

plt.plot(time, faults)
plt.xlabel('Time (jiffies)')
plt.ylabel('Page Fault Count')
plt.savefig(sys.argv[2])
