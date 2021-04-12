#!/usr/bin/env python3

import sys
import csv
import matplotlib.pyplot as plt

n_processes = []
time = []
util = []

if len(sys.argv) < 3:
	print(f'Usage: {sys.argv[0]} <profile.csv> <plot>')
	exit(0)

with open(sys.argv[1]) as csvfile:
	csvreader = csv.reader(csvfile)
	for row in csvreader:
		n_processes.append(int(row[0]))
		time.append(int(row[1]))
		util.append(int(row[2]))

utilization = [u / t for u, t in zip(util, time)]

plt.plot(n_processes, utilization)
plt.xlabel('N (number of concurrent processes)')
plt.ylabel('Utilization')
plt.savefig(sys.argv[2])
