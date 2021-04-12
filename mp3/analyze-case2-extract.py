#!/usr/bin/env python3

import os
import sys
import csv

time = []
util = []

if len(sys.argv) < 2:
	print(f'Usage: {sys.argv[0]} <profile.csv>')
	exit(0)

with open(sys.argv[1]) as profile:
	csvreader = csv.reader(profile)
	for row in csvreader:
		time.append(int(row[0]))
		util.append(int(row[3]))

max_util = 0
max_index = 0
for i, u in enumerate(util):
	if u > max_util:
		max_util = u
		max_index = i

print(os.path.splitext(sys.argv[1])[0] + ',' + str(time[max_index] - time[0]) + ',' + str(max_util))
