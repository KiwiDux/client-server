import os
import logging
from datetime import datetime

time = str(datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))

def generate_logs(time):
	log_dir = 'LOGS'
	if not os.path.exists(log_dir):
		os.makedirs(log_dir)
	
	number = 0
	logname = (time, '.txt')
	#time = str(datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
	while os.path.exists(log_dir,  '/',  logname):
		logname = time, str(number), '.txt'
		number += 1
	
	# New Log
	try:
		config = logging.basicConfig(filename = log_dir + '/' + logname , filemode='w')
	except PermissionError:
		print('Error: Unable to create log file')
		return log_dir
	
	print('Logs generated.')
	return log_dir

generate_logs()