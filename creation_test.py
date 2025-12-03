import os
import logging
from datetime import datetime

def generate_logs():
	log_dir = 'LOGS'
	# create directory if needed
	os.makedirs(log_dir, exist_ok=True)

	# create time variable for filenames
	times = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
	number = 0
	logname = times + '.txt'
	filepath = os.path.join(log_dir, logname)

	# if the filename already exists, add number suffix to the filename
	while os.path.exists(filepath):
		number += 1
		logname = times + '_' + str(number) + '.txt'
		filepath = os.path.join(log_dir, logname)

	# configure logging to write to the chosen file
	try:
		logging.basicConfig(
			filename=filepath,
			filemode='w',
			level=logging.INFO,
			format='%(asctime)s - %(levelname)s - %(message)s'
		)
		# ensure file is actually created (surface permission errors)
		open(filepath, 'a').close()
	except PermissionError:
		print('Error: Unable to create log file')
		return log_dir
	
	print('Logs generated.')
	return log_dir

if __name__ == '__main__':
	generate_logs()