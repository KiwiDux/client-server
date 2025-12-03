import socket
import time
import os
import logging
from datetime import datetime

def generate_logs():
	log_dir = 'LOGS'
	# create directory if needed
	os.makedirs(log_dir, exist_ok=True)

	# create timestamp variable for filenames
	timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
	number = 0
	# build filename as a string, not a tuple
	logname = timestamp + '.txt'
	filepath = os.path.join(log_dir, logname)

	# if the filename already exists, add number suffix to the filename
	while os.path.exists(filepath):
		number += 1
		logname = timestamp + '_' + str(number) + '.txt'
		filepath = os.path.join(log_dir, logname)

	# configure logging to write to the chosen file
	try:
		logging.basicConfig(
			filename=filepath,
			filemode='w',
			level=logging.INFO,
			format='%(asctime)s - %(levelname)s - %(message)s'
		)
		open(filepath, 'a').close()
	except PermissionError:
		print('Error: Unable to create log file')
		return None
	
	print('Logs generated: ', filepath)
	return filepath

def log_gather(log_dir):
	log_data_list = []
	old_log_list = []
	log_list = []
	
	tracking_file = 'processed_logs.txt'

	# Ensure LOGS directory exists
	if not os.path.exists(log_dir):
		print('Directory ', log_dir, ' not found.')
		return log_data_list

	# Get current list of files in LOGS
	current_logs = [file for file in os.listdir(log_dir) if os.path.isfile(os.path.join(log_dir, file))]

	# Check previously known logs
	if os.path.exists(tracking_file):
		with open(tracking_file, 'r') as file:
			old_log_list = file.read().splitlines()
	
	# Check for new logs
	log_list = [log for log in current_logs if log not in old_log_list]

	if not log_list:
		print('No new logs found.')
		return log_data_list

	print('Found ', str(len(log_list)), ' new logs: ', str(log_list))

	# Process new logs (read content) and update tracking
	with open(tracking_file, 'a') as file:
		for log_file in log_list:
			file_path = os.path.join(log_dir, log_file)
			try:
				# Read as BYTES for encryption
				with open(file_path, 'rb') as log:
					content = log.read()
					# Store filename and content
					log_data_list.append((log_file, content))
				
				# Mark as processed
				file.write(log_file + '\n')
			except Exception as error:
				print('Error reading ', log_file, ': ', str(error))
	
	return log_data_list



def process_log_cycle():
	# Generate Logs
	print('\nGenerating Logs')
	gather = generate_logs()

	# Gather Logs
	print('\nGathering Logs')
	log_data_list = log_gather('LOGS')

	if not log_data_list:
		print('No new logs found to send.')
		return
	
	elif log_data_list:
		print('\nSending Logs')
	
	else:
		print('\nConnection failed.')
	

def main():
	
	print('\n## Program started at', datetime.now(), ' ##')
	
	string_menu = '\n1.\tManual Log Send.\n2.\tAuto Log Send.\n\nSelect an option from above: '
	menu_select = input(string_menu)

	if menu_select == '1':
		process_log_cycle()

	elif menu_select == '2':
		print('Auto Log Send started. Press Any Key to stop.')
		try:
			while True:
				process_log_cycle()
				print('\nWaiting 2 seconds...')
				time.sleep(2)
		except KeyboardInterrupt:
			print('\nAuto send stopped by user.')
		except Exception as error:
			print('An error occurred: ', error)

	else:
		print('Invalid selection!')


if __name__ == '__main__':
	main()
