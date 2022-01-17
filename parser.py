import socket
import json
import time
import sys
import os

# PARSER: The host side of the kernel module
# Running this before inserting the kernel module, 
# you can log and parse whats happening in the VM in 
# read time.

# Order of operations might matter, like you need to start piping dmesg out before 
# inserting the kernel module


def get_stdin(dev):
	return sys.stdin.read(dev)

class PsiLog:
	def __init__(self, port, doSave):
		self.running = True
		self.inbound = port
		self.saving = doSave
		self.data = {}
		self.receive()


	def receive(self):
		print('{ :: Ψ Logging Started on 0.0.0:%d :: }' % self.inbound) 
		while self.running:
			try:	# Get Latest Line 
				line = sys.stdin.readline().replace('\n','')
				# if len(line):
				# 	print(line)
				# ln = client.recv().decode()
				if line.find('Ψ')>0:
					# Split Line into fields (seperated by spaces)
					fields = line.split(' ')
					
					# First field is a timestamp since boot 
					if len(fields[2]):
						ts = fields[2].replace("]",'')
						# Determine Which Type of Hook Message we received
						mode = fields[3].replace("[",'').replace("]",'').replace(":",'')
						# Depending on hook type we parse message differently
						if mode == 'Ψnx':
							content = fields[-1].split(' ')[-1].split(':')[0]
						else:
							content = ' '.join(fields[4:])
						# Build a dictionary for this entry (will make this easily JSONizable later)
						self.data[ts] = {'HOOK': mode, 'DATA': content}
						print(f'{ts}: {self.data[ts]}')
					
			except UnicodeDecodeError:
				pass
			except IndexError:
				print(fields)
				pass
			except KeyboardInterrupt:
				self.running = False
				pass

		sys.stdout.flush()
		print('{ :: Ψ Shutting down Logger :: }')
		timestamps = list(self.data.keys())

		if self.saving:
			# Save to disk what was captured
			print('{Ψ} Saving LogFiles')
			self.dump_to_file()
		dt = float(timestamps[-1]) - float(timestamps[0])
		print(f'[-] Ψ Finished saving {dt} seconds of kernel messages [{len(timestamps)} entries]')
		if len(timestamps) > 10000:
			print('[*] This may take a while...')

	def dump_to_file(self):
		log_name = 'example.log' # TODO: Create logfilename based on datestr
		# Make each entry JSON, and create a new master list
		open(log_name,'w').write(json.dumps(self.data))


def main():
	save = False
	if '-s' in sys.argv:
		# TODO: Make a logfilename based on datetime to avoid overwriting!
		save = True
	PsiLog(1337,  save)


if __name__ == '__main__':
 	main()
