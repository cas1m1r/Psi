import os


def load_system_calls():
	linux = open(os.path.join(os.getcwd(), 'latest_kernel','system_calls.txt'), 'r').read()
	syscalls = []
	columns = [c.replace('%', '') for c in linux.split('\n')[1].split('\t')]
	data = linux.split('\n')[2:]
	formatting = dict(zip(list(range(len(columns))), columns))
	for ln in data:
		syscall = {}
		fields = ln.split('\t')
		if len(fields) > 1:
			for i in range(len(fields)):
				field = formatting[i]
				syscall[field] = fields[i]
		syscalls.append(syscall)
	return syscalls


def create_hook_function(syscall_number):
	syscalls = load_system_calls()
	syscall = syscalls[syscall_number]
	original = syscall['System call'].split('_')[-1]
	hooked = f"psi_{original}"
	code = f'\nstatic asm linkage int {hooked}(const struct pt_regs* pt_regs)' + "{"
	lower = {'rdi': 'di', 'rsi': 'si', 'rdx': 'dx', }
	vars = []
	for register in list(syscall.keys())[2:]:
		if register in lower.keys() and len(syscall[register]):
			word = lower[register]
			elmts = syscall[register].split(' ')
			data_type = ' '.join(elmts[0:len(elmts)-1])
			variable = elmts[-1]
			code += f'\n\t{data_type} {variable} = ({data_type})pt_regs->{word};'
			vars.append(variable)
	code += f'\n\t\\\\ADD PRINT STATEMENT HERE: printk(KERN_INFO "[ψ] {original}(CORRECT_THIS)",{",".join(vars)});'
	code += f'\n\treturn original_{original}(pt_regs);'
	code += "\n}\n"
	return code
