// Disable SUDO.
void *disableSUDO(struct thread *td) {
	// Backup Orig Values first.
	uint16_t targetid[3];
	lv2.copyin(&target_id, &targetid, sizeof(targetid) / sizeof(*targetid));
	kconsole.WriteLine("Target ID loaded.\n");

	// Copy out to userland to not get lost.
	uint8_t mmapself[11];
	lv2.copyin(&mmap_self, &mmapself, sizeof(mmapself) / sizeof(*mmapself));
	kconsole.WriteLine("Mmap Self loaded.\n");

	// Disable Write Protection.
	lv2.disable_wp();
	kconsole.WriteLine("CPU Write Protection Disabled.\n");

	// Restore mmap self conditions.
#if defined FW_405
	if (mmapself[0] != __mmap_self_patch_0) {
		*(uint8_t*)(lv2.kern_base + __mmap_self_0) = mmapself[0]; //0x0F
		*(uint8_t*)(lv2.kern_base + __mmap_self_1) = mmapself[1]; //0x84
		*(uint8_t*)(lv2.kern_base + __mmap_self_2) = mmapself[2]; //0x74
		*(uint8_t*)(lv2.kern_base + __mmap_self_3) = mmapself[3]; //0x0F
	}
#elif defined FW_455
	if (mmapself[0] != __mmap_self_patch_0) {
		*(uint8_t*)(lv2.kern_base + __mmap_self_0) = mmapself[0]; //0x0F
		*(uint8_t*)(lv2.kern_base + __mmap_self_1) = mmapself[1]; //0x84
		*(uint8_t*)(lv2.kern_base + __mmap_self_2) = mmapself[2]; //0x74
		*(uint8_t*)(lv2.kern_base + __mmap_self_3) = mmapself[3]; //0x0F
	}
#else
	if (mmapself[0] != __mmap_self_patch_0) {
		*(uint8_t*)(lv2.kern_base + __mmap_self_0) = mmapself[0];
		*(uint8_t*)(lv2.kern_base + __mmap_self_1) = mmapself[1];
		*(uint8_t*)(lv2.kern_base + __mmap_self_2) = mmapself[2];

		*(uint8_t*)(lv2.kern_base + __mmap_self_3) = mmapself[3];
		*(uint8_t*)(lv2.kern_base + __mmap_self_4) = mmapself[4];
		*(uint8_t*)(lv2.kern_base + __mmap_self_5) = mmapself[5];

		*(uint8_t*)(lv2.kern_base + __mmap_self_6) = mmapself[6];
		*(uint8_t*)(lv2.kern_base + __mmap_self_7) = mmapself[7];
		*(uint8_t*)(lv2.kern_base + __mmap_self_8) = mmapself[8];
		*(uint8_t*)(lv2.kern_base + __mmap_self_9) = mmapself[9];
		*(uint8_t*)(lv2.kern_base + __mmap_self_10) = mmapself[10];
	}
#endif
	if (mmapself[0] != __mmap_self_patch_0) kconsole.WriteLine("Mmap Self condition Restored.\n");
	else kconsole.WriteLine("No need to Restore Mmap Self condition.\n");


	// Restore Target ID.
#if defined FW_405
	if (targetid[0] != __devkit_id) {
		*(uint16_t *)(lv2.kern_base + __target_id_0) = targetid[0];
		*(uint16_t *)(lv2.kern_base + __target_id_1) = targetid[1];
		*(uint16_t *)(lv2.kern_base + __target_id_2) = targetid[2];
	}
#elif defined FW_455
	if (targetid[0] != __devkit_id) {
		*(uint16_t *)(lv2.kern_base + __target_id_0) = targetid[0];
		*(uint16_t *)(lv2.kern_base + __target_id_1) = targetid[1];
		*(uint16_t *)(lv2.kern_base + __target_id_2) = targetid[2];
	}
#else
	if (targetid[0] != __devkit_id) {
		*(uint16_t *)(lv2.kern_base + __target_id_0) = targetid[0];
		*(uint16_t *)(lv2.kern_base + __target_id_1) = targetid[1];
	}
#endif
	if (targetid[0] != __devkit_id) kconsole.WriteLine("Target Id Restored.\n");
	else kconsole.WriteLine("No need to Restore Target ID.\n");


	// Enable Write Protection.
	lv2.enable_wp();
	kconsole.WriteLine("Write Protection Enabled.\n");

	return 0;
}

// Disable ASLR for Big Game Process.
void *disableProcessASLR(struct thread *td) {
	// Get Kernel Base.
	void* kern_base = &((uint8_t*)__readmsr(0xC0000082))[-__Xfast_syscall];

	// Disable Write Protection.
	lv2.disable_wp();

	// Disable process ASLR.
	*(uint16_t*)(kbase + 0x194875) = 0x9090;

	// Enable Write Protection.
	lv2.enable_wp();

	return 0;
}

// Disable ASLR for Big Game Process.
void *enableBrowser(struct thread *td) {
	// Init liblv2.
	lv2_init();

#if defined FW_405
	lv2.sceRegMgrSetInt(0x3C040000, 0);
#elif defined FW_455
	lv2.sceRegMgrSetInt(0x3C040000, 0);
#else
	lv2.sceRegMgrSetInt(0x3C040000, 0, 0, 0, 0);
#endif
	return 0;
}