SHELL := /bin/bash

CUR_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
ROOT_DIR := $(CUR_DIR)/../

$(ROOT_DIR)/venv/bin/ansible-playbook:
	python3 -m venv $(ROOT_DIR)/venv
	$(ROOT_DIR)/venv/bin/python -m pip install ansible==7.1.0 pywinrm

ansible: $(ROOT_DIR)/venv/bin/ansible-playbook

init:
	vagrant up --no-provision
	vagrant snapshot save --force 'ready_provision'

compile:
	mkdir -p bin/{userspace,driver}
	# x86_64-w64-mingw32-gcc src/userspace/selffuzz_test.c -I ../ -o bin/userspace/selffuzz_test.exe -Wall -mwindows
	x86_64-w64-mingw32-gcc src/userspace/unpack_harness.c -I ../ -o bin/userspace/unpack_harness.exe -Wall -O2 -DWIN32 -D_WIN32_WINNT=0x0602 -lpsapi -lntdll -mwindows
	x86_64-w64-mingw32-gcc src/driver/vuln_test.c -I ../ -o bin/driver/vuln_test.exe -Wall -lntdll -lpsapi
	# Force-JIT sweep: native CLR-hosting shim, 32-bit to match the target
	# process it is injected into (must be i686, NOT x86_64).
	i686-w64-mingw32-gcc -shared -O2 -I src/userspace -o bin/userspace/sweep_helper.dll \
		src/userspace/sweep_helper/sweep_shim.c -Wall
	# Force-JIT sweep: managed core (PrepareMethod over all methods).
	# Prefer mono's mcs on the build host; if absent, build sweep_core.dll
	# on the Windows guest with csc /platform:x86 /target:library.
	if command -v mcs >/dev/null 2>&1; then \
		mcs -sdk:4 -target:library -platform:x86 \
			-out:bin/userspace/sweep_core.dll \
			src/userspace/sweep_helper/sweep_helper.cs ; \
	else \
		echo "[!] mcs not found. Install mono on the build host:" ; \
		echo "      apt-get install -y mono-mcs    # or mono-devel" ; \
		echo "    then re-run 'make compile'. Alternatively build on the" ; \
		echo "    Windows guest with the .NET Framework compiler:" ; \
		echo "      csc /platform:x86 /target:library /out:sweep_core.dll sweep_helper.cs" ; \
	fi
	# Ship the managed source alongside the binaries so provision can rebuild
	# sweep_core.dll on the guest with the .NET Framework csc.
	cp src/userspace/sweep_helper/sweep_helper.cs bin/userspace/sweep_helper.cs

provision_userspace: compile ansible
	vagrant snapshot restore 'ready_provision'
	TARGET_HARNESS='userspace' vagrant provision
	vagrant halt

provision_unpack: compile ansible
	vagrant snapshot restore 'ready_provision' || true
	vagrant up --no-provision
	TARGET_HARNESS='unpack' vagrant provision
	# vagrant halt

provision_driver: compile ansible
	vagrant snapshot restore 'ready_provision'
	TARGET_HARNESS='driver' vagrant provision
	vagrant halt

# -- Batch analysis with independent worker VMs --
NUM_WORKERS ?= 4

setup-workers: compile ansible
	python3 batch_analyze.py setup -n $(NUM_WORKERS)

teardown-workers:
	python3 batch_analyze.py teardown

batch-status:
	python3 batch_analyze.py status

# -- Fix expired vagrant/vagrant credentials in the base box --
# The Windows guest expires passwords after 42 days by default.
# Run this whenever `vagrant up` fails with WinRM authentication errors.
BOX_IMG ?= $(HOME)/.vagrant.d/boxes/kafl_windows/0/libvirt/box_0.img

fix-box:
	sudo bash $(CUR_DIR)/fix_box_password.sh $(BOX_IMG)
