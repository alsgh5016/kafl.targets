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
