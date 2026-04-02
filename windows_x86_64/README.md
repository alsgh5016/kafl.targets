# Windows x86_64 Target (PE Unpacking)

kAFL 기반 Windows PE 바이너리 자동 언패킹 분석 환경.
WtE(Write-then-Execute) 탐지를 통해 패킹된 바이너리의 메모리 덤프를 수집한다.

## Prerequisites

- **Host OS**: Ubuntu 20.04+ (Intel PT 지원 CPU 필요)
- **Vagrant**: 2.3+ with `vagrant-libvirt` plugin
- **libvirt/QEMU**: `qemu-system-x86_64`, `libvirtd`
- **Cross compiler**: `x86_64-w64-mingw32-gcc` (mingw-w64)
- **Python**: 3.9+ with venv
- **Vagrant box**: `kafl_windows` (Packer로 사전 빌드 필요 — `templates/windows/` 참조)

```bash
# 필수 패키지 (Ubuntu)
sudo apt install mingw-w64 vagrant libvirt-daemon-system qemu-system-x86
vagrant plugin install vagrant-libvirt
```

## Quick Start

### 1. 초기 VM 설정

```bash
# Ansible 환경 설치 (최초 1회)
make ansible

# Windows VM 생성 + 스냅샷 저장
make init

# 하네스 컴파일 + VM 프로비저닝 (unpack 모드)
make provision_unpack
```

### 2. 단일 샘플 분석 (kAFL 직접 실행)

```bash
# 패킹된 바이너리를 bin/userspace/에 배치
cp /path/to/packed.exe bin/userspace/target_packed.exe

# 프로비저닝 (VM에 바이너리 업로드)
make provision_unpack

# kAFL 실행
kafl fuzz \
  --purge \
  -w /tmp/kafl_workdir \
  --redqueen --redqueen-hammer \
  -p 1
```

### 3. 배치 분석 (다중 워커)

```bash
# 워커 VM 생성 (4개)
make setup-workers NUM_WORKERS=4

# 워커 상태 확인
python3 batch_analyze.py status

# 배치 분석 실행
python3 batch_analyze.py run /path/to/samples -o ./results -t 600

# 자동 배치 (실패 복구 포함)
python3 auto_batch.py ./targets -o ./results -n 4 -t 600

# 워커 제거
make teardown-workers
```

## Makefile Targets

| Target | Description |
|--------|-------------|
| `make compile` | 하네스 크로스 컴파일 (`bin/userspace/unpack_harness.exe`) |
| `make init` | Vagrant VM 생성 + `ready_provision` 스냅샷 저장 |
| `make provision_unpack` | 언팩 하네스 프로비저닝 (compile + snapshot restore + provision) |
| `make provision_userspace` | 유저스페이스 하네스 프로비저닝 |
| `make provision_driver` | 드라이버 하네스 프로비저닝 |
| `make setup-workers` | 배치 분석용 워커 VM 생성 |
| `make teardown-workers` | 워커 VM 제거 |
| `make batch-status` | 워커 상태 확인 |

## batch_analyze.py Commands

```bash
# 워커 VM 설정
python3 batch_analyze.py setup -n <N>

# 배치 실행
python3 batch_analyze.py run <samples_dir> -o <output_dir> -t <timeout_sec>

# 워커 상태 확인
python3 batch_analyze.py status

# 워커 정리
python3 batch_analyze.py teardown
```

## auto_batch.py (자동 반복 실행)

워커 관리 + 배치 실행 + 결과 정리를 완료될 때까지 자동 반복한다.

```bash
# 첫 실행 (워커 setup 포함, 완료될 때까지 자동 반복)
python3 auto_batch.py ./targets/ -o ./batch_results -n 4 -t 600 -w /root/kafl_workdir

# 워커가 이미 있으면 기존 워커 재활용, 실패 시 자동 teardown + re-setup
```

**동작 흐름:**

1. **Round 1**: 워커 setup (없으면) → batch 실행 → cleanup → 완료된 .exe 삭제
2. **Round 2+**: 남은 샘플 있으면 → teardown → 새 워커 setup → batch → cleanup
3. **종료 조건**: 모든 샘플 완료 / max rounds 도달 / 3라운드 연속 진전 없음

## cleanup_results.py (결과 정리)

배치 분석 후 빈 결과와 완료된 샘플을 정리한다.

```bash
python3 cleanup_results.py --results-dir ./batch_results --targets-dir ./targets

# dry-run (실제 삭제 없이 확인만)
python3 cleanup_results.py --results-dir ./batch_results --targets-dir ./targets --dry-run
```

- 덤프 파일이 없는 빈 결과 디렉토리 제거
- 성공적으로 처리된 .exe 파일을 targets 디렉토리에서 삭제

## Configuration

### kafl.yaml

kAFL 실행 설정. QEMU 메모리, 이미지 경로 등을 지정.

```yaml
qemu_memory: 4096
qemu_image: '@format {env[HOME]}/.local/share/libvirt/images/windows_x86_64_vagrant-kafl-windows.img'
```

### Harness Timeout

언패킹 타임아웃은 `setup_target.yml`의 `arguments` 필드에서 설정 (기본 300000ms = 5분).
소스 코드에서는 `src/userspace/unpack_harness.c`의 `DEFAULT_TIMEOUT_MS`.

## Output Structure

```
results/<sample_name>/
  dump/                    # WtE 메모리 덤프 디렉토리
    config.yaml            # kAFL 실행 설정
    page_cache.addr        # 페이지 캐시 주소
    pt_trace_dump_0        # Intel PT 트레이스
    wte_dump_*/            # WtE 이벤트별 덤프
  result.json              # 분석 결과 (status, duration, wte_count)
```

## Troubleshooting

### Worker VM 잔여 프로세스

`teardown` 후에도 VM이 남아있는 경우:

```bash
# libvirt 도메인 강제 정리
for i in 0 1 2 3; do
  virsh destroy worker${i}_kafl-worker-${i} 2>/dev/null
  virsh undefine worker${i}_kafl-worker-${i} 2>/dev/null
  virsh vol-delete worker${i}_kafl-worker-${i}.img --pool default 2>/dev/null
done
rm -rf workers/
vagrant global-status --prune
```

### Vagrant boot timeout

Windows VM 부팅이 느린 경우 `batch_analyze.py`의 `_init_worker_vm` timeout 값을 조정.
