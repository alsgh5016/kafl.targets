# 운영 노트 — box 이미지 요구사항과 워커 산정

2026-09 작업 기록. 배치 분석이 "덤프 0"으로 실패하던 문제들의 원인과 수정, 그리고
**git으로 전달되지 않는 box 이미지 수정**을 정리한다.

새 서버에 배포하거나 box를 다시 만들 때는 [다른 서버 적용 절차](#다른-서버-적용-절차)를
그대로 따른다. 코드 수정은 `git pull`로 오지만 box 이미지 수정은 오지 않는다.

---

## 1. box 이미지 요구사항 (git 밖, 반드시 수동 적용)

`kafl_windows` box 안의 Windows 이미지는 아래 네 가지를 만족해야 한다.
하나라도 빠지면 배치가 조용히 실패한다.

| # | 항목 | 없으면 생기는 증상 |
|---|---|---|
| 1 | Startup 폴더에 `kafl_target.lnk`가 **없을 것** | vagrant 부팅 시 하네스가 Nyx 하이퍼콜을 쏴서 stock QEMU가 `KVM internal error`로 도메인을 정지시킴 |
| 2 | `hiberfil.sys`가 **없을 것** | NTFS가 hibernated 상태로 잠겨 오프라인 수정 불가. `kafl fuzz`의 kAFL64 CPU 모델과 저장된 CR4 상태가 불일치해 #GP → triple-fault |
| 3 | Defender 정책 키가 설정될 것 | 실시간 보호가 살아 업로드/실행을 차단 |
| 4 | **Tamper Protection이 꺼질 것** | 3번 정책과 런타임 `Set-MpPreference`가 전부 무력화됨 |

4번이 가장 중요하다. Tamper Protection이 켜져 있으면 playbook의 Defender 비활성화
명령들이 **성공을 반환하면서 실제로는 반영되지 않는다.**

box를 어떻게 만들었느냐에 따라 필요한 항목이 다르다.

| box 출처 | 1 (바로가기) | 2 (hiberfil) | 3·4 (Defender) |
|---|---|---|---|
| packer로 새로 빌드 | 해당 없음 | 대개 해당 없음 | **필요** |
| 이미 프로비저닝된 VM에서 `vagrant package` | **필요** | **필요** | **필요** |

3·4번은 Windows 기본값이 그러하므로 **어떤 box든 항상 필요하다.**
1·2번은 실행 중이던 VM을 패키징했을 때 딸려 들어온다.

### 1.1 확인 방법

box 이미지를 읽기 전용으로 열어 확인한다. 워커가 돌고 있어도 backing file은
공유 읽기가 되므로 안전하다.

```bash
B=~/.vagrant.d/boxes/kafl_windows/0/libvirt/box.img
qemu-nbd --read-only -c /dev/nbd0 "$B" && sleep 3
mkdir -p /mnt/boxro && mount -t ntfs-3g -o ro /dev/nbd0p1 /mnt/boxro

# 1) Startup 바로가기 — desktop.ini 만 있어야 한다
ls "/mnt/boxro/Users/vagrant/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"

# 2) 최대절전 파일 — 없어야 한다
ls -la /mnt/boxro/hiberfil.sys

# 3,4) 레지스트리
H=/mnt/boxro/Windows/System32/config/SOFTWARE
hivexsh "$H" <<'EOF'
cd \Microsoft\Windows Defender\Features
lsval
EOF

umount /mnt/boxro; qemu-nbd -d /dev/nbd0
```

`TamperProtection=dword:00000000` 이어야 한다. `00000001` 이면 아래 절차로 끈다.

### 1.2 수정 절차

쓰기 수정은 **워커를 전부 내린 뒤**에만 가능하다. 워커 디스크가 box를 backing으로
참조하므로, 돌고 있는 상태에서 backing을 바꾸면 오버레이가 깨진다.

```bash
# 사전 준비
apt-get install -y libhivex-bin qemu-utils ntfs-3g
modprobe nbd max_part=8

cd <repo>/windows_x86_64
python3 batch_analyze.py teardown                     # 워커 제거
virsh -c qemu:///session vol-list default             # box 볼륨 이름 확인
virsh -c qemu:///session vol-delete <볼륨명> --pool default

B=~/.vagrant.d/boxes/kafl_windows/0/libvirt/box.img
qemu-nbd -c /dev/nbd0 "$B" && sleep 3
mkdir -p /mnt/box
```

NTFS가 hibernated/unclean이면 rw 마운트가 거부된다. 그때만 아래 두 줄을 먼저 실행한다.
(`ntfsfix`는 `$LogFile` 저널을, `remove_hiberfile`은 `hiberfil.sys`를 처리한다.)

```bash
ntfsfix -d /dev/nbd0p1
mount -t ntfs-3g -o remove_hiberfile /dev/nbd0p1 /mnt/box
```

문제 없으면 그냥:

```bash
mount -t ntfs-3g /dev/nbd0p1 /mnt/box
```

**(1) Startup 바로가기 제거**

```bash
rm -f "/mnt/box/Users/vagrant/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/kafl_target.lnk"
```

바로가기는 프로비저닝이 샘플마다 다시 만든다. box에 있으면 안 된다.

**(2) `hiberfil.sys` 제거** — `remove_hiberfile`로 마운트했으면 이미 지워졌다.
남아 있으면 `rm -f /mnt/box/hiberfil.sys`.

**(3) Defender 정책**

`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`는 기본 Windows 이미지에
**존재하지 않는다.** hivexsh의 `cd`는 없는 노드에서 실패하므로 먼저 확인한다.

```bash
H=/mnt/box/Windows/System32/config/SOFTWARE
cp "$H" "$H.bak"

hivexsh "$H" <<'EOF'
cd \Policies\Microsoft
ls
EOF
```

`Windows Defender`가 목록에 없으면 만든다. 있으면 이 블록은 건너뛴다.

```bash
hivexsh -w "$H" <<'EOF'
cd \Policies\Microsoft
add Windows Defender
commit
EOF
```

그 다음 값을 써 넣는다.

```bash
hivexsh -w "$H" <<'EOF'
cd \Policies\Microsoft\Windows Defender
setval 1
DisableAntiSpyware
dword:1
add Real-Time Protection
cd Real-Time Protection
setval 4
DisableRealtimeMonitoring
dword:1
DisableBehaviorMonitoring
dword:1
DisableOnAccessProtection
dword:1
DisableScanOnRealtimeEnable
dword:1
commit
EOF
```

`Windows Defender` 노드가 이미 있었다면 그 아래에 값도 있을 수 있다. `setval`은
노드의 값을 **전부 교체하므로**, 먼저 `lsval`로 확인하고 기존 값을 함께 써 넣어야
한다. 값 개수가 여러 개라면 아래 (4)번의 덤프 → 변환 → 적용 방식을 쓰는 것이
안전하다. `Real-Time Protection` 도 마찬가지다.

**(4) Tamper Protection 해제**

`Features` 키에는 다른 값들이 함께 있고 `setval`은 노드의 값을 전부 교체한다.
기존 값을 보존하면서 두 개만 바꾸려면 아래처럼 덤프 → 변환 → 적용한다.

```bash
H=/mnt/box/Windows/System32/config/SOFTWARE

hivexsh "$H" > /tmp/features.txt <<'EOF'
cd \Microsoft\Windows Defender\Features
lsval
EOF

python3 - <<'PY'
import re
out = []
for line in open('/tmp/features.txt'):
    line = line.rstrip('\n')
    if not line.strip():
        continue
    m = re.match(r'^"([^"]+)"=(.+)$', line)
    name, val = m.group(1), m.group(2)
    if name in ('TamperProtection', 'TamperProtectionSource'):
        val = 'dword:00000000'
    val = re.sub(r'^hex\((\d+)\):', r'hex:\1:', val)   # lsval → setval 형식
    out.append((name, val))
with open('/tmp/setval.txt', 'w') as f:
    f.write('cd \\Microsoft\\Windows Defender\\Features\n')
    f.write(f'setval {len(out)}\n')
    for n, v in out:
        f.write(n + '\n' + v + '\n')
    f.write('commit\n')
print(f'{len(out)} values')
PY

hivexsh -w "$H" < /tmp/setval.txt
```

**(5) 검증 후 정리**

```bash
hivexsh "$H" <<'EOF'
cd \Microsoft\Windows Defender\Features
lsval
EOF
# TamperProtection=dword:00000000, TamperProtectionSource=dword:00000000 확인

rm -f "$H.bak"
sync; umount /mnt/box; qemu-nbd -d /dev/nbd0
```

**(6) 워커 재생성**

```bash
make setup-workers NUM_WORKERS=<N>
```

box가 스토리지 풀로 다시 업로드된다. 워커당 약 90초.

### 1.3 `.box` 아카이브 동기화

위 수정은 `~/.vagrant.d/boxes/` 안의 이미지에만 적용된다. 원본 `.box` 파일로
`vagrant box add`를 다시 하면 되돌아가므로, 수정 후 재포장해 둔다.

```bash
cd ~/.vagrant.d/boxes/kafl_windows/0/libvirt
tar cf ~/kafl_windows.box box.img metadata.json Vagrantfile
```

`tar cf`(비압축)를 쓴다. qcow2는 이미 압축된 데이터라 gzip 이득이 거의 없고
시간만 더 든다. 전송은 `rsync -zP`를 쓴다.

---

## 2. 코드 수정 (git pull로 전달됨)

| 커밋 | 내용 |
|---|---|
| `7244aec` | DHCP 리스가 만료되면 ARP로 게스트 IP 조회, 실패 시 명시적 에러 |
| `e8a1b14` | 조회 전에 서브넷을 프로브해 neighbour 테이블을 채움 |
| `cbe0dc6` | 프로비저닝 결과(바로가기·하네스·샘플) 검증 |
| `1e8f07e` | Defender 대기를 게스트 내부 루프로 (WinRM 왕복 1회) |
| `1d44281` | 프로비저닝 실패 시 스냅샷 복원 후 1회 재시도 |
| `f660062` | CPU 핀닝을 `thread_siblings_list` 기반으로 산출 |
| `b5a4aed` | 워커 생성 시 스냅샷 저장 후 강제 전원 차단 |
| `13e847e` | 도메인이 실제로 꺼졌는지 확인 |
| `d93e094` | `fix-box`의 box 디스크 파일명 자동 탐지 |

### 2.1 "N개 이후 덤프가 전부 0" 의 원인

libvirt의 DHCP 리스는 dnsmasq 기본값인 **1시간** 뒤 만료된다. 스냅샷에서 복원된
게스트는 이미 IP를 가진 채 재개되므로 DHCP를 다시 하지 않는다. 그 시점부터
`vagrant winrm-config`가 빈 값을 반환하고,

```
ansible-playbook -i "," ...   →  "skipping: no hosts matched"  →  exit 0
```

ansible이 **호스트 0개로 성공**하므로 `vagrant provision`도 성공으로 보고된다.
게스트에는 아무것도 올라가지 않은 채 `kafl fuzz`가 돌아 600초 타임아웃.

워커 수와 무관하게 **시간 기반**으로 발생하므로, 처리 속도에 따라 "28개쯤부터"처럼
보인다. `7244aec` + `e8a1b14`가 ARP 대체 조회와 명시적 실패를 추가해 해결한다.

### 2.2 CPU 핀닝

`worker_id * 2`를 논리 CPU 번호로 그대로 쓰던 코드는 CPU 번호 매김에 의존했다.
형제 스레드 목록이 서버마다 다르다.

| 서버 | `cpu1`의 형제 | 물리 코어 id | 핀닝 가능 워커 |
|---|---|---|---|
| 32c/64t | `1,33` | 0~31 | 16 |
| 10c/20t | `1,11` | 0~9 | 5 |

`f660062`가 `thread_siblings_list`를 읽어 각 형제 그룹의 최소 id만 물리 코어로
취급한다. 워커 수가 코어 쌍보다 많으면 경고를 남긴다.

배포 전 확인:

```bash
cat /sys/devices/system/cpu/cpu1/topology/thread_siblings_list
```

---

## 3. 워커 수 산정

처리율은 두 값 중 작은 쪽으로 정해진다.

```
처리율 = min( 워커수 ÷ 분석시간,  1 ÷ 프로비저닝주기 )
```

프로비저닝은 `vagrant_lock`으로 **직렬화**되어 있다(`batch_analyze.py`,
libvirt 경합 방지). 따라서 워커를 아무리 늘려도 `1 ÷ 프로비저닝주기`가 상한이다.

### 3.1 실측 (32코어 / 125GB 서버, 109개 배치)

| 구성 | 프로비저닝 주기 | 처리율 | 실측 동시 분석 | 실패 |
|---|---|---|---|---|
| 4워커, Tamper 켜짐 | 93초 | 28.6/시간 | 4 | 6/109 |
| 12워커, Tamper 켜짐 | 110초 | 34.1/시간 | 3~4 | 3/40 (부분) |
| 12워커, Tamper 해제 | 57.8초 | 58.6/시간 | 5.8 (최대 7) | 0/109 |
| **8워커, Tamper 해제** | **59.3초** | **57.0/시간** | **5.6 (최대 7)** | **0/109** |

아래 두 행이 각각 109개 전체를 완주한 결과다 (2026-09-27, 1.86시간 / 1.91시간).
**워커를 12개에서 8개로 줄여도 처리율은 2.7% 차이뿐이다.**

`실측 동시 분석`은 `-machine kAFL64` 프로세스 수를 1분 간격으로 표본 수집한
값이다. **정의된 워커 수와 다르다** — 양쪽 모두 평균 5.6~5.8에 머문다.
12개를 띄우면 그중 절반 이상이 락 앞에서 대기만 한다.

샘플당 시간은 두 단계로 나뉘고, 교차점 계산에 써야 하는 값은 병렬로 도는
분석시간 쪽이다.

| 단계 | 12워커 | 8워커 | 성질 |
|---|---|---|---|
| 프로비저닝 단계 (락 대기 포함) | 319초 | **105초** | 직렬 + 대기 |
| **kafl 분석** | **373초** | **372초** | **병렬** |

마지막 표가 결정적이다. 워커를 4개 줄였는데 분석시간은 그대로이고 **락 대기만
3분의 1로 떨어졌다.** 12워커의 여분 4개가 하던 일은 기다리는 것뿐이었다.

Tamper Protection이 켜져 있으면 Defender가 업로드되는 바이너리와 게스트 내
`csc.exe` 컴파일을 실시간 스캔해 **프로비저닝이 두 배로 늘어난다.**

### 3.2 권장값

```
필요 워커 = 분석시간 373초 ÷ 프로비저닝 주기 57.8초 ≈ 6.5  ->  7개
```

프로비저닝이 직렬이라 57.8초에 1개씩만 내보낸다(상한 62/시간). 워커 7개면
`7 ÷ 373초 = 67/시간`으로 이미 그 상한을 넘기므로, **8번째 워커부터는 락 앞에서
대기만 한다.**

| 상한 | 값 |
|---|---|
| 프로비저닝 상한 (`3600 ÷ 57.8초`) | 62.2/시간 |
| 7워커의 분석 능력 (`7 ÷ 373초`) | 67.0/시간 |
| 12워커 실측 | 58.6/시간 |

- **32코어 / 125GB**: **8개**. 계산상 7개로 충분하지만 분석시간 편차가 커서
  1개를 여유로 둔다. 8워커와 12워커를 각각 109개씩 완주시켜 처리율이 같음을
  확인했다(57.0 대 58.6/시간). 12개는 메모리만 더 쓴다.
- **10코어 / 48GB**: 4~5개 (메모리가 먼저 막힌다)

처리율을 62/시간 위로 올리려면 워커가 아니라 **프로비저닝 주기 자체**를 줄여야
한다. 락 병렬화는 실패했다(6절). 남은 여지는 게스트 내 작업량 축소다.

워커당 자원 실측:

| 자원 | 단위당 | 비고 |
|---|---|---|
| 메모리 | **약 10.7 GB** | **동시 분석 1개당.** 대기 중인 워커는 거의 쓰지 않는다. 12워커 배치 최대 사용량 62.2GB / 동시분석 5.8개 |
| 물리 코어 | 2 | `CORES_PER_WORKER` 고정 |
| `/dev/shm` | 1 MB | 제약 아님 |
| 디스크 | 아래 참조 | |

메모리 상한 = `(총 메모리 − 호스트 10GB) ÷ 8.2`.
`kafl.yaml`의 `qemu_memory`를 2048로 낮추면 워커당 약 4.2GB가 되어 더 늘릴 수 있다.

---

## 4. 저장 용량

결과의 대부분이 **Intel PT 원시 트레이스**(`pt_trace_dump_0`)다.
109개 배치 완주 실측:

| 항목 | 용량 | 비중 |
|---|---|---|
| 전체 | 38.9 GB | 100% |
| `pt_trace_dump_0` | 36.8 GB | **94.7%** |
| 실제 WtE 덤프 | 1.3 GB | 3.4% |

- 샘플당 평균 **0.36 GB**, 편차가 크다 (65MB ~ 5GB+).
- 12워커 기준 **시간당 약 21 GB** (4워커에서는 약 13 GB).

즉 실제로 필요한 덤프는 전체의 3.4%뿐이고, 나머지는 후속 디코딩용 원시 트레이스다.

PT 트레이스는 후속 디코딩에 쓰이므로 `--trace`를 끌 수 없다. 대신 저장 파일시스템에
투명 압축을 걸면 디코더를 건드리지 않고 용량을 줄일 수 있다. PT 트레이스 대부분이
PSB 동기화 패킷(`02 82` 반복)이라 압축률이 매우 높다.

zstd -3 실측 (배치 내 5개 샘플, 크기 구간별):

| 원본 | 압축 후 | 압축률 |
|---|---|---|
| 4782 MB | 20.7 MB | 231배 |
| 265 MB | 1.20 MB | 221배 |
| 209 MB | 1.13 MB | 185배 |
| 171 MB | 1.25 MB | 136배 |
| 43 MB | 0.45 MB | 96배 |

**100~230배**를 기대할 수 있고, 큰 파일일수록 높다. 압축 해제 약 1.6GB/s.
38.9GB 배치 결과가 대략 0.2~0.4GB로 줄어든다.

```bash
mkfs.btrfs /dev/sdX
mount -o compress=zstd:3 /dev/sdX /mnt/kafl_results
```

결과 디렉터리(`-o`)뿐 아니라 **워크디렉터리(`-w`)도** 옮겨야 한다. 진행 중인
PT 트레이스가 거기 쌓인다.

---

## 5. 다른 서버 적용 절차

```bash
# 1) 코드
cd <repo>
git status --short          # 로컬 수정 확인
git pull
grep -c "neighbour table" windows_x86_64/setup_target.sh    # 3
grep -n "_ensure_domain_off" windows_x86_64/batch_analyze.py # 2줄

# 2) CPU 토폴로지 확인
cat /sys/devices/system/cpu/cpu1/topology/thread_siblings_list

# 3) 잔재 정리
pgrep -af "machine kAFL64"                  # 고아 QEMU → kill
virsh -c qemu:///session list --all         # paused 도메인 → virsh destroy
                                            # shut off 는 정상, 그대로 둔다

# 4) box 이미지 — 1절 절차대로. 이것이 핵심이다.

# 5) 1개로 검증
mkdir -p /tmp/one && cp targets/<샘플>.exe /tmp/one/
cd windows_x86_64
python3 batch_analyze.py run /tmp/one -o /tmp/one_results -t 300
# -> OK (..., WtE=N, dumps=NNNN) 이어야 한다. dumps=0 이면 멈추고 원인부터 본다.

# 6) 전체 배치
python3 auto_batch.py ./targets -o ./batch_results -n <N> -t 600
```

`make deploy`는 돌리지 않는다. `force_clone: true`라 examples 저장소를
`git reset --hard`로 되돌린다.

### 5.1 `auto_batch.py` 주의

라운드가 끝나면 `cleanup_results.py`가 **덤프가 생성된 샘플의 `.exe`를
`targets/`에서 제거한다.** 샘플 원본을 남기려면 먼저 백업하거나,
`batch_analyze.py run`을 직접 쓴다 (그쪽은 cleanup을 돌리지 않는다).

---

## 6. 알려진 함정

**프로비저닝 경로에 무엇을 추가하든 비용이 크다.** 실측 사례:

| 추가한 것 | 대가 |
|---|---|
| ansible `retries: 12, delay: 5` | 프로비저닝 +155초 (재시도마다 WinRM 세션이 새로 열린다) |
| `win_copy` + `fetch` 진단 태스크 2개 | 12워커에서 실패율 **38%** (`unreachable`) |

WinRM 왕복이 늘어나면 동시성이 높을 때 연결이 불안정해진다. 게스트 내부에서
한 번의 호출로 끝낼 수 있으면 그렇게 한다.

**프로비저닝 병렬화는 이득이 없다.** `vagrant_lock`을 libvirt 호출에만 걸고
ansible 구간을 풀어봤으나, 각 실행이 92초 → 1018초로 11배 느려져 총 처리율이
같았다 (호스트는 CPU 78% idle, iowait 0.1%). 되돌렸다.

**`vagrant package`가 멈추는 경우가 있다.** `virt-sysprep`이 libguestfs
어플라이언스를 못 띄우면 진행률 없이 멈춘 것처럼 보인다. `qemu-img rebase`까지
끝났으면 `box.img`는 이미 완전한 독립 qcow2이므로 수동으로 tar 하면 된다.
`ps -ef | grep -E "qemu-img|virt-sysprep"` 와 `/proc/<pid>/io` 의
`read_bytes` 증가 여부로 진행 중인지 판별한다.
