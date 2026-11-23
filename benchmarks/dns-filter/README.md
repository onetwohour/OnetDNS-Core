# 필터(차단 판정) 처리량 벤치

10만 개 `||bNNNNNN.example^` 규칙을 로드한 뒤, 차단 대상 이름 2만 종을
UDP로 질의해 차단 응답 합성 경로의 처리량을 측정한다. 차단 응답은 양쪽
모두 로컬 합성이라 업스트림 영향이 없다. 조건은 `../dns-cache`와 동일
(WSL2, 단일 worker, CPU 고정, 10초×5회 중앙값).

## 2026-07-19 직접 비교 (O-A-O)

AdGuard Home은 로컬 필터 파일 인제스트 제약(safe_fs_patterns) 때문에 같은
10만 규칙을 `user_rules`로 주입했고, 측정 전 `dig`로 실차단(0.0.0.0)을
확인했다. 1·2회차는 같은 시간창 연속, OnetDNS 3회차는 일시적 프로세스
겹침으로 몇 분 뒤 재측정했다(7배 격차 규모에서 드리프트 영향은 미미).

| 순서 | 엔진 | 중앙 QPS | 중앙 평균 지연 | RSS(규칙 로드 후) |
|---|---|---:|---:|---:|
| 1 | OnetDNS(10만 규칙) | 289,569 | 0.324 ms | 7.35 MiB |
| 2 | AdGuard Home(10만 user_rules) | 38,996 | 2.558 ms | 55.32 MiB |
| 3 | OnetDNS(10만 규칙) | 269,112 | 0.350 ms | — |

같은 규칙 수·같은 차단 워크로드에서 OnetDNS는 AdGuard Home 대비 처리량
**6.9~7.4배**, 평균 지연 약 **1/8**, 규칙 로드 후 RSS 약 **1/7.5**였다.
선행 단독 측정(292,032 QPS/0.321 ms)도 같은 수준이었다.

참고: OnetDNS의 10만 규칙 RSS 7.2 MiB는 byte-reversed DAWG/FST 동결
구조의 결과다(빌드 시 중복 제거 후 조회 경로 무할당).

## 2026-07-22 재실측 (O-A-O, 유휴 구간)

AdGuard Home을 `user_rules` 대신 정식 필터 파일 경로로 로드해 다시 쟀다.

| 순서 | 엔진 | 중앙 QPS | 중앙 지연 | RSS(규칙 로드 후) |
|---|---|---:|---:|---:|
| 1 | OnetDNS(10만 규칙) | 327,536 | 0.287 ms | 7.0 MiB |
| 2 | AdGuard Home(10만 규칙 파일) | 40,201 | 2.481 ms | 298.0 MiB |
| 3 | OnetDNS(10만 규칙) | 328,637 | 0.286 ms | 7.0 MiB |

처리량 **8.16배**, 지연 **8.6배 낮음**, RSS **42.6배 적음**. AGH 40,201은
2026-07-19의 38,996과 일치해 두 측정이 서로 검증된다.

## 측정 함정 두 가지 (반드시 확인)

**1. AGH가 규칙을 실제로 로드했는지.** `filters:`의 로컬 경로는 AGH의
`safe_fs_patterns`가 비어 있으면 조용히 거부된다. 규칙이 0개인 채로도
벤치는 "동작"하는 것처럼 보인다 — 아래 2번 때문이다. 설정에
`safe_fs_patterns`로 해당 경로 glob을 허용하고, `<workdir>/data/filters/`에
목록 파일이 실제로 생겼는지 확인한다.

**2. NXDOMAIN만으로 실차단을 판정하지 말 것.** 질의 이름(`b*.example`)은
벤치 권한 존에 없으므로, 차단이 안 걸려도 업스트림이 정당하게 NXDOMAIN을
돌려준다. 두 NXDOMAIN은 구분되지 않는다. **결정적 검사는 업스트림(권한
서버)을 끄고 질의하는 것**이다 — 로컬 차단이면 즉답(OnetDNS는 NXDOMAIN
0 ms, AGH는 0.0.0.0 0 ms), 아니면 SERVFAIL/타임아웃이 난다. 규칙 미로드
상태로 측정하면 AGH가 전 질의를 업스트림에 넘겨 **429 QPS·228 ms** 같은
비정상값이 나오고, 이를 "수백 배 우위"로 오독하게 된다.

## 재현

```sh
# 자산 생성(1회)
awk 'BEGIN{for(i=0;i<100000;i++) printf "||b%06d.example^\n", i}' > blocklist.txt
awk 'BEGIN{srand(7); for(i=0;i<20000;i++) printf "b%06d.example A\n", int(rand()*100000)}' > blocked-queries.txt

# OnetDNS (onetdns-filter.toml: forward 백엔드 + blocklists=[blocklist.txt], 캐시 끔)
taskset -c 2 onetdns --config onetdns-filter.toml --no-web --no-supervisor
DNSPERF_CPU=1 sh ../dns-cache/run-dnsperf.sh 15357 blocked-queries.txt 10 5

# 실차단 검증: 업스트림을 시작하지 않은 상태에서 즉답이어야 한다
dig @127.0.0.1 -p 15357 b011289.example A +noall +comment +stats   # NXDOMAIN, 0 msec
```

## 로드/갱신 중 최대 메모리

`run-update-memory.sh`는 차단 목록을 로드·갱신하는 동안의 최대 RSS(`VmHWM`)를 세
시나리오로 측정한다 — `first`(캐시 없이 처음 내려받아 로드), `update`(엔진이 올라간 뒤
목록이 바뀌어 재로드), `restart`(컴파일 캐시가 있는 상태로 재시작).

**세 시나리오는 서로 다른 값을 낸다.** 특히 `update`는 무중단 교체를 위해 구 엔진이
살아 있는 채로 새 엔진을 지으므로 `first`보다 높다. 하나를 재고 다른 것을 주장하지 말 것.

20만 규칙(중복 제거 후 175,166) 기준, netns 안에서 SSRF 보호를 끄지 않고 측정:

| 시나리오 | 원본 | 현재 | 변화 |
|---|---:|---:|---:|
| first | 79,044 | **28,164** | −64.4% |
| update | 90,896 | **38,572** | −57.6% |
| restart | 43,956 | **26,884** | −38.8% |

피크는 회차 편차가 0이다(같은 빌드 2회가 KiB 단위까지 일치) — A/B는 1회로 판정된다.
안정 상태 RSS는 편차가 있으므로 같은 기준으로 보지 말 것.

200만 규칙(x86_64 musl 정적 릴리스 빌드, WSL Debian의 netns)에서는 다음과 같다.

| 시나리오 | 최대 RSS | 안정 상태 RSS |
|---|---:|---:|
| first | 127,360 KiB | 31,124 KiB |
| update | 151,660 KiB | 31,140 KiB |
| restart | 55,424 KiB | 31,272 KiB |

목록 내용이 그대로인 채 `POST /v1/reload`로 다시 읽으면 컴파일 캐시를 쓰므로 피크가 update보다
낮다. 감독자 아래에서 대시보드를 켠 같은 구성으로 프로세스 트리의 Pss를 50 ms마다 재면, 안정
상태 41 MiB, 다시 읽는 동안 최대 93 MiB였다. 감독자 프로세스는 3 MiB다.

```sh
unshare -rn sh run-update-memory.sh /path/to/onetdns 200000
```

**픽스처가 결과를 지배한다.** 생성기는 실제 차단 목록의 구조(등록 도메인은 다양하되
서브도메인 라벨이 반복되고 한 도메인 아래 여러 항목)를 모델링한 것이지 실제 목록이
아니다. `ad000001.foo.test`처럼 공통 접미사만 다른 이름을 쓰면 automaton이 붕괴해
20만 규칙에서 상태가 45개까지 줄고 결론이 전부 뒤집힌다. 진짜 목록을 구할 수 있으면
그것으로 교체하는 편이 언제나 낫다. 자세한 계량과 거부된 후보는 `TECH_DEBT.md` 참조.

## 픽스처를 바꿔 다시 재기

`run-filter-interleave.sh`는 워크디렉터리에 `blocklist.txt`/`blocked-queries.txt`가
이미 있으면 그대로 쓴다. 붕괴하지 않는 픽스처로 재려면 먼저 생성기를 돌린다:

```sh
sh gen-realistic-fixture.sh "$W" 100000 20000
# AGH도 같은 목록을 물려야 공정하다 — 캐시된 필터 파일을 직접 교체한다
mkdir -p "$W/agwork/data/filters" && cp "$W/blocklist.txt" "$W/agwork/data/filters/1.txt"
sh run-filter-interleave.sh "$W" ./onetdns ./AdGuardHome "$W/agh.yaml"
```

같은 하네스·같은 규칙 수(10만)에서 픽스처만 바꾼 결과 — **양쪽 다 배율이 줄었다**:

| 지표 | 붕괴 픽스처 | 현실적 픽스처 |
|---|---:|---:|
| 처리량 배율 | 8.06~8.19배 | **6.95~7.19배** |
| RSS 규칙 로드 시점 | 1/5.75 | **1/3.85~1/3.95** |
| RSS 부하 10초 뒤 | 1/41 | **1/34.1~1/34.8** |

OnetDNS automaton이 커진 만큼(7,412 → 10,852 KiB) AGH는 거의 그대로였기 때문이다
(42,604 → 42,616~42,924 KiB). **현실적 픽스처 값을 인용할 것.**

RSS는 CPU 경합에 둔감해 브래킷 4회가 KiB 단위까지 재현되지만, **처리량은 이 하네스에서
드리프트가 크다** — 같은 구간의 한 브래킷이 레그 간 55.8%를 보였다. 처리량 배율은 반드시
O1/O2 차이가 작은 브래킷에서만 인용할 것.

## 대규모 목록의 자원 (240만 룰)

다음 표는 keyless cache v3 이전 Linux 서비스 RSS 기준선이다. 역사적 A/B 근거로 보존하지만
현재 용량 산정값으로 쓰면 안 된다. **픽스처에 따라 2.4~2.7배 달라진다.**

| 항목 | 붕괴 픽스처 | **현실적 픽스처** |
|---|---:|---:|
| 원문 | 48.0 MB | 53.7 MB |
| compiled cache | 45.8 MiB | **116.8 MiB** |
| 캐시에서 복원 | 257 ms | **668 ms** |
| 복원 중 최대 RSS | 95.4 MiB | **253.5 MiB** |
| 원문에서 처음 짓기 | 2.15 s | **3.38 s** |
| 빌드 중 최대 RSS | **122.8 MiB** | **237.7 MiB** |
| 안정 상태 RSS | 50.3 MiB | **121.8 MiB** |

로드용 해시맵을 아레나 테이블로 바꾸기 전에는 두 픽스처의 빌드 피크가 237.7 대 265.1 MiB로
비슷했다 — 그 구간을 automaton이 아니라 규칙 텍스트와 중복 제거 해시맵이 지배했기 때문이다.
바꾼 뒤로는 붕괴 픽스처가 **122.8 MiB(−48%)**로 내려가 두 픽스처가 갈라졌고, 현실적 픽스처의
피크는 automaton 빌더가 잡는다(궤적으로 확인, TECH_DEBT.md 참조).

### wide-DAWG pack/캐시 생성 A/B

위 Linux 서비스 RSS 표와 별개로, `domain_memory` 벤치는 전역 추적 할당자를 사용해 DAWG
pack과 캐시 인코딩 자체의 살아 있는 할당 바이트를 측정한다. 기본 순차 이름은 오토마톤이 지나치게
합쳐지므로 `ONETDNS_DOMAIN_BENCH_WIDE=1`로 고정 xorshift 픽스처를 써야 한다.

| 규칙 | 기존 BFS pack + 메모리 캐시 | 현재 pack + 스트리밍 캐시 | 감소 |
|---:|---:|---:|---:|
| 20만 | 41.9 MiB | **34.2 MiB** | **18.4%** |
| 240만 | 388.6 MiB | **288.4 MiB** | **25.8%** |

v2 당시 pack은 출력 상태 배열을 BFS 큐로 재사용해 별도 `order`를 없애고, 빌더를 더 일찍
반납한다. 프로덕션 저장 경로도 완성 payload `Vec`를 만들지 않고 64 KiB 버퍼로 원자적 임시
파일에 직접 기록한다. 이 A/B 안의 기존/당시 20만 v2 payload checksum은
`49e5547ca691859f`, 240만은 `dfee0ae0c305cc33`으로 바이트 단위 동일했다. 이 수치는
allocator A/B이지 OS RSS가 아니므로,
Linux `VmHWM`은 `musl-gcc`가 있는 환경에서 `run-update-memory.sh`로 별도 재검증해야 한다.

### keyless cache v3와 적응형 빌드 (2026-08-01)

아래는 Windows MSVC의 전역 추적 할당자 결과다. OS RSS와 섞지 않는다. 최종 compact map은
도메인 문자열/offset을 보존하지 않고, 일치 결과는 질의 문자열을 빌린다. hit 보고용 이름과
카운터는 `with_hit_tracking(true)`일 때만 오토마톤에서 복원한다.

| 240만 규칙 경로 | 이전 | 현재 | 변화 |
|---|---:|---:|---:|
| 모델형 최종, hit off | 93.7 MiB | **1.5 MiB** | **−98.4%** |
| 모델형 빌드 피크, hit off | 414.6 MiB | **370.5 MiB** | **−10.6%** |
| 모델형 최종, hit on | — | 112.0 MiB | opt-in 관측 비용 |
| 모델형 빌드 피크, hit on | — | 388.5 MiB | opt-in 관측 비용 |
| wide 스트리밍 생성 피크 | 288.4 MiB | **270.2 MiB** | **−6.3%** |
| wide 최종/파일 | — | **91.3 MiB** | 동일 keyless payload |
| wide decode 추가 피크 | 178.8 MiB | **108.0 MiB** | **−39.6%** |

32K 표본의 packed 밀도가 빌드 경로를 고른다. 오토마톤이 작은 모델형은 큰 연속 복사본을 만들지
않고 정렬 테이블에서 직접 만들고, wide/DGA형은 작은 연속 입력으로 옮겨 16B 정렬 항목을 먼저
반납한다. 두 경로 모두 완성 그래프가 모든 입력을 받아들이는지 확인한 뒤 pack한다.

cache v3는 이름/offset payload가 없고 오토마톤 언어를 비재귀로 재구성한다. 개발 단계 정책에
따라 v2 migration은 없으며 이전 버전은 즉시 거부한다. 240만 모델형 cache는 1.5 MiB,
decode 405 ms, decode 추가 피크 2.4 MiB였다. wide v3 checksum은 `f00062cc552c4c50`이다.

```powershell
$env:ONETDNS_DOMAIN_BENCH_RULES='2400000'
$env:ONETDNS_DOMAIN_BENCH_CACHE='1'
$env:ONETDNS_DOMAIN_BENCH_WIDE='1'
$env:ONETDNS_DOMAIN_BENCH_STREAM='1'
cargo bench -p onetdns-filter --bench domain_memory
```
