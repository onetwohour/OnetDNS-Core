# Windows 측정 하네스

리눅스 하네스(`benchmarks/dns-*`)는 dnsperf와 `/proc`에 기대고 있어 윈도우에서 돌지
않는다. 그렇다고 WSL에서 가상 스위치를 건너 호스트를 때리면 경로가 막혀 서버가 아니라
스위치를 재게 된다. 이 디렉터리는 그 두 문제를 피해 윈도우에서 판정 가능한 값을 만든다.

## 이 호스트에서 무엇이 천장인지부터 안다

`run-cpu-per-resolution.ps1`은 매번 **바닥값**을 먼저 측정한다. 받은 바이트를 그대로
돌려주는 에코 서버(`tools/dnsload --serve-echo`)를 실행하고 같은 부하를 넣는다. DNS
처리가 0인 서버조차 못 넘는 값이므로, 어떤 DNS 서버도 그보다 빠를 수 없다.

측정 사례에서 OnetDNS의 QPS는 그 바닥값의 **약 104%**였다. 즉 이 호스트에서 QPS는
서버의 성질이 아니라 OS UDP 경로의 성질이며, **QPS로는 서버 개선을 판정할 수 없다.**
바닥값을 같이 보고하지 않으면 "고쳤는데 QPS가 안 올랐다"를 서버 탓으로 잘못 읽는다.

호스트에 따라 바닥값은 크게 다르다. 실시간 바이러스 검사와 네트워크 검사(NIS), 그리고
누적된 방화벽 규칙이 데이터그램마다 붙기 때문이다. 이 값들을 바꾸는 것은 시스템 보안
설정 변경이므로 하네스는 건드리지 않고 읽어서 보고만 한다.

## 판정 가능한 축은 해석당 user CPU다

벽시계가 아니라 서버 프로세스가 실제로 태운 user CPU를 처리한 질의 수로 나눈다.
부하가 천장에 막혀 있어도 "질의 하나를 처리하는 비용"은 그대로 드러난다.

다만 이 호스트에서는 서버가 CPU의 1~2%만 쓰게 되므로 **절대값의 산포가 크다**(관측
40~90%). 그래서 절대값 단독 인용은 금지하고, 아래 A/B의 비율만 쓴다.

## A/B는 같은 라운드 안에서 교차한다

구간이 시간에 따라 열화하면 먼저 측정하는 팔이 유리해진다. 라운드마다 순서를 뒤집어
두 팔을 번갈아 재고 **같은 라운드 안의 비율**만 인용한다. 열화가 양쪽에 같이 실려
상쇄되기 때문이다.

```powershell
# 대시보드/통계 경로가 질의당 CPU에 얼마를 얹는지
powershell -File benchmarks/windows/run-cpu-per-resolution.ps1 `
  -Rounds 6 -Seconds 20 -ArgsA '--no-web' -ArgsB ''

# 두 빌드를 비교한다
powershell -File benchmarks/windows/run-cpu-per-resolution.ps1 `
  -BinaryB 'target\release\onetdns-baseline.exe'
```

`--no-web`을 뺀 팔은 대시보드를 기본 주소 `127.0.0.1:8553`에 연다. 이 PC에서 OnetDNS가
돌고 있으면 그 포트와 겹치므로, 그때는 `-ControlPort`로 다른 loopback 포트를 준다.

비율 산포가 게이트(기본 5%)를 넘으면 그 회차의 값은 인용하지 않는다. 넘더라도 모든
라운드가 같은 방향으로 크게 벌어진다면 방향만 보고하고 점추정은 보고하지 않는다.

## 부하 발생기

`tools/dnsload`는 std만 쓰며 루트 워크스페이스에 들어 있지 않다
(`tools/tls-diff`와 같은 방식). 요약 출력은 dnsperf와 같은 모양이라 기존 파서가
그대로 읽는다. 존과 질의 목록은 `benchmarks/dns-authority/generate-zone.sh`를
재사용하므로 리눅스 하네스와 같은 대상을 때린다.

```sh
cd tools/dnsload && cargo build --release
```
