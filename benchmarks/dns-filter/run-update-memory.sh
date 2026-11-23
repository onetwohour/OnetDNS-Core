#!/bin/sh
# 차단 목록 로드/갱신 중 최대 RSS(VmHWM)를 세 시나리오로 측정한다.
#
#   first    - 캐시 없는 상태에서 구독을 처음 내려받아 로드
#   update   - 엔진이 이미 올라간 뒤 목록 내용이 바뀌어 재적재(구·신 엔진 공존)
#   restart  - 캐시가 있는 상태로 재시작
#
# **세 시나리오는 서로 다른 값을 낸다. 특히 update는 first보다 높다** — 구 엔진이
# 살아 있는 채로 새 엔진을 짓기 때문이다. 하나를 재고 다른 것을 주장하지 말 것.
#
# usage: unshare -rn sh run-update-memory.sh BIN [RULES=200000]
#
# 왜 netns인가: 차단 목록 다운로드는 SSRF 보호가 루프백·사설 주소를 정당하게 거부한다.
# 보호를 끄지 말고 namespace 안에 dummy 인터페이스로 라우팅 가능한 주소를 만들어
# 정상 경로로 받게 한다.
#
# RSS는 회차 편차가 거의 0이라(±8 KiB 실측) 1회 측정으로 A/B 판정이 된다.
set -eu
BIN=${1:?usage: run-update-memory.sh BIN [RULES]}
RULES=${2:-200000}
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

mkdir -p "$W/www"
# **픽스처가 결과를 지배한다.** 두 극단 모두 틀렸다 —
#  - 공통 접미사만 다른 이름(ad000001.foo.test): DAWG가 붕괴해 20만 규칙에 상태 45개.
#  - 완전 무작위 라벨: 공유 구조가 0이라 상태 556,993개로 과대평가.
# 실제 차단 목록은 그 사이다 — 등록 도메인은 다양하지만 서브도메인 라벨
# (ads/track/analytics/cdn/pixel...)이 반복되고 한 등록 도메인 아래 여러 항목이 붙는다.
# 아래 생성기는 그 구조를 모델링한다. **실제 목록이 아니라 모델**임을 명시한다 —
# 진짜 목록을 구할 수 있으면 그것으로 교체하는 편이 언제나 낫다.
gen_list() {
    awk -v n="$1" -v seed="$2" 'BEGIN {
        srand(seed);
        split("com net org io ru cn info biz top xyz", tld, " ");
        ntld = 10;
        split("ads ad track tracker analytics stat stats metrics pixel beacon cdn img static log event collect sync rtb bid px t a", sub_, " ");
        nsub = 22;
        # 등록 도메인 풀: 항목 수의 약 1/4. 실제 목록의 도메인당 항목 수와 비슷하다.
        ndom = int(n / 4) + 1;
        for (d = 0; d < ndom; d++) {
            len = 5 + int(rand() * 9);
            lab = "";
            for (j = 0; j < len; j++) lab = lab sprintf("%c", 97 + int(rand() * 26));
            dom[d] = lab "." tld[1 + int(rand() * ntld)];
        }
        emitted = 0;
        while (emitted < n) {
            d = int(rand() * ndom);
            r = rand();
            if (r < 0.25) name = dom[d];
            else if (r < 0.85) name = sub_[1 + int(rand() * nsub)] "." dom[d];
            else name = sub_[1 + int(rand() * nsub)] "." sub_[1 + int(rand() * nsub)] "." dom[d];
            printf "||%s^\n", name;
            emitted++;
        }
    }'
}
gen_list "$RULES" 1 >"$W/www/list.txt"
gen_list "$RULES" 2 >"$W/www/list2.txt"

ip link set lo up
ip link add dummy0 type dummy 2>/dev/null || true
ip addr add 1.2.3.4/32 dev dummy0
ip link set dummy0 up

(cd "$W/www" && python3 -m http.server 18080 --bind 1.2.3.4 >/dev/null 2>&1) &
HTTP=$!
trap 'kill -KILL $HTTP 2>/dev/null || true; rm -rf "$W"' EXIT
sleep 1

cat >"$W/onetdns.toml" <<EOS
mode = "personal"
backend = "forward"
listen = ["127.0.0.1:15999"]
upstreams = ["1.1.1.1"]
workers = 1
do_udp = true
do_tcp = false
cache_enabled = true
cache_size = 1000
blocklist_urls = ["http://1.2.3.4:18080/list.txt"]
list_refresh_secs = 3
EOS
# 캐시 디렉터리는 설정 키가 아니라 설정 파일 옆 blocklist-cache/로 자동 결정된다.

wait_for() {
    log=$1
    pat=$2
    want=$3
    i=0
    while [ "$i" -lt 400 ]; do
        [ -d "/proc/$PID" ] || return 1
        seen=$(grep -c "$pat" "$log" 2>/dev/null) || seen=0
        if [ "${seen:-0}" -ge "$want" ]; then
            return 0
        fi
        i=$((i + 1))
        sleep 0.1
    done
    return 1
}

peak() { awk '/^VmHWM:/{print $2}' "/proc/$PID/status" 2>/dev/null; }
rss() { awk '/^VmRSS:/{print $2}' "/proc/$PID/status" 2>/dev/null; }

"$BIN" run --config "$W/onetdns.toml" --no-web --no-supervisor >"$W/a.log" 2>&1 &
PID=$!
wait_for "$W/a.log" "filter.subscription_applied" 1 || echo "warn: 1차 로드를 확인하지 못했습니다" >&2
sleep 1
echo "first   peak_rss_kib=$(peak) settled_rss_kib=$(rss) $(grep 'filter.subscription_applied' "$W/a.log" | grep -o 'block=[0-9]*' | tail -1)"

# 내용을 바꿔야 지문이 달라져 실제 재빌드가 일어난다.
cp "$W/www/list2.txt" "$W/www/list.txt"
wait_for "$W/a.log" "filter.subscription_applied" 2 || echo "warn: 갱신 로드를 확인하지 못했습니다" >&2
sleep 1
echo "update  peak_rss_kib=$(peak) settled_rss_kib=$(rss)"
kill -KILL "$PID" 2>/dev/null || true
sleep 1

# 재시작 레그는 순수 캐시 경로여야 한다. 원본 서버를 내리고 갱신 주기도 길게 잡아
# 다시 내려받지 않게 한다(그러지 않으면 update 시나리오를 한 번 더 측정하는 셈이 된다).
kill -KILL "$HTTP" 2>/dev/null || true
sed 's/^list_refresh_secs = .*/list_refresh_secs = 86400/' "$W/onetdns.toml" >"$W/restart.toml"

"$BIN" run --config "$W/restart.toml" --no-web --no-supervisor >"$W/b.log" 2>&1 &
PID=$!
wait_for "$W/b.log" "filter.lists_loaded\|filter.cache_loaded\|filter.cache_applied" 1 || echo "warn: 재시작 로드를 확인하지 못했습니다" >&2
sleep 2
echo "restart peak_rss_kib=$(peak) settled_rss_kib=$(rss)"
kill -KILL "$PID" 2>/dev/null || true
