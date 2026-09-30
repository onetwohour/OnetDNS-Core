/*!
 * @brief 요청 단위 장애 격리 경계.
 *
 * @details 릴리스 프로필이 panic = "unwind"인 이유가 여기 있다. 외부 입력이 유발한
 *          패닉 하나가 워커 스레드를 죽이면 그 스레드가 담당하던 모든 연결이 함께 끊긴다.
 *          이 경계가 그것을 요청 하나의 실패로 가둔다.
 * @warning unwind는 OOM, 명시적 abort, FFI 메모리 손상, 운영체제 종료를 가두지 못한다.
 *          요청 처리 코드는 여전히 요청에서 온 값에 unwrap()/expect()를 쓰지 않아야 한다.
 */

use std::cell::Cell;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Once;

thread_local! {
    /** @brief 이 스레드가 현재 몇 겹의 요청 경계 안에 있는지. 0이면 경계 밖이다. */
    static REQUEST_DEPTH: Cell<u32> = const { Cell::new(0) };
}

/** @brief 패닉 알림을 한 번만 건다. */
static INSTALL_HOOK: Once = Once::new();

/** @brief 격리된 패닉 누적 수. /metrics의 onetdns_request_panics_total로 나간다. */
static REQUEST_PANICS: AtomicU64 = AtomicU64::new(0);

/** @brief 요청 처리가 패닉으로 끝났음을 나타내는 표시. */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestPanicked;

/** @brief 경계 진입·이탈로 깊이를 관리하는 RAII 가드. */
struct Boundary;

impl Boundary {
    /** @brief 깊이를 올리며 경계에 들어간다. Drop이 되돌린다. 언와인드 중에도 실행된다. */
    fn enter() -> Self {
        REQUEST_DEPTH.with(|depth| depth.set(depth.get().saturating_add(1)));
        Self
    }
}

impl Drop for Boundary {
    /** @brief 깊이를 되돌린다. 되돌리지 않으면 다음 질의가 이미 안에 있는 것으로 보인다. */
    fn drop(&mut self) {
        REQUEST_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

/**
 * @brief 요청 경계 안의 패닉은 기본 진단 출력을 내지 않도록 훅을 건다.
 *
 * @details 격리된 패닉마다 역추적을 찍으면 공격자가 로그 폭주를 유발할 수 있다. 경계 밖의
 *          패닉은 진짜 결함이므로 원래 훅으로 그대로 흘려보낸다.
 * @note 여러 번 불려도 한 번만 설치된다.
 */
pub fn install_request_panic_hook() {
    INSTALL_HOOK.call_once(|| {
        let original = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let contained = REQUEST_DEPTH.with(|depth| depth.get() != 0);
            if !contained {
                original(info);
            }
        }));
    });
}

/**
 * @brief 요청 처리 클로저를 실행하며 패닉을 가둔다.
 *
 * @details 전송별로 격리 단위가 다르다. UDP·DNSCrypt·DoQ·DoH3는 패킷 또는 작업 하나,
 *          TCP·DoT·DoH는 연결 하나, QUIC은 연결 상태를 버리되 리스너는 유지한다.
 * @note 진단 로그는 2의 거듭제곱 번째 발생에서만 남긴다. 패닉을 유도할 수 있는 입력이
 *       존재할 때 로그 자체가 자원 소모 경로가 되지 않게 하려는 것이다.
 * @return 클로저 반환값, 또는 패닉했으면 RequestPanicked.
 */
pub fn catch_request<T>(f: impl FnOnce() -> T) -> Result<T, RequestPanicked> {
    let _boundary = Boundary::enter();
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(value) => Ok(value),
        Err(_) => {
            let count = REQUEST_PANICS.fetch_add(1, Ordering::Relaxed) + 1;
            if count.is_power_of_two() {
                crate::error!(
                    event = "request.panic_isolated",
                    count,
                    "Contained an unexpected error while handling a query; the worker thread keeps running"
                );
            }
            Err(RequestPanicked)
        }
    }
}

/** @brief 지금까지 격리한 패닉 수. 지표 노출용이다. */
pub fn request_panic_count() -> u64 {
    REQUEST_PANICS.load(Ordering::Relaxed)
}

#[cfg(test)]
/** @brief 패닉이 그 질의에만 머무는지, 그리고 겹쳐 들어가도 깊이가 맞는지. */
mod tests {
    use super::*;

    #[test]
    /** @brief 패닉한 뒤에도 다음 질의가 처리되는지. */
    fn catches_panic_and_runs_next_request() {
        assert_eq!(catch_request(|| 7), Ok(7));
        assert_eq!(
            catch_request(|| panic!("malicious request")),
            Err(RequestPanicked)
        );
        assert_eq!(catch_request(|| 9), Ok(9));
    }

    #[test]
    /** @brief 겹쳐 들어간 뒤 풀려도 깊이가 맞는지. */
    fn nested_boundaries_restore_depth_after_unwind() {
        let result = catch_request(|| catch_request(|| panic!("nested")));
        assert_eq!(result, Ok(Err(RequestPanicked)));
        assert_eq!(catch_request(|| 11), Ok(11));
    }
}
