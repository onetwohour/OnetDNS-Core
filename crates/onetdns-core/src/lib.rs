/*!
 * @brief 상위 크레이트가 공유하는 정책 트레이트와 원시 자료구조.
 *
 * @details onetdns-proto 바로 위에 놓인 두 번째 층이다. 여기 있는 트레이트가 데이터
 *          평면과 그 구현(필터, ACL, 속도 제한)의 경계를 이룬다. 상위 크레이트는 서로를
 *          직접 알지 않고 이 트레이트를 통해서만 만난다.
 */

/** @brief 질의를 보낸 쪽의 정보. */
pub mod client;
/** @brief 주소 대역. */
pub mod ipnet;
/** @brief 질의 하나의 패닉을 그 질의에만 가두는 것. */
pub mod isolation;
/** @brief JSON 읽고 쓰기. */
pub mod json;
/** @brief 로그. */
pub mod log;
/** @brief 상한이 있는 캐시 자료 구조. */
pub mod lrumap;
/** @brief 관리 화면을 내보이는 HTTPS 출처. */
pub mod origin;
/** @brief 접근 제어·속도 제한·차단이 지켜야 할 약속. */
pub mod policy;
/** @brief 난수. */
pub mod rng;
/** @brief RSA 서명 검증. */
pub mod rsa;
/** @brief 복제해도 원문 버퍼를 늘리지 않는 비밀 문자열. */
pub mod secret;
/** @brief 전부 교체할 수 있는 값. */
pub mod swap;
#[cfg(unix)]
/** @brief 스레드마다 작은 캐시를 두는 할당기. */
pub mod talloc;
/** @brief ICMP 오류가 수신을 깨뜨리지 않는 UDP 소켓과 데이터그램을 잃지 않는 수신 대기. */
pub mod udp;

pub use client::{ClientInfo, Transport};
pub use ipnet::IpNet;
pub use lrumap::LruMap;
pub use origin::HttpsOrigin;
pub use policy::{
    AccessControl, AclDecision, BlockResponse, FilterEngine, FilterExplanation, FilterVerdict,
    MatchStage, RateDecision, RateLimiter, RewriteTarget,
};
pub use rng::{
    ephemeral_random_array, fill_ephemeral_random, fill_random, random_array, try_fill_random,
    try_random_array,
};
pub use secret::SecretString;
pub use swap::ArcSwap;

/**
 * @brief 스레드 로컬 할당자가 쓰는 크기 계급.
 * @details 요청 크기를 이 중 하나로 올림해 같은 계급의 해제된 블록을 재사용한다. 계급이
 *          촘촘할수록 낭비가 줄지만 프리리스트 수가 늘어난다.
 */
pub const ALLOC_SIZE_CLASSES: [usize; 12] =
    [16, 32, 48, 64, 96, 128, 192, 256, 384, 512, 1024, 2048];

/** @brief 계급화 할당이 감당하는 정렬 상한. 이보다 큰 정렬은 시스템 할당자로 넘긴다. */
pub const ALLOC_MAX_ALIGN: usize = 16;

/**
 * @brief 요청 크기를 담을 수 있는 최소 계급을 고른다.
 * @return 맞는 계급이 없거나 정렬이 과하면 요청 크기 그대로. 이 경우 계급화가 적용되지 않는다.
 */
pub fn alloc_class_size(size: usize, align: usize) -> usize {
    if size == 0 || align > ALLOC_MAX_ALIGN {
        return size;
    }
    match ALLOC_SIZE_CLASSES.iter().find(|&&class| size <= class) {
        Some(&class) => class,
        None => size,
    }
}

/**
 * @brief 포이즌을 복구하며 잠그는 Mutex 확장.
 *
 * @details 요청 처리 중 패닉이 나면 그 스레드가 잡고 있던 뮤텍스가 포이즌된다. 그대로
 *          unwrap()하면 요청 하나의 패닉이 그 락을 쓰는 모든 후속 요청으로 번져
 *          서버 전체가 멎는다. 여기서는 내부 값을 그대로 이어받아 그 전파를 끊는다.
 * @warning 복구는 데이터가 일관되다는 뜻이 아니다. 이 락 뒤의 상태는 패닉 시점에
 *          부분 갱신돼 있어도 진행 가능한 것이어야 한다.
 */
pub trait MutexExt<T: ?Sized> {
    /** @brief 포이즌을 무시하고 잠근다. 포이즌 상태에서도 가드를 돌려준다. */
    fn lock_recover(&self) -> std::sync::MutexGuard<'_, T>;
}

impl<T: ?Sized> MutexExt<T> for std::sync::Mutex<T> {
    /**
     * @brief 잠금을 건다. 앞서 잡은 스레드가 패닉했어도 이어서 쓴다.
     * @warning 그 값이 반쯤 고쳐진 상태일 수 있다. 그래도 서비스를 멈추는 것보다는 낫다는
     *          판단이고, 이 값들은 그런 상태로도 뜻이 통하는 것들이다.
     */
    fn lock_recover(&self) -> std::sync::MutexGuard<'_, T> {
        self.lock().unwrap_or_else(|e| e.into_inner())
    }
}
