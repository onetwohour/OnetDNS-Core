/*!
 * @brief EDNS Client Subnet을 붙이고 떼는 계층.
 */

use std::net::IpAddr;
use std::sync::Arc;

use onetdns_proto::{Edns, Message, RecordType};

use super::outcome_to_option;
use crate::native::{ResolveFailure, ResolveOutcome, Resolver};

/**
 * @brief 클라이언트 대역 정보를 붙이거나 떼는 계층.
 * @warning 붙이면 업스트림이 클라이언트 위치에 따라 다른 답을 준다. 그래서 이 계층이 켜지면
 *          UDP 고속 경로를 쓸 수 없다.
 */
pub struct EcsLayer {
    /** @brief 다음 계층. */
    inner: Arc<dyn Resolver>,
    /** @brief 붙일 옵션. 없으면 붙어 온 것을 뗀다. */
    option: Option<(u16, Vec<u8>)>,
}

impl EcsLayer {
    /** @brief 지정한 대역을 붙이는 계층. */
    pub fn new(inner: Arc<dyn Resolver>, custom_ip: IpAddr) -> Self {
        let (family, addr, prefix): (u16, Vec<u8>, u8) = match custom_ip {
            IpAddr::V4(v4) => (1, v4.octets().to_vec(), 24),
            IpAddr::V6(v6) => (2, v6.octets().to_vec(), 56),
        };
        let nbytes = (prefix as usize).div_ceil(8);
        let mut data = Vec::new();
        data.extend_from_slice(&family.to_be_bytes());
        data.push(prefix);
        data.push(0);
        data.extend_from_slice(&addr[..nbytes.min(addr.len())]);
        EcsLayer {
            inner,
            option: Some((8, data)),
        }
    }

    /** @brief 붙어 온 대역 정보를 떼는 계층. 이 서버의 클라이언트 위치를 업스트림에 흘리지 않으려는 것이다. */
    pub fn strip(inner: Arc<dyn Resolver>) -> Self {
        EcsLayer {
            inner,
            option: None,
        }
    }
}

/**
 * @brief EDNS 레코드를 다시 짜지 못해 질의를 접었음을 알린다.
 * @details 질의마다 호출되는 경로라 2의 거듭제곱 번째만 남긴다. 이 실패는 클라이언트에게
 *          SERVFAIL로 보이므로 기록이 없으면 원인을 찾을 수 없다.
 */
fn ecs_encode_failed(error: &impl std::fmt::Display) {
    /** @brief 누적 실패 수. */
    static COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let count = COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    if count.is_power_of_two() {
        onetdns_core::error!(event = "ecs.edns_encode_failed", count = count, %error, "클라이언트 대역 정보를 붙인 EDNS 레코드를 만들지 못해 질의를 실패로 접었습니다");
    }
}

impl Resolver for EcsLayer {
    /** @brief 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    /** @brief 대역 정보를 붙이거나 떼고 안으로 넘긴다. */
    fn resolve_outcome(&self, req: &Message) -> ResolveOutcome {
        let mut r = req.clone();
        let opt_index = r
            .additionals
            .iter()
            .position(|record| record.rtype == RecordType::OPT);
        let mut edns = opt_index
            .and_then(|index| Edns::from_record(&r.additionals[index]))
            .unwrap_or_default();
        edns.options.retain(|(code, _)| *code != 8);
        if let Some(option) = &self.option {
            edns.options.push(option.clone());
        }
        match (opt_index, self.option.is_some()) {
            (Some(index), _) => match edns.try_to_record() {
                Ok(record) => r.additionals[index] = record,

                Err(error) => {
                    ecs_encode_failed(&error);
                    return ResolveOutcome::Failure(ResolveFailure::Permanent(None));
                }
            },
            (None, true) => match edns.try_to_record() {
                Ok(record) => r.additionals.push(record),
                Err(error) => {
                    ecs_encode_failed(&error);
                    return ResolveOutcome::Failure(ResolveFailure::Permanent(None));
                }
            },
            (None, false) => {}
        }
        self.inner.resolve_outcome(&r)
    }
}

#[cfg(test)]
/** @brief 요청에 ECS 옵션이 붙는지. */
mod tests {
    use super::*;
    use crate::layers::test_support::*;
    use onetdns_proto::{RecordType, ResponseCode};

    #[test]
    /** @brief 대역 정보가 붙는지. */
    fn ecs_option_attached() {
        let inner = Mock::new(1, ResponseCode::NoError.0);
        let layer = EcsLayer::new(inner, "203.0.113.5".parse().unwrap());

        let option = layer.option.as_ref().expect("ECS 옵션이 부착되어야 함");
        assert_eq!(option.0, 8);
        assert_eq!(option.1, vec![0x00, 0x01, 24, 0, 203, 0, 113]);

        let resp = layer.resolve(&query("x.test", RecordType::A));
        assert!(resp.is_some());
    }
}
