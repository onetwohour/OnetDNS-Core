/*!
 * @brief DHCPv6 서버.
 *
 * @details 주소를 나눠 주면서 이 서버를 DNS로 함께 알린다. 재시작해도 같은 클라이언트가
 *          같은 주소를 받도록 임대 정보를 파일에 남긴다.
 * @warning 인증이 없는 프로토콜이라 상한이 방어의 전부다. 클라이언트 식별자 길이와 임대
 *          개수를 제한하지 않으면 임의로 만든 식별자로 주소와 메모리를 모두 소진시킬 수 있다.
 */

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::net::{Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

/** @brief 읽어들일 임대 파일 크기 상한. */
const MAX_PERSIST_FILE: u64 = 16 * 1024 * 1024;
/** @brief 임대 파일의 첫 줄. 형식이 다르면 읽지 않는다. */
const LEASE_HEADER: &str = "ONETDNS-DHCP6-LEASES-V1\n";

/** @brief 담을 임대 개수 상한. */
const MAX_LEASES: usize = 100_000;

/** @brief DUID type 2바이트와 최소 1바이트 식별자를 합친 길이 하한. */
const MIN_DUID_LEN: usize = 3;
/** @brief DUID type 2바이트와 최대 128바이트 식별자를 합친 길이 상한. */
const MAX_DUID_LEN: usize = 130;
/** @brief IPv6에서 확장 헤더가 없을 때 가능한 표준 UDP payload 최대값. */
const MAX_STANDARD_IPV6_UDP_PAYLOAD: usize = u16::MAX as usize - 8;
/** @brief 최대 표준 payload와 초과 데이터그램을 구별할 한 바이트까지 받는다. */
const DHCP6_RECV_CAPACITY: usize = MAX_STANDARD_IPV6_UDP_PAYLOAD + 1;
/** @brief 주소 하나를 담은 IA_NA의 outer TLV까지 포함한 최대 응답 wire 길이. */
const IA_NA_ADDRESS_RESPONSE_WIRE_LEN: usize = 4 + 12 + 4 + 24;
/** @brief 고정 응답 옵션을 빼기 전에도 절대 넘을 수 없는 IA 응답 개수. */
const MAX_RESPONSE_IA_COUNT: usize =
    (MAX_STANDARD_IPV6_UDP_PAYLOAD - 4) / IA_NA_ADDRESS_RESPONSE_WIRE_LEN;
/** @brief 직접 클라이언트가 인접 relay와 server를 찾는 link-local multicast 그룹. */
const DHCP6_CLIENT_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);
/** @brief 둘째 IA부터 쓰는 고정 길이 보조 키. 정상 DUID보다 길어 충돌하지 않는다. */
const SECONDARY_IA_KEY_LEN: usize = 1 + MAX_DUID_LEN + 4;

/** @brief RFC 9915의 DUID type+identifier 길이 범위인지. */
pub(super) fn valid_duid(duid: &[u8]) -> bool {
    (MIN_DUID_LEN..=MAX_DUID_LEN).contains(&duid.len())
}

/** @brief 표준 UDP 길이 안의 완전한 데이터그램만 파서로 넘긴다. */
fn standard_dhcp6_datagram_len(received: usize) -> Option<usize> {
    (received <= MAX_STANDARD_IPV6_UDP_PAYLOAD).then_some(received)
}

#[derive(Clone, Copy)]
/** @brief IAID를 종전 값 구조의 정렬 여백에 함께 두는 주소 상태. */
struct IaValue {
    ip: u128,
    expiry: u64,
    iaid: [u8; 4],
    /** @brief 첫 값이면 추가 IA의 머리, 추가 값이면 다음 IAID. 자기 IAID는 끝 표식이다. */
    link: [u8; 4],
}

impl IaValue {
    /** @brief 연결이 없는 새 IA 값. */
    fn new(ip: u128, expiry: u64, iaid: [u8; 4]) -> Self {
        Self {
            ip,
            expiry,
            iaid,
            link: iaid,
        }
    }
}

#[derive(Clone, Copy)]
/** @brief 추가 IA 값. 이전 IAID까지 가져 임의 삭제도 O(1)로 연결한다. */
struct AdditionalIaValue {
    value: IaValue,
    /** @brief 이전 추가 IAID. 머리에서는 자기 IAID가 표식이다. */
    previous: [u8; 4],
}

/** @brief 같은 DUID의 둘째 IA를 모호하지 않은 빌린 HashMap 키로 만든다. */
fn secondary_ia_key<'a>(
    duid: &[u8],
    iaid: [u8; 4],
    storage: &'a mut [u8; SECONDARY_IA_KEY_LEN],
) -> Option<&'a [u8]> {
    if duid.is_empty() || duid.len() > MAX_DUID_LEN {
        return None;
    }
    storage[0] = u8::try_from(duid.len()).ok()?;
    storage[1..1 + duid.len()].copy_from_slice(duid);
    storage[1 + MAX_DUID_LEN..].copy_from_slice(&iaid);
    Some(storage)
}

/** @brief 보조 키를 DUID와 IAID로 되돌린다. */
fn split_secondary_ia_key(key: &[u8]) -> Option<(&[u8], [u8; 4])> {
    if key.len() != SECONDARY_IA_KEY_LEN {
        return None;
    }
    let duid_len = usize::from(*key.first()?);
    if duid_len == 0 || duid_len > MAX_DUID_LEN {
        return None;
    }
    Some((
        &key[1..1 + duid_len],
        key[1 + MAX_DUID_LEN..].try_into().ok()?,
    ))
}

#[derive(Default)]
/** @brief 보통 DUID는 한 번만 찾고, 같은 DUID의 추가 IA만 별도 맵에 두는 기록. */
struct IaMap {
    primary: HashMap<Vec<u8>, IaValue>,
    additional: HashMap<Vec<u8>, AdditionalIaValue>,
}

impl IaMap {
    /** @brief 첫 IA는 맵 한 번, 추가 IA만 보조 키 한 번을 더 찾아 반환한다. */
    fn get(&self, duid: &[u8], iaid: [u8; 4]) -> Option<&IaValue> {
        let primary = self.primary.get(duid)?;
        if primary.iaid == iaid {
            return Some(primary);
        }
        let mut storage = [0; SECONDARY_IA_KEY_LEN];
        self.additional
            .get(secondary_ia_key(duid, iaid, &mut storage)?)
            .map(|additional| &additional.value)
    }

    /** @brief 바인딩을 가변으로 찾는다. */
    fn get_mut(&mut self, duid: &[u8], iaid: [u8; 4]) -> Option<&mut IaValue> {
        let primary_iaid = self.primary.get(duid)?.iaid;
        if primary_iaid == iaid {
            return self.primary.get_mut(duid);
        }
        let mut storage = [0; SECONDARY_IA_KEY_LEN];
        self.additional
            .get_mut(secondary_ia_key(duid, iaid, &mut storage)?)
            .map(|additional| &mut additional.value)
    }

    /** @brief 첫 IA는 raw DUID로, 추가 IA는 앞뒤 연결된 보조 키로 삽입한다. */
    fn insert(&mut self, duid: &[u8], mut value: IaValue) -> Option<IaValue> {
        if duid.is_empty() || duid.len() > MAX_DUID_LEN {
            return None;
        }
        match self.primary.entry(duid.to_vec()) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                value.link = value.iaid;
                entry.insert(value);
                return None;
            }
            std::collections::hash_map::Entry::Occupied(mut entry)
                if entry.get().iaid == value.iaid =>
            {
                value.link = entry.get().link;
                return Some(entry.insert(value));
            }
            std::collections::hash_map::Entry::Occupied(_) => {}
        }

        let mut storage = [0; SECONDARY_IA_KEY_LEN];
        let key = secondary_ia_key(duid, value.iaid, &mut storage)?;
        if let Some(additional) = self.additional.get_mut(key) {
            value.link = additional.value.link;
            return Some(std::mem::replace(&mut additional.value, value));
        }

        let new_iaid = value.iaid;
        let (primary_iaid, old_head) = {
            let primary = self
                .primary
                .get_mut(duid)
                .expect("The first IA must be present");
            let old_head = primary.link;
            primary.link = new_iaid;
            (primary.iaid, old_head)
        };
        if old_head != primary_iaid {
            let mut old_storage = [0; SECONDARY_IA_KEY_LEN];
            let old_key = secondary_ia_key(duid, old_head, &mut old_storage)
                .expect("The DUID must already be validated");
            self.additional
                .get_mut(old_key)
                .expect("Additional IA links must be intact")
                .previous = new_iaid;
            value.link = old_head;
        } else {
            value.link = new_iaid;
        }
        self.additional.insert(
            key.to_vec(),
            AdditionalIaValue {
                value,
                previous: new_iaid,
            },
        );
        None
    }

    /** @brief 임의 IA를 O(1)로 제거하고 첫 IA면 다음 IA를 raw DUID 키로 승격한다. */
    fn remove(&mut self, duid: &[u8], iaid: [u8; 4]) -> Option<IaValue> {
        let primary_iaid = self.primary.get(duid)?.iaid;
        if primary_iaid == iaid {
            let removed = self.primary.remove(duid)?;
            if removed.link != removed.iaid {
                let mut head_storage = [0; SECONDARY_IA_KEY_LEN];
                let head_key = secondary_ia_key(duid, removed.link, &mut head_storage)?;
                let promoted = self
                    .additional
                    .remove(head_key)
                    .expect("The additional IA head must be present")
                    .value;
                if promoted.link != promoted.iaid {
                    let mut next_storage = [0; SECONDARY_IA_KEY_LEN];
                    let next_key = secondary_ia_key(duid, promoted.link, &mut next_storage)?;
                    let next = self
                        .additional
                        .get_mut(next_key)
                        .expect("The next additional IA must be present");
                    next.previous = next.value.iaid;
                }
                self.primary.insert(duid.to_vec(), promoted);
            }
            return Some(removed);
        }

        let mut storage = [0; SECONDARY_IA_KEY_LEN];
        let key = secondary_ia_key(duid, iaid, &mut storage)?;
        let removed = self.additional.remove(key)?;
        let next = removed.value.link;
        if removed.previous == iaid {
            let primary = self
                .primary
                .get_mut(duid)
                .expect("The first IA must be present");
            primary.link = if next == iaid { primary.iaid } else { next };
        } else {
            let mut previous_storage = [0; SECONDARY_IA_KEY_LEN];
            let previous_key = secondary_ia_key(duid, removed.previous, &mut previous_storage)?;
            let previous = self
                .additional
                .get_mut(previous_key)
                .expect("The previous additional IA must be present");
            previous.value.link = if next == iaid {
                previous.value.iaid
            } else {
                next
            };
        }
        if next != iaid {
            let mut next_storage = [0; SECONDARY_IA_KEY_LEN];
            let next_key = secondary_ia_key(duid, next, &mut next_storage)?;
            let next_value = self
                .additional
                .get_mut(next_key)
                .expect("The next additional IA must be present");
            next_value.previous = if removed.previous == iaid {
                next_value.value.iaid
            } else {
                removed.previous
            };
        }
        Some(removed.value)
    }

    /** @brief 모든 IA 수. */
    fn len(&self) -> usize {
        self.primary.len().saturating_add(self.additional.len())
    }

    /** @brief IA가 하나도 없는지. */
    fn is_empty(&self) -> bool {
        self.primary.is_empty()
    }

    /** @brief 테스트에서 고수위 회수를 확인할 첫 맵 capacity. */
    #[cfg(test)]
    fn capacity(&self) -> usize {
        self.primary
            .capacity()
            .saturating_add(self.additional.capacity())
    }

    /** @brief 값만 연속 순회한다. */
    fn values(&self) -> impl Iterator<Item = &IaValue> {
        self.primary
            .values()
            .chain(self.additional.values().map(|entry| &entry.value))
    }

    /** @brief 원래 DUID와 함께 모든 값을 순회한다. */
    fn entries(&self) -> impl Iterator<Item = (&[u8], &IaValue)> {
        self.primary
            .iter()
            .map(|(duid, value)| (duid.as_slice(), value))
            .chain(self.additional.iter().filter_map(|(key, entry)| {
                let (duid, iaid) = split_secondary_ia_key(key)?;
                (iaid == entry.value.iaid).then_some((duid, &entry.value))
            }))
    }

    /** @brief 가장 이른 만료 시각. */
    fn next_expiry(&self) -> u64 {
        self.values()
            .map(|value| value.expiry)
            .min()
            .unwrap_or(u64::MAX)
    }

    /** @brief 만료된 첫·추가 IA를 연결을 유지하며 할당 없이 제거한다. */
    fn remove_expired(&mut self, now: u64, used: &mut HashSet<u128>) {
        let additional = &mut self.additional;
        self.primary.retain(|duid, primary| loop {
            if primary.expiry > now {
                return true;
            }
            used.remove(&primary.ip);
            if primary.link == primary.iaid {
                return false;
            }
            let mut head_storage = [0; SECONDARY_IA_KEY_LEN];
            let head_key = secondary_ia_key(duid, primary.link, &mut head_storage)
                .expect("The DUID must already be validated");
            let promoted = additional
                .remove(head_key)
                .expect("The additional IA head must be present")
                .value;
            if promoted.link != promoted.iaid {
                let mut next_storage = [0; SECONDARY_IA_KEY_LEN];
                let next_key = secondary_ia_key(duid, promoted.link, &mut next_storage)
                    .expect("The DUID must already be validated");
                let next = additional
                    .get_mut(next_key)
                    .expect("The next additional IA must be present");
                next.previous = next.value.iaid;
            }
            *primary = promoted;
        });

        for (duid, primary) in &mut self.primary {
            if primary.link == primary.iaid {
                continue;
            }
            let mut previous = None;
            let mut current = primary.link;
            loop {
                let (expiry, ip, next) = {
                    let mut storage = [0; SECONDARY_IA_KEY_LEN];
                    let key = secondary_ia_key(duid, current, &mut storage)
                        .expect("The DUID must already be validated");
                    let entry = additional
                        .get(key)
                        .expect("Additional IA links must be intact");
                    (entry.value.expiry, entry.value.ip, entry.value.link)
                };
                let has_next = next != current;
                if expiry <= now {
                    let mut storage = [0; SECONDARY_IA_KEY_LEN];
                    let key = secondary_ia_key(duid, current, &mut storage)
                        .expect("The DUID must already be validated");
                    additional.remove(key);
                    used.remove(&ip);
                    if let Some(previous_iaid) = previous {
                        let mut previous_storage = [0; SECONDARY_IA_KEY_LEN];
                        let previous_key =
                            secondary_ia_key(duid, previous_iaid, &mut previous_storage)
                                .expect("The DUID must already be validated");
                        let previous_value = additional
                            .get_mut(previous_key)
                            .expect("The previous additional IA must be present");
                        previous_value.value.link = if has_next { next } else { previous_iaid };
                    } else {
                        primary.link = if has_next { next } else { primary.iaid };
                    }
                    if !has_next {
                        break;
                    }
                    let mut next_storage = [0; SECONDARY_IA_KEY_LEN];
                    let next_key = secondary_ia_key(duid, next, &mut next_storage)
                        .expect("The DUID must already be validated");
                    let next_value = additional
                        .get_mut(next_key)
                        .expect("The next additional IA must be present");
                    next_value.previous = previous.unwrap_or(next);
                    current = next;
                } else {
                    if !has_next {
                        break;
                    }
                    previous = Some(current);
                    current = next;
                }
            }
        }
    }

    /** @brief 복원 상태에서 만료·범위 밖·중복 주소를 연결을 유지하며 제거한다. */
    fn retain_valid(&mut self, now: u64, start: u128, end: u128, used: &mut HashSet<u128>) {
        let additional = &mut self.additional;
        self.primary.retain(|duid, primary| loop {
            let valid = primary.expiry > now
                && start <= end
                && primary.ip >= start
                && primary.ip <= end
                && used.insert(primary.ip);
            if valid {
                return true;
            }
            onetdns_core::warn!(event = "dhcp6.stale_lease_dropped", duid = %hex_bytes(duid), iaid = %hex_bytes(&primary.iaid), ip = %Ipv6Addr::from(primary.ip), "Removed saved leases outside the current DHCPv6 address range");
            if primary.link == primary.iaid {
                return false;
            }
            let mut head_storage = [0; SECONDARY_IA_KEY_LEN];
            let head_key = secondary_ia_key(duid, primary.link, &mut head_storage)
                .expect("The DUID must already be validated");
            let promoted = additional
                .remove(head_key)
                .expect("The additional IA head must be present")
                .value;
            if promoted.link != promoted.iaid {
                let mut next_storage = [0; SECONDARY_IA_KEY_LEN];
                let next_key = secondary_ia_key(duid, promoted.link, &mut next_storage)
                    .expect("The DUID must already be validated");
                let next = additional
                    .get_mut(next_key)
                    .expect("The next additional IA must be present");
                next.previous = next.value.iaid;
            }
            *primary = promoted;
        });

        for (duid, primary) in &mut self.primary {
            if primary.link == primary.iaid {
                continue;
            }
            let mut previous = None;
            let mut current = primary.link;
            loop {
                let (value, next) = {
                    let mut storage = [0; SECONDARY_IA_KEY_LEN];
                    let key = secondary_ia_key(duid, current, &mut storage)
                        .expect("The DUID must already be validated");
                    let entry = *additional
                        .get(key)
                        .expect("Additional IA links must be intact");
                    (entry.value, entry.value.link)
                };
                let has_next = next != current;
                let valid = value.expiry > now
                    && value.ip >= start
                    && value.ip <= end
                    && used.insert(value.ip);
                if !valid {
                    onetdns_core::warn!(event = "dhcp6.stale_lease_dropped", duid = %hex_bytes(duid), iaid = %hex_bytes(&value.iaid), ip = %Ipv6Addr::from(value.ip), "Removed saved leases outside the current DHCPv6 address range");
                    let mut storage = [0; SECONDARY_IA_KEY_LEN];
                    let key = secondary_ia_key(duid, current, &mut storage)
                        .expect("The DUID must already be validated");
                    additional.remove(key);
                    if let Some(previous_iaid) = previous {
                        let mut previous_storage = [0; SECONDARY_IA_KEY_LEN];
                        let previous_key =
                            secondary_ia_key(duid, previous_iaid, &mut previous_storage)
                                .expect("The DUID must already be validated");
                        let previous_value = additional
                            .get_mut(previous_key)
                            .expect("The previous additional IA must be present");
                        previous_value.value.link = if has_next { next } else { previous_iaid };
                    } else {
                        primary.link = if has_next { next } else { primary.iaid };
                    }
                    if !has_next {
                        break;
                    }
                    let mut next_storage = [0; SECONDARY_IA_KEY_LEN];
                    let next_key = secondary_ia_key(duid, next, &mut next_storage)
                        .expect("The DUID must already be validated");
                    let next_value = additional
                        .get_mut(next_key)
                        .expect("The next additional IA must be present");
                    next_value.previous = previous.unwrap_or(next);
                    current = next;
                } else {
                    if !has_next {
                        break;
                    }
                    previous = Some(current);
                    current = next;
                }
            }
        }
    }

    /** @brief 비면 모든 버킷을 반환하고, 드문 IA 맵도 같은 고수위 규칙으로 줄인다. */
    fn release_excess_capacity(&mut self) {
        if self.is_empty() {
            *self = Self::default();
            return;
        }
        if self.primary.capacity() > self.primary.len().saturating_mul(4).max(16) {
            self.primary.shrink_to(self.primary.len().saturating_mul(2));
        }
        if self.additional.capacity() > self.additional.len().saturating_mul(4).max(16) {
            self.additional
                .shrink_to(self.additional.len().saturating_mul(2));
        }
    }
}

/** @brief 크기 상한을 걸어 임대 파일을 읽는다. 못 읽으면 빈 상태로 시작한다. */
fn read_persist_text(path: &std::path::Path) -> Option<String> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => {
            onetdns_core::warn!(
                event = "dhcp6.restore_open_failed",
                path = %path.display(),
                %error,
                "Could not open saved DHCP state; starting empty"
            );
            return None;
        }
    };
    let mut bytes = Vec::new();
    if let Err(error) = file.take(MAX_PERSIST_FILE + 1).read_to_end(&mut bytes) {
        onetdns_core::warn!(
            event = "dhcp6.restore_read_failed",
            path = %path.display(),
            %error,
            "Could not read saved DHCP state; starting empty"
        );
        return None;
    }
    if bytes.len() as u64 > MAX_PERSIST_FILE {
        onetdns_core::warn!(
            event = "dhcp6.restore_too_large",
            path = %path.display(),
            bytes = bytes.len(),
            limit = MAX_PERSIST_FILE,
            "Saved DHCP file exceeds the size limit; not restoring it"
        );
        return None;
    }
    match String::from_utf8(bytes) {
        Ok(text) => Some(text),
        Err(error) => {
            onetdns_core::warn!(
                event = "dhcp6.restore_invalid_utf8",
                path = %path.display(),
                %error,
                "Saved DHCP file is not valid text; not restoring it"
            );
            None
        }
    }
}

/** @brief 서버를 찾는 요청. */
pub const SOLICIT: u8 = 1;
/** @brief 서버가 자신을 알리는 응답. */
pub const ADVERTISE: u8 = 2;
/** @brief 주소를 달라는 요청. */
pub const REQUEST: u8 = 3;
/** @brief 임대를 늘려 달라는 요청. */
pub const RENEW: u8 = 5;
/** @brief 확정 응답. */
pub const REPLY: u8 = 7;
/** @brief 주소를 돌려주는 요청. */
pub const RELEASE: u8 = 8;
/** @brief 주소 없이 DNS 같은 설정만 묻는 요청. */
pub const INFORMATION_REQUEST: u8 = 11;

/** @brief 클라이언트 식별자 옵션. */
pub const OPT_CLIENT_ID: u16 = 1;
/** @brief 서버 식별자 옵션. */
pub const OPT_SERVER_ID: u16 = 2;
/** @brief IA_NA(임시가 아닌 주소) 옵션. */
pub const OPT_IA_NA: u16 = 3;
/** @brief 주소 하나와 그 수명 옵션. */
pub const OPT_IA_ADDR: u16 = 5;
/** @brief 임시 주소 IA 옵션. */
const OPT_IA_TA: u16 = 4;
/** @brief 접두사 위임 IA 옵션. */
const OPT_IA_PD: u16 = 25;
/** @brief 처리 결과 코드 옵션. */
pub const OPT_STATUS_CODE: u16 = 13;
/** @brief DNS 서버 목록 옵션. */
pub const OPT_DNS_SERVERS: u16 = 23;

/** @brief 요청을 정상 처리했다. */
const STATUS_SUCCESS: u16 = 0;
/** @brief 이 IA에는 클라이언트와 결합된 주소가 없다. */
const STATUS_NO_BINDING: u16 = 3;
/** @brief 이 IA에 내줄 주소가 없다. */
const STATUS_NO_ADDRS_AVAIL: u16 = 2;

#[derive(Debug, Clone)]
/** @brief 주고받는 메시지 하나. */
pub struct Dhcp6Message {
    /** @brief 메시지 종류. */
    pub msg_type: u8,
    /** @brief 거래 번호. 요청과 응답을 짝짓는다. */
    pub txid: [u8; 3],
    /** @brief 담긴 옵션들. */
    pub options: Vec<(u16, Vec<u8>)>,
}

impl Dhcp6Message {
    /**
     * @brief 바이트열을 메시지로.
     * @warning 옵션 길이가 남은 바이트를 넘으면 전체를 거부한다. 거기까지만 받아들이면
     *          잘린 요청이 온전한 요청처럼 처리된다.
     */
    pub fn parse(buf: &[u8]) -> Option<Dhcp6Message> {
        if buf.len() < 4 {
            return None;
        }
        let msg_type = buf[0];
        let txid = [buf[1], buf[2], buf[3]];
        let mut options = Vec::new();
        let mut ia_count = 0usize;
        let mut seen_client_id = false;
        let mut seen_server_id = false;
        let mut i = 4;
        while i < buf.len() {
            if buf.len() - i < 4 {
                return None;
            }
            let code = u16::from_be_bytes([buf[i], buf[i + 1]]);
            let len = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
            i += 4;
            let end = i.checked_add(len)?;
            if end > buf.len() {
                return None;
            }
            match code {
                OPT_CLIENT_ID => {
                    if seen_client_id || !valid_duid(&buf[i..end]) {
                        return None;
                    }
                    seen_client_id = true;
                    options.push((code, buf[i..end].to_vec()));
                }
                OPT_SERVER_ID => {
                    if seen_server_id || !valid_duid(&buf[i..end]) {
                        return None;
                    }
                    seen_server_id = true;
                    options.push((code, buf[i..end].to_vec()));
                }
                OPT_IA_NA => {
                    ia_count = ia_count.checked_add(1)?;
                    if ia_count > MAX_RESPONSE_IA_COUNT {
                        return None;
                    }
                    options.push((code, buf[i..end].to_vec()));
                }
                _ => {}
            }
            i = end;
        }
        Some(Dhcp6Message {
            msg_type,
            txid,
            options,
        })
    }

    /** @brief 메시지를 바이트열로. */
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(4);
        b.push(self.msg_type);
        b.extend_from_slice(&self.txid);
        for (code, data) in &self.options {
            let Ok(len) = u16::try_from(data.len()) else {
                continue;
            };
            b.extend_from_slice(&code.to_be_bytes());
            b.extend_from_slice(&len.to_be_bytes());
            b.extend_from_slice(data);
        }
        b
    }

    /** @brief 정확히 하나만 있는 옵션의 내용. 없거나 중복이면 거부한다. */
    fn option(&self, code: u16) -> Option<&[u8]> {
        let mut matching = self.options.iter().filter(|(c, _)| *c == code);
        let value = matching.next()?.1.as_slice();
        matching.next().is_none().then_some(value)
    }
}

/** @brief 연속된 DHCPv6 하위 옵션의 길이 경계를 검사한다. */
fn valid_nested_options(mut options: &[u8]) -> bool {
    while !options.is_empty() {
        if options.len() < 4 {
            return false;
        }
        let len = u16::from_be_bytes([options[2], options[3]]) as usize;
        let Some(end) = 4usize.checked_add(len) else {
            return false;
        };
        if end > options.len() {
            return false;
        }
        options = &options[end..];
    }
    true
}

/** @brief 검증이 끝난 IA_NA의 빌린 표현. */
struct ParsedIaNa<'a> {
    iaid: [u8; 4],
    options: &'a [u8],
}

impl ParsedIaNa<'_> {
    /** @brief 이 IA의 첫 주소. 서버 응답은 현재 IA마다 하나를 할당한다. */
    fn first_address(&self) -> Option<u128> {
        let mut options = self.options;
        while !options.is_empty() {
            let code = u16::from_be_bytes([options[0], options[1]]);
            let len = u16::from_be_bytes([options[2], options[3]]) as usize;
            let end = 4 + len;
            if code == OPT_IA_ADDR {
                return Some(u128::from_be_bytes(
                    options[4..20].try_into().expect("IAADDR was validated"),
                ));
            }
            options = &options[end..];
        }
        None
    }

    /** @brief 이 IA에 특정 주소가 들어 있는지 무할당으로 찾는다. */
    fn contains_address(&self, expected: u128) -> bool {
        let mut options = self.options;
        while !options.is_empty() {
            let code = u16::from_be_bytes([options[0], options[1]]);
            let len = u16::from_be_bytes([options[2], options[3]]) as usize;
            let end = 4 + len;
            if code == OPT_IA_ADDR
                && u128::from_be_bytes(options[4..20].try_into().expect("IAADDR was validated"))
                    == expected
            {
                return true;
            }
            options = &options[end..];
        }
        false
    }
}

/** @brief IA_NA와 그 안의 모든 IAADDR를 무할당으로 검증한다. */
fn parse_ia_na(ia_na: &[u8]) -> Option<ParsedIaNa<'_>> {
    if ia_na.len() < 12 {
        return None;
    }
    let iaid = [ia_na[0], ia_na[1], ia_na[2], ia_na[3]];
    let mut options = &ia_na[12..];
    while !options.is_empty() {
        if options.len() < 4 {
            return None;
        }
        let code = u16::from_be_bytes([options[0], options[1]]);
        let len = u16::from_be_bytes([options[2], options[3]]) as usize;
        let end = 4usize.checked_add(len)?;
        if end > options.len() {
            return None;
        }
        let data = &options[4..end];
        if code == OPT_IA_ADDR && (data.len() < 24 || !valid_nested_options(&data[24..])) {
            return None;
        }
        options = &options[end..];
    }
    Some(ParsedIaNa {
        iaid,
        options: &ia_na[12..],
    })
}

/** @brief 주소 하나와 수명을 담은 옵션. */
fn ia_addr_option(addr: Ipv6Addr, pref: u32, valid: u32) -> Vec<u8> {
    let mut d = Vec::with_capacity(24);
    d.extend_from_slice(&addr.octets());
    d.extend_from_slice(&pref.to_be_bytes());
    d.extend_from_slice(&valid.to_be_bytes());
    let mut o = Vec::with_capacity(28);
    o.extend_from_slice(&OPT_IA_ADDR.to_be_bytes());
    let len = u16::try_from(d.len()).expect("IAADDR option length must fit in a 16-bit integer");
    o.extend_from_slice(&len.to_be_bytes());
    o.extend_from_slice(&d);
    o
}

/** @brief IA_NA 옵션. 갱신 시점 두 개와 주소가 들어간다. */
fn ia_na_option(iaid: [u8; 4], t1: u32, t2: u32, addr: Ipv6Addr, lease: u32) -> (u16, Vec<u8>) {
    let mut d = Vec::new();
    d.extend_from_slice(&iaid);
    d.extend_from_slice(&t1.to_be_bytes());
    d.extend_from_slice(&t2.to_be_bytes());
    d.extend_from_slice(&ia_addr_option(addr, lease, lease));
    (OPT_IA_NA, d)
}

/** @brief 사용자 임대 수명을 RFC 9915 권고 T1·T2로 오버플로 없이 바꾼다. */
fn renewal_timers(lease: u32) -> (u32, u32) {
    if lease == u32::MAX {
        return (u32::MAX, u32::MAX);
    }
    (lease / 2, (u64::from(lease) * 4 / 5) as u32)
}

/** @brief wire의 infinity 임대를 내부에서도 만료되지 않는 시각으로 보존한다. */
fn lease_expiry(now: u64, lease: u32) -> u64 {
    if lease == u32::MAX {
        u64::MAX
    } else {
        now.saturating_add(u64::from(lease))
    }
}

/** @brief 사람 문자열 없이 고정 크기 Status Code 옵션을 만든다. */
fn status_option(code: u16) -> (u16, Vec<u8>) {
    (OPT_STATUS_CODE, code.to_be_bytes().to_vec())
}

/** @brief 주소 대신 IA별 상태만 담은 IA_NA 응답. */
fn ia_na_status_option(iaid: [u8; 4], code: u16) -> (u16, Vec<u8>) {
    let mut data = Vec::with_capacity(18);
    data.extend_from_slice(&iaid);
    data.extend_from_slice(&[0; 8]);
    data.extend_from_slice(&OPT_STATUS_CODE.to_be_bytes());
    data.extend_from_slice(&2u16.to_be_bytes());
    data.extend_from_slice(&code.to_be_bytes());
    (OPT_IA_NA, data)
}

#[derive(Debug, Clone)]
/** @brief 나눠 줄 범위와 함께 알릴 값들. */
pub struct Dhcp6Config {
    /** @brief 이 서버의 서버 식별자. */
    pub server_duid: Vec<u8>,
    /** @brief 나눠 줄 범위의 시작. */
    pub range_start: Ipv6Addr,
    /** @brief 나눠 줄 범위의 끝. */
    pub range_end: Ipv6Addr,
    /** @brief 함께 알릴 DNS 서버. */
    pub dns: Vec<Ipv6Addr>,
    /** @brief multicast를 가입할 인터페이스. 0은 운영체제 기본. */
    pub interface_index: u32,
    /** @brief 임대 기간. */
    pub lease_secs: u32,

    /** @brief 임대 기록을 담아 둘 파일. */
    pub lease_file: Option<PathBuf>,
}

/** @brief 임대 하나. */
pub struct Lease6Info {
    /** @brief 클라이언트 식별자. */
    pub duid: Vec<u8>,
    /** @brief 이 클라이언트 안에서 IA_NA를 식별하는 값. */
    pub iaid: [u8; 4],
    /** @brief 빌려준 주소. */
    pub ip: Ipv6Addr,
    /** @brief 이 임대가 끝나는 시각. */
    pub expiry_unix: u64,
}

/** @brief 임대 기록. */
pub struct Lease6Pool {
    /** @brief 나눠 줄 범위의 시작. */
    start: u128,
    /** @brief 나눠 줄 범위의 끝. */
    end: u128,
    /** @brief 임대 기간. */
    lease_secs: u32,
    /** @brief 첫 IA는 raw DUID, 추가 IA는 고정 보조 키로 찾는 확정 임대들. */
    leases: IaMap,
    /** @brief 같은 두 단계 키로 찾는 광고 후 미확정 주소들. */
    offers: IaMap,
    /** @brief 임대 또는 offer가 점유한 주소. 새 할당이 기록 전체를 복사하지 않게 한다. */
    used: HashSet<u128>,
    /** @brief 임대 기록을 담아 둘 파일. */
    persist: Option<PathBuf>,
    /** @brief 범위가 바닥났다고 이미 알렸는지. 요청마다 같은 경고를 되풀이하지 않으려는 것이다. */
    exhausted: bool,
    /** @brief 다음 새 주소 검색을 시작할 위치. */
    allocation_cursor: u128,
    /** @brief 가장 이른 임대 만료 시각. */
    next_expiry: u64,
}

impl Lease6Pool {
    /** @brief 원격 DUID가 만드는 확정 임대와 임시 offer의 합계. */
    fn dynamic_entries(&self) -> usize {
        self.leases.len().saturating_add(self.offers.len())
    }

    /**
     * @brief 저장된 임대를 읽어 기록을 만든다.
     * @note 지금 설정한 범위 밖의 임대는 버린다. 설정을 바꾼 뒤에도 이전 주소를 계속
     *       내주면 그 주소는 어디에도 닿지 않는다.
     */
    pub fn new(cfg: &Dhcp6Config) -> Self {
        let start = u128::from(cfg.range_start);
        let end = u128::from(cfg.range_end);
        let now = crate::unix_now();
        let mut leases = cfg
            .lease_file
            .as_deref()
            .map(load_leases6)
            .unwrap_or_default();
        let mut used = HashSet::with_capacity(leases.len());
        leases.retain_valid(now, start, end, &mut used);
        let next_expiry = leases.next_expiry();
        let mut pool = Lease6Pool {
            start,
            end,
            lease_secs: cfg.lease_secs,
            leases,
            offers: IaMap::default(),
            used,
            persist: cfg.lease_file.clone(),
            exhausted: false,
            allocation_cursor: start,
            next_expiry,
        };
        pool.seek_cursor_to_available();
        pool
    }

    /**
     * @brief 서비스를 재시작할 때 기록을 버리지 않고 새 설정에 맞춘다.
     * @details 새 기록을 만들면 이미 나간 주소를 다른 기기에 또 준다. 새 범위 밖의 임대와
     *          확정되지 않은 광고만 버린다.
     */
    pub fn reconfigure(&mut self, cfg: &Dhcp6Config) {
        let start = u128::from(cfg.range_start);
        let end = u128::from(cfg.range_end);
        let mut used = HashSet::with_capacity(self.leases.len());
        self.leases
            .retain_valid(crate::unix_now(), start, end, &mut used);
        self.start = start;
        self.end = end;
        self.lease_secs = cfg.lease_secs;
        self.persist = cfg.lease_file.clone();
        self.offers = IaMap::default();
        self.used = used;
        self.next_expiry = self.leases.next_expiry();
        self.exhausted = false;
        self.allocation_cursor = start;
        self.seek_cursor_to_available();
        self.save();
    }

    #[cfg(test)]
    /** @brief 직접 로드한 테스트 상태까지 포함해 주소 인덱스와 다음 만료 시각을 다시 만든다. */
    fn rebuild_runtime(&mut self) {
        self.used = self
            .leases
            .values()
            .chain(self.offers.values())
            .map(|value| value.ip)
            .collect();
        self.next_expiry = self.leases.next_expiry().min(self.offers.next_expiry());
        self.seek_cursor_to_available();
    }

    /** @brief 시작·복원 단계에서 첫 요청이 찬 앞부분을 걷지 않도록 커서를 옮긴다. */
    fn seek_cursor_to_available(&mut self) {
        if self.start > self.end {
            return;
        }
        let mut candidate = self.start;
        for _ in 0..self.used.len().saturating_add(1) {
            if !self.used.contains(&candidate) {
                self.allocation_cursor = candidate;
                return;
            }
            candidate = if candidate == self.end {
                self.start
            } else {
                candidate + 1
            };
            if candidate == self.start {
                return;
            }
        }
    }

    /** @brief 가장 이른 만료 전에는 O(1), 도달했을 때만 임대 기록을 정리한다. */
    fn cleanup_expired(&mut self, now: u64) {
        if now < self.next_expiry {
            return;
        }
        self.leases.remove_expired(now, &mut self.used);
        self.offers.remove_expired(now, &mut self.used);
        self.next_expiry = self.leases.next_expiry().min(self.offers.next_expiry());
        if self.leases.is_empty() && self.offers.is_empty() {
            self.leases = IaMap::default();
            self.offers = IaMap::default();
            self.used = HashSet::new();
        } else {
            self.leases.release_excess_capacity();
            self.offers.release_excess_capacity();
            if self.used.capacity() > self.used.len().saturating_mul(4).max(16) {
                self.used.shrink_to(self.used.len().saturating_mul(2));
            }
        }
    }

    /**
     * @brief 범위가 바닥났는지가 바뀌었을 때만 알린다.
     * @details 클라이언트는 실패해도 계속 다시 묻는다. 요청마다 남기면 같은 경고가 쌓인다.
     */
    fn note_availability(&mut self, picked: Option<u128>) -> Option<u128> {
        match (picked, self.exhausted) {
            (None, false) => {
                self.exhausted = true;
                onetdns_core::warn!(event = "dhcp6.pool_exhausted", range_start = %Ipv6Addr::from(self.start), range_end = %Ipv6Addr::from(self.end), entries = self.dynamic_entries(), "DHCPv6 address range is full; new devices cannot get an address");
            }
            (Some(_), true) => {
                self.exhausted = false;
                onetdns_core::info!(event = "dhcp6.pool_available", range_start = %Ipv6Addr::from(self.start), range_end = %Ipv6Addr::from(self.end), "DHCPv6 address range has free addresses again");
            }
            _ => {}
        }
        picked
    }

    /**
     * @brief 이 클라이언트에 줄 주소를 고른다.
     * @details 이미 받은 것이 살아 있으면 그대로 준다. 범위가 좁으면 앞에서부터 훑고,
     *          넓으면 무작위로 몇 번 시도한다. 넓은 범위를 다 훑으면 시간이 끝나지 않는다.
     * @return 줄 주소. 상한에 닿았거나 남은 슬롯이 없으면 없다.
     */
    pub fn allocate(&mut self, duid: &[u8], iaid: [u8; 4]) -> Option<u128> {
        if duid.is_empty() || duid.len() > MAX_DUID_LEN {
            return None;
        }
        let now = crate::unix_now();
        self.cleanup_expired(now);
        let mut has_binding = false;
        if let Some(value) = self.leases.get(duid, iaid) {
            has_binding = true;
            if value.expiry > now {
                return Some(value.ip);
            }
        }
        if let Some(value) = self.offers.get(duid, iaid) {
            has_binding = true;
            if value.expiry > now {
                return Some(value.ip);
            }
        }

        if !has_binding && self.dynamic_entries() >= MAX_LEASES {
            return self.note_availability(None);
        }
        if self.start > self.end {
            return self.note_availability(None);
        }
        let mut candidate =
            if self.allocation_cursor >= self.start && self.allocation_cursor <= self.end {
                self.allocation_cursor
            } else {
                self.start
            };
        let initial = candidate;
        let mut picked = None;
        for _ in 0..self.used.len().saturating_add(1) {
            let next = if candidate == self.end {
                self.start
            } else {
                candidate + 1
            };
            if !self.used.contains(&candidate) {
                self.allocation_cursor = next;
                picked = Some(candidate);
                break;
            }
            candidate = next;
            if candidate == initial {
                break;
            }
        }
        self.note_availability(picked)
    }

    /** @brief SOLICIT에 광고한 주소를 잠시 점유해 다른 DUID에 중복 광고하지 않는다. */
    fn hold_offer(&mut self, duid: &[u8], iaid: [u8; 4], ip: u128) -> bool {
        if duid.is_empty() || duid.len() > MAX_DUID_LEN {
            return false;
        }
        if ip < self.start || ip > self.end {
            return false;
        }
        let now = crate::unix_now();
        self.cleanup_expired(now);
        if self
            .leases
            .get(duid, iaid)
            .is_some_and(|value| value.ip == ip && value.expiry > now)
        {
            return true;
        }
        let own_offer = self.offers.get(duid, iaid).map(|value| value.ip);
        if self.used.contains(&ip) && own_offer != Some(ip) {
            return false;
        }
        if own_offer.is_none() && self.dynamic_entries() >= MAX_LEASES {
            return false;
        }
        let expiry = now.saturating_add(60);
        if let Some(old) = self.offers.insert(duid, IaValue::new(ip, expiry, iaid)) {
            if old.ip != ip {
                self.used.remove(&old.ip);
            }
        }
        self.used.insert(ip);
        self.next_expiry = self.next_expiry.min(expiry);
        true
    }

    /** @brief 주소를 기록에 적는다. REQUEST면 같은 IA에 살아 있는 offer를 요구한다. */
    fn commit_inner(
        &mut self,
        duid: &[u8],
        iaid: [u8; 4],
        ip: u128,
        require_offer: bool,
        persist: bool,
    ) -> bool {
        if duid.is_empty() || duid.len() > MAX_DUID_LEN {
            return false;
        }
        let now = crate::unix_now();
        self.cleanup_expired(now);
        if ip < self.start || ip > self.end {
            return false;
        }
        let own_ip = self.leases.get(duid, iaid).map(|value| value.ip);
        let offered_ip = self
            .offers
            .get(duid, iaid)
            .filter(|value| value.expiry > now)
            .map(|value| value.ip);
        if require_offer && offered_ip != Some(ip) && own_ip != Some(ip) {
            return false;
        }
        if self.used.contains(&ip) && own_ip != Some(ip) && offered_ip != Some(ip) {
            return false;
        }
        if own_ip.is_none() && offered_ip.is_none() && self.dynamic_entries() >= MAX_LEASES {
            return false;
        }
        let exp = lease_expiry(now, self.lease_secs);
        if offered_ip.is_some() {
            if let Some(offer) = self.offers.remove(duid, iaid) {
                self.used.remove(&offer.ip);
            }
        }
        if let Some(old) = self.leases.insert(duid, IaValue::new(ip, exp, iaid)) {
            if old.ip != ip {
                self.used.remove(&old.ip);
            }
        }
        self.used.insert(ip);
        self.next_expiry = self.next_expiry.min(exp);
        if persist {
            self.save();
        }
        true
    }

    /** @brief 테스트·복원 경로에서 주소를 직접 확정한다. */
    #[cfg(test)]
    pub fn commit(&mut self, duid: &[u8], iaid: [u8; 4], ip: u128) -> bool {
        self.commit_inner(duid, iaid, ip, false, true)
    }

    /** @brief 그 IA에 광고했던 정확한 주소만 확정한다. */
    fn commit_offer(&mut self, duid: &[u8], iaid: [u8; 4], ip: u128) -> bool {
        self.commit_inner(duid, iaid, ip, true, false)
    }

    /** @brief 그 IA의 살아 있는 정확한 주소만 갱신한다. */
    fn renew(&mut self, duid: &[u8], iaid: [u8; 4], ip: u128) -> bool {
        if duid.is_empty() || duid.len() > MAX_DUID_LEN {
            return false;
        }
        let now = crate::unix_now();
        self.cleanup_expired(now);
        let Some(value) = self.leases.get_mut(duid, iaid) else {
            return false;
        };
        if value.ip != ip || value.expiry <= now {
            return false;
        }
        let new_expiry = lease_expiry(now, self.lease_secs);
        value.expiry = new_expiry;
        self.next_expiry = self.next_expiry.min(new_expiry);
        true
    }

    /** @brief 이 IA의 살아 있는 offer 또는 기존 임대 주소. */
    fn offered_address(&self, duid: &[u8], iaid: [u8; 4], now: u64) -> Option<u128> {
        self.offers
            .get(duid, iaid)
            .filter(|value| value.expiry > now)
            .map(|value| value.ip)
            .or_else(|| {
                self.leases
                    .get(duid, iaid)
                    .filter(|value| value.expiry > now)
                    .map(|value| value.ip)
            })
    }

    /** @brief 이 IA의 살아 있는 임대 주소. */
    fn leased_address(&self, duid: &[u8], iaid: [u8; 4], now: u64) -> Option<u128> {
        self.leases
            .get(duid, iaid)
            .filter(|value| value.expiry > now)
            .map(|value| value.ip)
    }

    /** @brief 그 IA가 실제로 가진 정확한 주소만 돌려받는다. */
    fn release_address(&mut self, duid: &[u8], iaid: [u8; 4], ip: u128) -> bool {
        if duid.is_empty() || duid.len() > MAX_DUID_LEN {
            return false;
        }
        let now = crate::unix_now();
        if !self
            .leases
            .get(duid, iaid)
            .is_some_and(|value| value.ip == ip && value.expiry > now)
        {
            return false;
        }
        let Some(released) = self.leases.remove(duid, iaid) else {
            return false;
        };
        self.used.remove(&released.ip);
        if self.leases.is_empty() && self.offers.is_empty() {
            self.leases = IaMap::default();
            self.offers = IaMap::default();
            self.used = HashSet::new();
        } else {
            self.leases.release_excess_capacity();
            if self.used.capacity() > self.used.len().saturating_mul(4).max(16) {
                self.used.shrink_to(self.used.len().saturating_mul(2));
            }
        }
        true
    }

    /** @brief 살아 있는 임대 수. */
    pub fn active(&self) -> usize {
        let now = crate::unix_now();
        self.leases
            .values()
            .filter(|value| value.expiry > now)
            .count()
    }

    /** @brief 살아 있는 임대 목록. 대시보드가 쓴다. */
    pub fn snapshot(&self) -> Vec<Lease6Info> {
        let now = crate::unix_now();
        let mut out: Vec<Lease6Info> = self
            .leases
            .entries()
            .filter(|(_, value)| value.expiry > now)
            .map(|(duid, value)| Lease6Info {
                duid: duid.to_vec(),
                iaid: value.iaid,
                ip: Ipv6Addr::from(value.ip),
                expiry_unix: value.expiry,
            })
            .collect();
        out.sort_by_key(|i| u128::from(i.ip));
        out
    }

    /** @brief 기록을 원자적으로 교체해 저장한다. 만료된 것은 빼고 적는다. */
    fn save(&self) {
        let Some(path) = &self.persist else { return };
        let now = crate::unix_now();
        let mut text = String::from(LEASE_HEADER);
        for (duid, value) in self
            .leases
            .entries()
            .filter(|(_, value)| value.expiry > now)
        {
            text.push_str(&format!(
                "{} {} {} {}\n",
                hex_bytes(duid),
                hex_bytes(&value.iaid),
                Ipv6Addr::from(value.ip),
                value.expiry
            ));
        }
        if let Err(e) = crate::atomic_file::atomic_write(path, text.as_bytes()) {
            onetdns_core::warn!(event = "dhcp6.lease_save_failed", path = ?path, error = %e, "Could not save DHCPv6 leases to file");
        }
    }
}

/** @brief 바이트열을 16진 문자열로. */
fn hex_bytes(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/** @brief 16진 문자열을 바이트열로. */
fn bytes_from_hex(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

/**
 * @brief 저장된 임대를 읽는다.
 * @warning 한 줄이라도 형식이 어긋나면 전체를 버린다. 반쯤 읽어 들이면 어떤 주소가
 *          이미 나갔는지 알 수 없어 같은 주소를 둘에게 준다.
 */
fn load_leases6(path: &std::path::Path) -> IaMap {
    let mut out = IaMap::default();
    let mut seen_ips = HashSet::new();
    let Some(text) = read_persist_text(path) else {
        return out;
    };
    let Some(text) = text.strip_prefix(LEASE_HEADER) else {
        onetdns_core::warn!(event = "dhcp6.leases_restore_invalid", path = %path.display(), "DHCPv6 lease file does not match the current format; starting empty");
        return out;
    };
    let now = crate::unix_now();
    let mut malformed = 0u64;
    for line in text.lines() {
        if out.len() >= MAX_LEASES {
            malformed = malformed.saturating_add(1);
            continue;
        }
        let mut toks = line.split_whitespace();
        let (Some(duid_s), Some(iaid_s), Some(ip_s), Some(exp_s)) =
            (toks.next(), toks.next(), toks.next(), toks.next())
        else {
            malformed = malformed.saturating_add(1);
            continue;
        };
        let (Some(duid), Ok(iaid), Ok(ip), Ok(expiry)) = (
            bytes_from_hex(duid_s),
            u32::from_str_radix(iaid_s, 16).map(u32::to_be_bytes),
            ip_s.parse::<Ipv6Addr>(),
            exp_s.parse::<u64>(),
        ) else {
            malformed = malformed.saturating_add(1);
            continue;
        };
        if !valid_duid(&duid) || iaid_s.len() != 8 {
            malformed = malformed.saturating_add(1);
            continue;
        }
        if toks.next().is_some() {
            malformed = malformed.saturating_add(1);
            continue;
        }
        if expiry <= now {
            continue;
        }
        let ip = u128::from(ip);
        if out.get(&duid, iaid).is_some() || !seen_ips.insert(ip) {
            malformed = malformed.saturating_add(1);
            continue;
        }
        let previous = out.insert(&duid, IaValue::new(ip, expiry, iaid));
        debug_assert!(previous.is_none());
    }
    if malformed > 0 {
        onetdns_core::warn!(
            event = "dhcp6.leases_restore_invalid",
            path = %path.display(),
            malformed,
            "DHCPv6 lease file is corrupted; starting empty"
        );
        return IaMap::default();
    }
    out
}

/** @brief 이 응답이 표준 UDP payload 안에 들어갈 때 처리 가능한 IA 수. */
fn response_ia_capacity(
    client_id_len: usize,
    cfg: &Dhcp6Config,
    request_type: u8,
) -> Option<usize> {
    if !valid_duid(&cfg.server_duid) {
        return None;
    }
    let mut fixed = 4usize;
    fixed = fixed.checked_add(4usize.checked_add(client_id_len)?)?;
    fixed = fixed.checked_add(4usize.checked_add(cfg.server_duid.len())?)?;
    if request_type == RELEASE {
        fixed = fixed.checked_add(4 + 2)?;
    } else if !cfg.dns.is_empty() {
        let dns_bytes = cfg.dns.len().checked_mul(16)?;
        if dns_bytes > usize::from(u16::MAX) {
            return None;
        }
        fixed = fixed.checked_add(4usize.checked_add(dns_bytes)?)?;
    }
    let remaining = MAX_STANDARD_IPV6_UDP_PAYLOAD.checked_sub(fixed)?;
    Some(remaining / IA_NA_ADDRESS_RESPONSE_WIRE_LEN)
}

/** @brief 모든 IA_NA를 한 번씩 검증하고 한 메시지 안의 IAID 중복을 거부한다. */
fn validate_ia_nas(req: &Dhcp6Message, max_count: usize) -> Option<usize> {
    let mut count = 0usize;
    let mut first_iaid = None;
    let mut seen = None::<HashSet<[u8; 4]>>;
    for (code, data) in &req.options {
        if *code != OPT_IA_NA {
            continue;
        }
        let ia = parse_ia_na(data)?;
        count = count.checked_add(1)?;
        if count > max_count {
            return None;
        }
        match (first_iaid, seen.as_mut()) {
            (None, _) => first_iaid = Some(ia.iaid),
            (Some(first), None) => {
                if first == ia.iaid {
                    return None;
                }
                let mut ids = HashSet::with_capacity(8);
                ids.insert(first);
                ids.insert(ia.iaid);
                seen = Some(ids);
            }
            (Some(_), Some(ids)) => {
                if !ids.insert(ia.iaid) {
                    return None;
                }
            }
        }
    }
    (count > 0).then_some(count)
}

/**
 * @brief 요청 하나를 처리해 응답을 만든다.
 * @warning 확정을 요구하는 요청은 서버 식별자가 이 서버의 것과 같아야 한다. 확인하지 않으면
 *          다른 서버에 보낸 요청에 이 서버가 끼어든다.
 */
pub fn handle(
    req: &Dhcp6Message,
    pool: &mut Lease6Pool,
    cfg: &Dhcp6Config,
) -> Option<Dhcp6Message> {
    if req.msg_type == INFORMATION_REQUEST {
        return information_reply(req, cfg);
    }
    let client_id = req.option(OPT_CLIENT_ID)?;
    if !valid_duid(client_id) {
        return None;
    }
    match req.msg_type {
        SOLICIT if req.options.iter().any(|(code, _)| *code == OPT_SERVER_ID) => return None,
        SOLICIT => {}
        REQUEST | RENEW | RELEASE if req.option(OPT_SERVER_ID) == Some(&cfg.server_duid) => {}
        REQUEST | RENEW | RELEASE => return None,
        _ => return None,
    }
    let max_ias = response_ia_capacity(client_id.len(), cfg, req.msg_type)?;
    let ia_count = validate_ia_nas(req, max_ias)?;
    let response_type = if req.msg_type == SOLICIT {
        ADVERTISE
    } else {
        REPLY
    };
    let mut options = Vec::with_capacity(2 + ia_count + usize::from(!cfg.dns.is_empty()));
    options.push((OPT_CLIENT_ID, client_id.to_vec()));
    options.push((OPT_SERVER_ID, cfg.server_duid.clone()));
    let lease = cfg.lease_secs;
    let (t1, t2) = renewal_timers(lease);
    let now = crate::unix_now();
    let mut changed = false;

    for (_, data) in req.options.iter().filter(|(code, _)| *code == OPT_IA_NA) {
        let ia = parse_ia_na(data)?;
        let response_ia = match req.msg_type {
            SOLICIT => {
                let Some(ip) = pool.allocate(client_id, ia.iaid) else {
                    options.push(ia_na_status_option(ia.iaid, STATUS_NO_ADDRS_AVAIL));
                    continue;
                };
                if !pool.hold_offer(client_id, ia.iaid, ip) {
                    options.push(ia_na_status_option(ia.iaid, STATUS_NO_ADDRS_AVAIL));
                    continue;
                }
                ia_na_option(ia.iaid, t1, t2, Ipv6Addr::from(ip), lease)
            }
            REQUEST => {
                let Some(offered) = pool.offered_address(client_id, ia.iaid, now) else {
                    options.push(ia_na_status_option(ia.iaid, STATUS_NO_BINDING));
                    continue;
                };
                if !ia.contains_address(offered) || !pool.commit_offer(client_id, ia.iaid, offered)
                {
                    options.push(ia_na_status_option(ia.iaid, STATUS_NO_BINDING));
                    continue;
                }
                changed = true;
                ia_na_option(ia.iaid, t1, t2, Ipv6Addr::from(offered), lease)
            }
            RENEW => {
                let Some(leased) = pool.leased_address(client_id, ia.iaid, now) else {
                    options.push(ia_na_status_option(ia.iaid, STATUS_NO_BINDING));
                    continue;
                };
                if !ia.contains_address(leased) || !pool.renew(client_id, ia.iaid, leased) {
                    options.push(ia_na_status_option(ia.iaid, STATUS_NO_BINDING));
                    continue;
                }
                changed = true;
                ia_na_option(ia.iaid, t1, t2, Ipv6Addr::from(leased), lease)
            }
            RELEASE => {
                let Some(leased) = pool.leased_address(client_id, ia.iaid, now) else {
                    options.push(ia_na_status_option(ia.iaid, STATUS_NO_BINDING));
                    continue;
                };
                if !ia.contains_address(leased) || !pool.release_address(client_id, ia.iaid, leased)
                {
                    options.push(ia_na_status_option(ia.iaid, STATUS_NO_BINDING));
                    continue;
                }
                changed = true;
                continue;
            }
            _ => return None,
        };
        options.push(response_ia);
    }
    if changed {
        pool.save();
    }
    if req.msg_type == RELEASE {
        options.push(status_option(STATUS_SUCCESS));
    } else if !cfg.dns.is_empty() {
        let dns: Vec<u8> = cfg.dns.iter().flat_map(|d| d.octets()).collect();
        options.push((OPT_DNS_SERVERS, dns));
    }
    Some(Dhcp6Message {
        msg_type: response_type,
        txid: req.txid,
        options,
    })
}

/**
 * @brief 주소 없이 설정만 묻는 요청에 답한다.
 * @details 라우터 광고의 O 플래그를 본 기기는 DNS 서버를 이 요청으로만 묻는다. RFC 8415에
 *          따라 IA 옵션이 있거나 다른 서버를 지목한 요청은 버린다.
 */
fn information_reply(req: &Dhcp6Message, cfg: &Dhcp6Config) -> Option<Dhcp6Message> {
    if req
        .options
        .iter()
        .any(|(code, _)| matches!(*code, OPT_IA_NA | OPT_IA_TA | OPT_IA_PD))
    {
        return None;
    }
    if req
        .option(OPT_SERVER_ID)
        .is_some_and(|server| server != cfg.server_duid.as_slice())
    {
        return None;
    }
    let mut options = Vec::with_capacity(3);
    if let Some(client_id) = req.option(OPT_CLIENT_ID) {
        if !valid_duid(client_id) {
            return None;
        }
        options.push((OPT_CLIENT_ID, client_id.to_vec()));
    }
    options.push((OPT_SERVER_ID, cfg.server_duid.clone()));
    if !cfg.dns.is_empty() {
        options.push((
            OPT_DNS_SERVERS,
            cfg.dns.iter().flat_map(|d| d.octets()).collect(),
        ));
    }
    Some(Dhcp6Message {
        msg_type: REPLY,
        txid: req.txid,
        options,
    })
}

/** @brief 서버 식별자. 하드웨어 주소를 시드로 만든다. */
pub fn make_server_duid(seed: &[u8; 6]) -> Vec<u8> {
    let mut d = Vec::with_capacity(10);
    d.extend_from_slice(&3u16.to_be_bytes());
    d.extend_from_slice(&1u16.to_be_bytes());
    d.extend_from_slice(seed);
    d
}

/** @brief 선택한 링크의 직접 DHCPv6 client multicast 그룹에 가입한다. */
fn join_dhcp6_multicast_with<F>(interface_index: u32, mut join: F) -> std::io::Result<()>
where
    F: FnMut(&Ipv6Addr, u32) -> std::io::Result<()>,
{
    join(&DHCP6_CLIENT_MULTICAST, interface_index)
}

/** @brief 직접 client 응답은 source port와 무관하게 UDP 546으로 돌려보낸다. */
fn direct_client_destination(mut peer: SocketAddr) -> SocketAddr {
    peer.set_port(546);
    peer
}

/** @brief DHCPv6 서버를 시작한다. */
pub fn spawn_dhcp6(
    cfg: Dhcp6Config,
    port: u16,
    pool: std::sync::Arc<std::sync::Mutex<Lease6Pool>>,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    use onetdns_core::MutexExt;
    use std::sync::atomic::Ordering;
    let sock = onetdns_core::udp::bind((Ipv6Addr::UNSPECIFIED, port))?;
    join_dhcp6_multicast_with(cfg.interface_index, |group, interface| {
        sock.join_multicast_v6(group, interface)
    })?;
    onetdns_core::info!(
        event = "dhcp6.multicast_joined",
        group = %DHCP6_CLIENT_MULTICAST,
        interface = cfg.interface_index,
        "Joined the DHCPv6 client multicast group"
    );
    let wait = onetdns_core::udp::RecvWait::new(Duration::from_millis(500));
    wait.install(&sock)?;
    std::thread::Builder::new()
        .name("dhcp6".into())
        .spawn(move || {
            let mut buf = vec![0u8; DHCP6_RECV_CAPACITY];
            while !shutdown.load(Ordering::Relaxed) {
                let (n, peer) = match wait.recv_from(&sock, &mut buf) {
                    Ok(x) => x,
                    Err(error) => {
                        if !matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) {
                            onetdns_core::warn!(event = "dhcp6.recv_failed", %error, "Failed to receive a DHCPv6 request");
                        }
                        continue;
                    }
                };
                let Some(n) = standard_dhcp6_datagram_len(n) else {
                    continue;
                };
                let Some(req) = Dhcp6Message::parse(&buf[..n]) else {
                    continue;
                };
                let reply = handle(&req, &mut pool.lock_recover(), &cfg);
                if let Some(reply) = reply {
                    let issued = matches!(req.msg_type, REQUEST | RENEW)
                        && reply.options.iter().any(|(code, data)| {
                            *code == OPT_IA_NA
                                && parse_ia_na(data)
                                    .is_some_and(|ia| ia.first_address().is_some())
                        });
                    if issued {
                        onetdns_core::info!(
                            event = "dhcp6.lease_issued",
                            active = pool.lock_recover().active(),
                            "Issued a DHCPv6 lease"
                        );
                    }
                    let destination = direct_client_destination(peer);
                    if let Err(error) = sock.send_to(&reply.encode(), destination) {
                        onetdns_core::warn!(event = "dhcp6.send_failed", peer = %destination, %error, "Failed to send a DHCPv6 reply; the device will not get an address");
                    }
                }
            }
        })
}

#[cfg(test)]
/** @brief 인코딩 왕복, 어긋난 옵션 거부, 배분과 저장. */
mod tests {
    use super::*;

    /** @brief RFC상 무시할 작은 옵션을 최대 데이터그램 가까이 채운 요청. */
    fn unknown_option_flood_wire(count: usize) -> Vec<u8> {
        let mut wire = solicit(b"unknown-flood", [0, 0, 0, 1]).encode();
        for _ in 0..count {
            wire.extend_from_slice(&65_000u16.to_be_bytes());
            wire.extend_from_slice(&0u16.to_be_bytes());
        }
        assert!(wire.len() <= MAX_STANDARD_IPV6_UDP_PAYLOAD);
        wire
    }

    /** @brief singleton 식별자를 되풀이해 표준 데이터그램을 채운 공격 입력. */
    fn singleton_identifier_flood_wire(code: u16, count: usize) -> Vec<u8> {
        let mut wire = solicit(b"singleton-flood", [0, 0, 0, 1]).encode();
        for _ in 0..count {
            wire.extend_from_slice(&code.to_be_bytes());
            wire.extend_from_slice(&3u16.to_be_bytes());
            wire.extend_from_slice(&[0, 1, 2]);
        }
        assert!(wire.len() <= MAX_STANDARD_IPV6_UDP_PAYLOAD);
        wire
    }

    /** @brief 큰 임대 기록 테스트에서 겹치지 않는 DUID를 만든다. */
    fn duid_for(index: usize) -> Vec<u8> {
        (index as u64).to_be_bytes().to_vec()
    }

    /** @brief 테스트가 직접 상태를 채울 때도 실제 두 단계 키 계약을 사용한다. */
    fn insert_test_binding(map: &mut IaMap, duid: &[u8], iaid: [u8; 4], ip: u128, expiry: u64) {
        assert!(map.insert(duid, IaValue::new(ip, expiry, iaid)).is_none());
    }

    #[test]
    /** @brief IAID가 종전 주소·만료 값의 정렬 여백 안에 들어가는지. */
    fn ia_value_uses_existing_alignment_padding() {
        assert_eq!(
            std::mem::size_of::<IaValue>(),
            std::mem::size_of::<(u128, u64)>()
        );
    }

    /** @brief 테스트용 설정. */
    fn cfg() -> Dhcp6Config {
        Dhcp6Config {
            server_duid: make_server_duid(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            range_start: "2001:db8::100".parse().unwrap(),
            range_end: "2001:db8::102".parse().unwrap(),
            dns: vec!["2001:db8::1".parse().unwrap()],
            interface_index: 0,
            lease_secs: 3600,
            lease_file: None,
        }
    }

    /** @brief 테스트용 탐색 요청. */
    fn solicit(duid: &[u8], iaid: [u8; 4]) -> Dhcp6Message {
        let mut ia = Vec::new();
        ia.extend_from_slice(&iaid);
        ia.extend_from_slice(&[0u8; 8]);
        Dhcp6Message {
            msg_type: SOLICIT,
            txid: [1, 2, 3],
            options: vec![(OPT_CLIENT_ID, duid.to_vec()), (OPT_IA_NA, ia)],
        }
    }

    /** @brief 검증된 IA_NA에서 첫 Status Code를 읽는다. */
    fn ia_status(ia_na: &[u8]) -> Option<u16> {
        let parsed = parse_ia_na(ia_na)?;
        let mut options = parsed.options;
        while !options.is_empty() {
            let code = u16::from_be_bytes([options[0], options[1]]);
            let len = u16::from_be_bytes([options[2], options[3]]) as usize;
            let end = 4 + len;
            if code == OPT_STATUS_CODE && len >= 2 {
                return Some(u16::from_be_bytes([options[4], options[5]]));
            }
            options = &options[end..];
        }
        None
    }

    /** @brief 응답의 IAID와 할당 주소를 요청 순서대로 읽는다. */
    fn assigned_ias(message: &Dhcp6Message) -> Vec<([u8; 4], Ipv6Addr)> {
        message
            .options
            .iter()
            .filter(|(code, _)| *code == OPT_IA_NA)
            .filter_map(|(_, data)| {
                let ia = parse_ia_na(data)?;
                Some((ia.iaid, Ipv6Addr::from(ia.first_address()?)))
            })
            .collect()
    }

    /** @brief 서버 IA_NA의 T1·T2·preferred·valid 수명을 읽는다. */
    fn ia_lifetimes(message: &Dhcp6Message) -> (u32, u32, u32, u32) {
        let ia = message.option(OPT_IA_NA).expect("IA_NA 응답");
        assert!(ia.len() >= 40);
        (
            u32::from_be_bytes(ia[4..8].try_into().unwrap()),
            u32::from_be_bytes(ia[8..12].try_into().unwrap()),
            u32::from_be_bytes(ia[32..36].try_into().unwrap()),
            u32::from_be_bytes(ia[36..40].try_into().unwrap()),
        )
    }

    #[test]
    /** @brief 인코딩하고 되읽으면 같은지. */
    fn wire_roundtrip() {
        let m = solicit(b"client-duid", [9, 9, 9, 9]);
        let back = Dhcp6Message::parse(&m.encode()).unwrap();
        assert_eq!(back.msg_type, SOLICIT);
        assert_eq!(back.txid, [1, 2, 3]);
        assert_eq!(back.option(OPT_CLIENT_ID), Some(b"client-duid".as_slice()));
    }

    #[test]
    /** @brief 큰 사용자 임대 수명도 T2 계산에서 포화되거나 infinity 의미를 잃지 않는지. */
    fn large_lease_lifetime_keeps_rfc_renewal_timers() {
        for lease in [u32::MAX - 1, u32::MAX] {
            let mut c = cfg();
            c.lease_secs = lease;
            let reply = handle(
                &solicit(b"large-lifetime", lease.to_be_bytes()),
                &mut Lease6Pool::new(&c),
                &c,
            )
            .unwrap();
            let (t1, t2, preferred, valid) = ia_lifetimes(&reply);
            let expected = if lease == u32::MAX {
                (u32::MAX, u32::MAX)
            } else {
                (lease / 2, (u64::from(lease) * 4 / 5) as u32)
            };

            assert_eq!((t1, t2), expected);
            assert_eq!((preferred, valid), (lease, lease));
            assert!(t1 <= t2 && t2 <= valid);
        }
        assert_eq!(lease_expiry(123, u32::MAX), u64::MAX);
        assert_eq!(
            lease_expiry(123, u32::MAX - 1),
            123 + u64::from(u32::MAX - 1)
        );
    }

    #[test]
    /** @brief 수신 버퍼 절단이 후행 중복 CLIENT_ID를 숨길 수 없어야 한다. */
    fn receive_capacity_covers_tail_option_validation() {
        let c = cfg();
        let mut request = solicit(b"tail-dup", [0, 0, 0, 1]);
        let prefix_len = request.encode().len();
        let filler_len = 1500usize
            .checked_sub(prefix_len + 4)
            .expect("테스트 prefix가 1500바이트보다 작아야 합니다");
        request.options.push((65_000, vec![0; filler_len]));
        let prefix = request.encode();
        assert_eq!(prefix.len(), 1500);

        let mut full = prefix.clone();
        full.extend_from_slice(&OPT_CLIENT_ID.to_be_bytes());
        full.extend_from_slice(&8u16.to_be_bytes());
        full.extend_from_slice(b"tail-dup");
        assert!(full.len() < MAX_STANDARD_IPV6_UDP_PAYLOAD);

        let truncated = Dhcp6Message::parse(&prefix).unwrap();
        assert!(handle(&truncated, &mut Lease6Pool::new(&c), &c).is_some());
        assert!(Dhcp6Message::parse(&full).is_none());
        let receive_buffer = vec![0u8; DHCP6_RECV_CAPACITY];
        assert!(
            receive_buffer.get(MAX_STANDARD_IPV6_UDP_PAYLOAD).is_some(),
            "작은 recv_from 버퍼는 뒤쪽 중복 식별자를 버리고 앞부분만 실행합니다"
        );
        assert_eq!(
            standard_dhcp6_datagram_len(MAX_STANDARD_IPV6_UDP_PAYLOAD),
            Some(MAX_STANDARD_IPV6_UDP_PAYLOAD)
        );
        assert_eq!(
            standard_dhcp6_datagram_len(MAX_STANDARD_IPV6_UDP_PAYLOAD + 1),
            None
        );
    }

    #[test]
    /** @brief DHCPv6 서버가 선택한 링크의 All_DHCP_Relay_Agents_and_Servers에 가입하는지. */
    fn multicast_join_uses_rfc_group_and_selected_interface() {
        let mut joined = Vec::new();
        join_dhcp6_multicast_with(17, |group, interface| {
            joined.push((*group, interface));
            Ok(())
        })
        .unwrap();

        assert_eq!(joined, vec![("ff02::1:2".parse::<Ipv6Addr>().unwrap(), 17)]);
    }

    #[test]
    /** @brief 임의 허용 source port의 직접 클라이언트에도 546으로 scope를 보존해 답하는지. */
    fn direct_client_reply_uses_port_546_and_preserves_scope() {
        let peer = std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::1234".parse().unwrap(),
            62_000,
            77,
            17,
        ));

        let destination = direct_client_destination(peer);

        let std::net::SocketAddr::V6(destination) = destination else {
            panic!("DHCPv6 client destination must stay IPv6");
        };
        assert_eq!(destination.ip(), &"fe80::1234".parse::<Ipv6Addr>().unwrap());
        assert_eq!(destination.port(), 546);
        assert_eq!(destination.flowinfo(), 77);
        assert_eq!(destination.scope_id(), 17);
    }

    #[test]
    /** @brief 무시할 옵션 flood가 개별 소유 Vec와 옵션 메타데이터로 증폭되지 않는지. */
    fn unknown_option_flood_is_ignored_without_storage_amplification() {
        let c = cfg();
        let wire = unknown_option_flood_wire(16_000);
        let parsed = Dhcp6Message::parse(&wire).unwrap();

        assert_eq!(parsed.options.len(), 2);
        assert!(parsed.options.capacity() <= 4);
        assert!(handle(&parsed, &mut Lease6Pool::new(&c), &c).is_some());
    }

    #[test]
    /** @brief singleton 식별자 flood를 수천 Vec로 소유하기 전에 파서가 끝내는지. */
    fn duplicate_singleton_flood_is_rejected_during_parse() {
        assert!(
            Dhcp6Message::parse(&singleton_identifier_flood_wire(OPT_CLIENT_ID, 8_000)).is_none()
        );
        assert!(
            Dhcp6Message::parse(&singleton_identifier_flood_wire(OPT_SERVER_ID, 8_000)).is_none()
        );
    }

    #[test]
    /** @brief DUID의 2바이트 type과 1..=128바이트 식별자 길이를 wire에서 강제하는지. */
    fn duid_wire_length_is_bounded_before_state_changes() {
        assert!(Dhcp6Message::parse(&solicit(&[0; 2], [0; 4]).encode()).is_none());
        assert!(Dhcp6Message::parse(&solicit(&[0; 3], [0; 4]).encode()).is_some());
        assert!(Dhcp6Message::parse(&solicit(&[0; MAX_DUID_LEN], [0; 4]).encode()).is_some());
        assert!(Dhcp6Message::parse(&solicit(&[0; MAX_DUID_LEN + 1], [0; 4]).encode()).is_none());
    }

    #[test]
    /** @brief 어떤 응답에도 담을 수 없는 IA 개수를 파서 단계에서 bounded 거부하는지. */
    fn impossible_ia_count_is_rejected_during_parse() {
        let absolute_response_capacity =
            (MAX_STANDARD_IPV6_UDP_PAYLOAD - 4) / IA_NA_ADDRESS_RESPONSE_WIRE_LEN;
        let mut wire = vec![SOLICIT, 1, 2, 3];
        for iaid in 0..=absolute_response_capacity as u32 {
            wire.extend_from_slice(&OPT_IA_NA.to_be_bytes());
            wire.extend_from_slice(&12u16.to_be_bytes());
            wire.extend_from_slice(&iaid.to_be_bytes());
            wire.extend_from_slice(&[0; 8]);
        }
        assert!(wire.len() <= MAX_STANDARD_IPV6_UDP_PAYLOAD);

        assert!(Dhcp6Message::parse(&wire).is_none());
    }

    #[test]
    #[ignore = "마이크로벤치: cargo test -p onetdns --release bench_dhcp6_unknown_option_flood_parse -- --ignored --nocapture"]
    /** @brief 작은 unknown option 16,000개의 파싱 비용을 측정한다. */
    fn bench_dhcp6_unknown_option_flood_parse() {
        const OPS: usize = 64;
        const ROUNDS: usize = 6;
        let wire = unknown_option_flood_wire(16_000);

        for round in 0..ROUNDS {
            let started = std::time::Instant::now();
            for _ in 0..OPS {
                let parsed = Dhcp6Message::parse(std::hint::black_box(&wire)).unwrap();
                std::hint::black_box(parsed);
            }
            let ns_per_parse = started.elapsed().as_nanos() / OPS as u128;
            println!(
                "dhcp6_unknown_flood round={} ns_per_parse={ns_per_parse}",
                round + 1
            );
        }
    }

    #[test]
    /** @brief 다중 IA 최악 응답이 UDP 상한을 넘기 전에 요청 전체를 거부하는지. */
    fn multi_ia_response_budget_is_checked_before_state_changes() {
        let mut c = cfg();
        c.range_end = "2001:db8::ffff".parse().unwrap();
        let duid = b"response-budget";
        let capacity = response_ia_capacity(duid.len(), &c, SOLICIT).unwrap();
        let request_with = |count: usize| {
            let mut request = solicit(duid, 0u32.to_be_bytes());
            for iaid in 1..count as u32 {
                let mut ia = Vec::from(iaid.to_be_bytes());
                ia.extend_from_slice(&[0; 8]);
                request.options.push((OPT_IA_NA, ia));
            }
            request
        };

        let mut fitting_pool = Lease6Pool::new(&c);
        let fitting = handle(&request_with(capacity), &mut fitting_pool, &c).unwrap();
        assert!(fitting.encode().len() <= MAX_STANDARD_IPV6_UDP_PAYLOAD);
        assert_eq!(fitting_pool.dynamic_entries(), capacity);

        let mut oversized_pool = Lease6Pool::new(&c);
        assert!(handle(&request_with(capacity + 1), &mut oversized_pool, &c).is_none());
        assert_eq!(oversized_pool.dynamic_entries(), 0);
    }

    #[test]
    #[ignore = "마이크로벤치: cargo test -p onetdns --release bench_dhcp6_many_ia_validation -- --ignored --nocapture"]
    /** @brief 큰 정상 다중 IA 메시지의 검증 비용이 IA 수의 제곱으로 커지는지 측정한다. */
    fn bench_dhcp6_many_ia_validation() {
        const IA_COUNT: usize = 1_024;
        const OPS: usize = 64;
        let mut request = solicit(b"many-ia", 0u32.to_be_bytes());
        for iaid in 1..IA_COUNT as u32 {
            let mut ia = Vec::from(iaid.to_be_bytes());
            ia.extend_from_slice(&[0; 8]);
            request.options.push((OPT_IA_NA, ia));
        }

        let started = std::time::Instant::now();
        for _ in 0..OPS {
            assert_eq!(
                std::hint::black_box(validate_ia_nas(std::hint::black_box(&request), usize::MAX,)),
                Some(IA_COUNT)
            );
        }
        println!(
            "dhcp6_many_ia count={IA_COUNT} ns_per_validation={}",
            started.elapsed().as_nanos() / OPS as u128
        );
    }

    #[test]
    /** @brief 어긋난 옵션이 전체를 거부되는지. 앞부분만 받아들이면 잘린 요청이 통과한다. */
    fn malformed_option_is_rejected_instead_of_partially_applied() {
        let encoded = solicit(b"client-duid", [9, 9, 9, 9]).encode();

        let mut truncated = encoded.clone();
        truncated.pop();
        assert!(Dhcp6Message::parse(&truncated).is_none());

        let mut trailing = encoded;
        trailing.push(0xff);
        assert!(Dhcp6Message::parse(&trailing).is_none());
    }

    #[test]
    /** @brief 탐색에는 알림으로, 요청에는 확정으로 답하는지. */
    fn solicit_advertises_request_replies() {
        let c = cfg();
        let mut pool = Lease6Pool::new(&c);

        let adv = handle(&solicit(b"duid-a", [1, 0, 0, 1]), &mut pool, &c).unwrap();
        assert_eq!(adv.msg_type, ADVERTISE);
        assert_eq!(adv.option(OPT_CLIENT_ID), Some(b"duid-a".as_slice()));
        assert_eq!(adv.option(OPT_SERVER_ID), Some(c.server_duid.as_slice()));

        let ia = adv.option(OPT_IA_NA).unwrap();
        let addr_bytes = &ia[16..32];
        let address = Ipv6Addr::from(<[u8; 16]>::try_from(addr_bytes).unwrap());
        assert_eq!(address, "2001:db8::100".parse::<Ipv6Addr>().unwrap());

        let mut req = solicit(b"duid-a", [1, 0, 0, 1]);
        req.msg_type = REQUEST;
        req.options.retain(|(code, _)| *code != OPT_IA_NA);
        req.options
            .push(ia_na_option([1, 0, 0, 1], 0, 0, address, 3_600));
        req.options.push((OPT_SERVER_ID, c.server_duid.clone()));
        let reply = handle(&req, &mut pool, &c).unwrap();
        assert_eq!(reply.msg_type, REPLY);
        assert_eq!(pool.active(), 1);

        let mut changed = c.clone();
        changed.dns = vec!["2001:db8::53".parse().unwrap()];
        pool.reconfigure(&changed);
        assert_eq!(pool.active(), 1);
        let other = handle(&solicit(b"duid-b", [2, 0, 0, 2]), &mut pool, &changed).unwrap();
        let other_ia = other.option(OPT_IA_NA).unwrap();
        assert_ne!(
            Ipv6Addr::from(<[u8; 16]>::try_from(&other_ia[16..32]).unwrap()),
            address
        );
    }

    #[test]
    /**
     * @brief 주소 없이 설정만 묻는 요청에 DNS 서버를 알려 주는지.
     * @details 라우터 광고의 O 플래그를 본 기기는 이 요청으로만 DNS 서버를 묻는다. IA 옵션이
     *          든 요청과 다른 서버를 지목한 요청은 RFC 8415에 따라 버린다.
     */
    fn information_request_gets_dns_servers() {
        let c = cfg();
        let mut pool = Lease6Pool::new(&c);
        let mut info = Dhcp6Message {
            msg_type: INFORMATION_REQUEST,
            txid: [7, 7, 7],
            options: vec![(OPT_CLIENT_ID, b"stateless".to_vec())],
        };
        let reply = handle(&info, &mut pool, &c).unwrap();
        assert_eq!(reply.msg_type, REPLY);
        assert_eq!(reply.txid, [7, 7, 7]);
        assert_eq!(reply.option(OPT_SERVER_ID), Some(c.server_duid.as_slice()));
        assert_eq!(reply.option(OPT_CLIENT_ID), Some(b"stateless".as_slice()));
        assert_eq!(
            reply.option(OPT_DNS_SERVERS),
            Some(
                "2001:db8::1"
                    .parse::<Ipv6Addr>()
                    .unwrap()
                    .octets()
                    .as_slice()
            )
        );
        assert_eq!(pool.active(), 0);

        let anonymous = Dhcp6Message {
            msg_type: INFORMATION_REQUEST,
            txid: [8, 8, 8],
            options: Vec::new(),
        };
        assert!(handle(&anonymous, &mut pool, &c).is_some());

        info.options.push((OPT_SERVER_ID, b"someone-else".to_vec()));
        assert!(handle(&info, &mut pool, &c).is_none());
        info.options.pop();
        info.options.push((OPT_IA_NA, vec![0; 12]));
        assert!(handle(&info, &mut pool, &c).is_none());
    }

    #[test]
    /** @brief SOLICIT에 광고한 주소를 같은 DUID의 REQUEST에서 그대로 확정하는지. */
    fn request_commits_the_address_advertised_to_each_duid() {
        let mut c = cfg();
        c.range_end = c.range_start;
        let mut pool = Lease6Pool::new(&c);

        let advertised = handle(&solicit(b"duid-a", [1, 0, 0, 1]), &mut pool, &c).unwrap();
        let address = Ipv6Addr::from(
            <[u8; 16]>::try_from(&advertised.option(OPT_IA_NA).unwrap()[16..32]).unwrap(),
        );

        let exhausted = handle(&solicit(b"duid-b", [2, 0, 0, 2]), &mut pool, &c).unwrap();
        assert_eq!(
            ia_status(exhausted.option(OPT_IA_NA).unwrap()),
            Some(STATUS_NO_ADDRS_AVAIL),
            "점유된 주소를 중복 광고하지 말고 명시적으로 고갈을 알려야 합니다"
        );

        let mut request = solicit(b"duid-a", [1, 0, 0, 1]);
        request.msg_type = REQUEST;
        request.options.retain(|(code, _)| *code != OPT_IA_NA);
        request
            .options
            .push(ia_na_option([1, 0, 0, 1], 0, 0, address, 3_600));
        request.options.push((OPT_SERVER_ID, c.server_duid.clone()));
        let reply = handle(&request, &mut pool, &c).unwrap();
        let committed = Ipv6Addr::from(
            <[u8; 16]>::try_from(&reply.option(OPT_IA_NA).unwrap()[16..32]).unwrap(),
        );

        assert_eq!(committed, address);
        assert_eq!(pool.snapshot()[0].ip, address);
    }

    #[test]
    /** @brief REQUEST와 RELEASE의 IAADDR가 실제 offer/lease와 다르면 상태를 바꾸지 않는지. */
    fn request_and_release_require_the_owned_ia_address() {
        let c = cfg();
        let mut pool = Lease6Pool::new(&c);
        let duid = b"duid-owned";
        let advertised = handle(&solicit(duid, [7, 0, 0, 1]), &mut pool, &c).unwrap();
        let address = Ipv6Addr::from(
            <[u8; 16]>::try_from(&advertised.option(OPT_IA_NA).unwrap()[16..32]).unwrap(),
        );
        let wrong = Ipv6Addr::from(u128::from(address) + 1);

        let mut bad_request = solicit(duid, [7, 0, 0, 1]);
        bad_request.msg_type = REQUEST;
        bad_request.options.retain(|(code, _)| *code != OPT_IA_NA);
        bad_request
            .options
            .push(ia_na_option([7, 0, 0, 1], 0, 0, wrong, 3_600));
        bad_request
            .options
            .push((OPT_SERVER_ID, c.server_duid.clone()));
        let bad_request_reply = handle(&bad_request, &mut pool, &c).unwrap();
        assert_eq!(
            ia_status(bad_request_reply.option(OPT_IA_NA).unwrap()),
            Some(STATUS_NO_BINDING)
        );
        assert_eq!(pool.active(), 0);

        let mut good_request = bad_request;
        good_request.options.retain(|(code, _)| *code != OPT_IA_NA);
        good_request
            .options
            .push(ia_na_option([7, 0, 0, 1], 0, 0, address, 3_600));
        assert!(handle(&good_request, &mut pool, &c).is_some());
        assert_eq!(pool.active(), 1);

        let mut bad_renew = good_request.clone();
        bad_renew.msg_type = RENEW;
        bad_renew.options.retain(|(code, _)| *code != OPT_IA_NA);
        bad_renew
            .options
            .push(ia_na_option([7, 0, 0, 1], 0, 0, wrong, 3_600));
        let bad_renew_reply = handle(&bad_renew, &mut pool, &c).unwrap();
        assert_eq!(
            ia_status(bad_renew_reply.option(OPT_IA_NA).unwrap()),
            Some(STATUS_NO_BINDING)
        );
        assert_eq!(pool.active(), 1);

        let mut good_renew = bad_renew;
        good_renew.options.retain(|(code, _)| *code != OPT_IA_NA);
        good_renew
            .options
            .push(ia_na_option([7, 0, 0, 1], 0, 0, address, 3_600));
        assert!(handle(&good_renew, &mut pool, &c).is_some());
        assert_eq!(pool.active(), 1);

        let mut bad_release = good_renew;
        bad_release.msg_type = RELEASE;
        bad_release.options.retain(|(code, _)| *code != OPT_IA_NA);
        bad_release
            .options
            .push(ia_na_option([7, 0, 0, 1], 0, 0, wrong, 0));
        let bad_release_reply = handle(&bad_release, &mut pool, &c).unwrap();
        assert_eq!(
            ia_status(bad_release_reply.option(OPT_IA_NA).unwrap()),
            Some(STATUS_NO_BINDING)
        );
        assert_eq!(pool.active(), 1);

        bad_release.options.retain(|(code, _)| *code != OPT_IA_NA);
        bad_release
            .options
            .push(ia_na_option([7, 0, 0, 1], 0, 0, address, 0));
        let released = handle(&bad_release, &mut pool, &c).unwrap();
        assert_eq!(released.msg_type, REPLY);
        assert_eq!(
            released.option(OPT_STATUS_CODE),
            Some(STATUS_SUCCESS.to_be_bytes().as_slice())
        );
        assert_eq!(pool.active(), 0);
    }

    #[test]
    /** @brief 주소 할당 메시지가 IA_NA 누락·절단·중복을 받아들이지 않는지. */
    fn address_messages_require_one_well_formed_ia_na() {
        let c = cfg();
        let mut truncated_nested = vec![0; 12];
        truncated_nested.extend_from_slice(&OPT_IA_ADDR.to_be_bytes());
        truncated_nested.extend_from_slice(&24u16.to_be_bytes());
        truncated_nested.extend_from_slice(&[0; 8]);
        let (_, mut multiple_address_hints) =
            ia_na_option([0, 0, 0, 1], 0, 0, "2001:db8::100".parse().unwrap(), 3_600);
        multiple_address_hints.extend_from_slice(&ia_addr_option(
            "2001:db8::101".parse().unwrap(),
            3_600,
            3_600,
        ));
        let (_, mut truncated_address_suboption) =
            ia_na_option([0, 0, 0, 1], 0, 0, "2001:db8::100".parse().unwrap(), 3_600);
        truncated_address_suboption[14..16].copy_from_slice(&26u16.to_be_bytes());
        truncated_address_suboption.extend_from_slice(&[0, 1]);
        for options in [
            vec![(OPT_CLIENT_ID, b"missing".to_vec())],
            vec![
                (OPT_CLIENT_ID, b"short".to_vec()),
                (OPT_IA_NA, vec![0, 0, 0, 1]),
            ],
            vec![
                (OPT_CLIENT_ID, b"duplicate".to_vec()),
                (OPT_IA_NA, vec![0; 12]),
                (OPT_IA_NA, vec![0; 12]),
            ],
            vec![
                (OPT_CLIENT_ID, b"truncated-nested".to_vec()),
                (OPT_IA_NA, truncated_nested),
            ],
            vec![
                (OPT_CLIENT_ID, b"truncated-address-child".to_vec()),
                (OPT_IA_NA, truncated_address_suboption),
            ],
            vec![
                (OPT_CLIENT_ID, b"duplicate-client".to_vec()),
                (OPT_CLIENT_ID, b"duplicate-client".to_vec()),
                (OPT_IA_NA, vec![0; 12]),
            ],
        ] {
            let request = Dhcp6Message {
                msg_type: SOLICIT,
                txid: [1, 2, 3],
                options,
            };
            assert!(handle(&request, &mut Lease6Pool::new(&c), &c).is_none());
        }

        let multiple_hints = Dhcp6Message {
            msg_type: SOLICIT,
            txid: [1, 2, 3],
            options: vec![
                (OPT_CLIENT_ID, b"multiple-address-hints".to_vec()),
                (OPT_IA_NA, multiple_address_hints),
            ],
        };
        assert!(handle(&multiple_hints, &mut Lease6Pool::new(&c), &c).is_some());
    }

    #[test]
    /** @brief 중복 SERVER_ID가 정상 offer를 확정하지 못하는지. */
    fn request_requires_one_server_id() {
        let c = cfg();
        let mut pool = Lease6Pool::new(&c);
        let duid = b"duplicate-server";
        let advertised = handle(&solicit(duid, [4, 0, 0, 1]), &mut pool, &c).unwrap();
        let address = Ipv6Addr::from(
            <[u8; 16]>::try_from(&advertised.option(OPT_IA_NA).unwrap()[16..32]).unwrap(),
        );
        let mut request = Dhcp6Message {
            msg_type: REQUEST,
            txid: [1, 2, 3],
            options: vec![
                (OPT_CLIENT_ID, duid.to_vec()),
                ia_na_option([4, 0, 0, 1], 0, 0, address, 3_600),
                (OPT_SERVER_ID, c.server_duid.clone()),
                (OPT_SERVER_ID, c.server_duid.clone()),
            ],
        };

        assert!(handle(&request, &mut pool, &c).is_none());
        assert_eq!(pool.active(), 0);
        request.options.pop();
        assert!(handle(&request, &mut pool, &c).is_some());
        assert_eq!(pool.active(), 1);
    }

    #[test]
    /** @brief 같은 DUID의 서로 다른 IAID가 독립된 IA와 주소를 갖는지. */
    fn same_duid_can_hold_distinct_iaids() {
        let c = cfg();
        let mut pool = Lease6Pool::new(&c);
        let duid = b"multi-interface-client";

        let first = handle(&solicit(duid, [0, 0, 0, 1]), &mut pool, &c).unwrap();
        let second = handle(&solicit(duid, [0, 0, 0, 2]), &mut pool, &c).unwrap();
        let first_address = &first.option(OPT_IA_NA).unwrap()[16..32];
        let second_address = &second.option(OPT_IA_NA).unwrap()[16..32];

        assert_ne!(
            first_address, second_address,
            "DUID만 키로 쓰면 서로 다른 인터페이스의 IA가 같은 offer로 합쳐집니다"
        );
    }

    #[test]
    /** @brief 세 IA의 중간 삭제와 만료 승격 뒤에도 연결과 주소 소유권이 보존되는지. */
    fn additional_ia_links_survive_middle_removal_and_expiry_promotion() {
        let mut c = cfg();
        c.range_end = "2001:db8::110".parse().unwrap();
        let mut pool = Lease6Pool::new(&c);
        let duid = b"three-ia-client";
        let first = u128::from(c.range_start);
        let now = crate::unix_now();
        for (offset, iaid) in [[0, 0, 0, 1], [0, 0, 0, 2], [0, 0, 0, 3]]
            .into_iter()
            .enumerate()
        {
            insert_test_binding(
                &mut pool.leases,
                duid,
                iaid,
                first + offset as u128,
                now + 3_600,
            );
        }
        pool.rebuild_runtime();

        assert!(pool.release_address(duid, [0, 0, 0, 2], first + 1));
        assert!(pool.leases.get(duid, [0, 0, 0, 1]).is_some());
        assert!(pool.leases.get(duid, [0, 0, 0, 2]).is_none());
        assert!(pool.leases.get(duid, [0, 0, 0, 3]).is_some());
        assert!(pool.release_address(duid, [0, 0, 0, 1], first));
        assert_eq!(pool.leases.get(duid, [0, 0, 0, 3]).unwrap().ip, first + 2);

        pool.leases.get_mut(duid, [0, 0, 0, 3]).unwrap().expiry = now;
        insert_test_binding(&mut pool.leases, duid, [0, 0, 0, 4], first + 3, now + 3_600);
        pool.rebuild_runtime();
        pool.cleanup_expired(now);

        assert!(pool.leases.get(duid, [0, 0, 0, 3]).is_none());
        assert_eq!(pool.leases.get(duid, [0, 0, 0, 4]).unwrap().ip, first + 3);
        assert_eq!(pool.active(), 1);
        assert_eq!(pool.used.len(), 1);
    }

    #[test]
    /** @brief 광고 주소를 알아도 다른 IAID로 그 offer를 확정할 수 없는지. */
    fn request_cannot_switch_the_offered_iaid() {
        let c = cfg();
        let mut pool = Lease6Pool::new(&c);
        let duid = b"iaid-switch";
        let advertised = handle(&solicit(duid, [0, 0, 0, 1]), &mut pool, &c).unwrap();
        let address = Ipv6Addr::from(
            <[u8; 16]>::try_from(&advertised.option(OPT_IA_NA).unwrap()[16..32]).unwrap(),
        );
        let request = Dhcp6Message {
            msg_type: REQUEST,
            txid: [1, 2, 3],
            options: vec![
                (OPT_CLIENT_ID, duid.to_vec()),
                ia_na_option([0, 0, 0, 2], 0, 0, address, 0),
                (OPT_SERVER_ID, c.server_duid.clone()),
            ],
        };

        let reply = handle(&request, &mut pool, &c).unwrap();
        assert_eq!(
            ia_status(reply.option(OPT_IA_NA).unwrap()),
            Some(STATUS_NO_BINDING)
        );
        assert_eq!(pool.active(), 0);
    }

    #[test]
    /** @brief 한 메시지의 여러 IA_NA를 각각 광고하는지. */
    fn solicit_handles_multiple_identity_associations() {
        let c = cfg();
        let mut pool = Lease6Pool::new(&c);
        let mut request = solicit(b"multi-ia", [0, 0, 0, 1]);
        request.options.push((OPT_IA_NA, {
            let mut ia = Vec::from([0, 0, 0, 2]);
            ia.extend_from_slice(&[0; 8]);
            ia
        }));

        let advertised = handle(&request, &mut pool, &c).unwrap();
        let ias: Vec<&[u8]> = advertised
            .options
            .iter()
            .filter(|(code, _)| *code == OPT_IA_NA)
            .map(|(_, data)| data.as_slice())
            .collect();
        assert_eq!(ias.len(), 2);
        assert_eq!(&ias[0][..4], &[0, 0, 0, 1]);
        assert_eq!(&ias[1][..4], &[0, 0, 0, 2]);
        assert_ne!(&ias[0][16..32], &ias[1][16..32]);
    }

    #[test]
    /** @brief 여러 IA가 확정·갱신되고 한 IA만 해제되어도 나머지가 유지되는지. */
    fn multiple_identity_associations_have_independent_lifecycles() {
        let c = cfg();
        let mut pool = Lease6Pool::new(&c);
        let duid = b"multi-ia-lifecycle";
        let mut solicit_message = solicit(duid, [0, 0, 0, 1]);
        solicit_message.options.push((OPT_IA_NA, {
            let mut ia = Vec::from([0, 0, 0, 2]);
            ia.extend_from_slice(&[0; 8]);
            ia
        }));
        let advertised = handle(&solicit_message, &mut pool, &c).unwrap();
        let assigned = assigned_ias(&advertised);
        assert_eq!(assigned.len(), 2);

        let address_options = || {
            assigned
                .iter()
                .map(|(iaid, address)| ia_na_option(*iaid, 0, 0, *address, 0))
                .collect::<Vec<_>>()
        };
        let mut request_options = vec![(OPT_CLIENT_ID, duid.to_vec())];
        request_options.extend(address_options());
        request_options.push((OPT_SERVER_ID, c.server_duid.clone()));
        let request = Dhcp6Message {
            msg_type: REQUEST,
            txid: [4, 5, 6],
            options: request_options,
        };
        let reply = handle(&request, &mut pool, &c).unwrap();
        assert_eq!(assigned_ias(&reply), assigned);
        assert_eq!(pool.active(), 2);

        let mut renew = request.clone();
        renew.msg_type = RENEW;
        assert_eq!(
            assigned_ias(&handle(&renew, &mut pool, &c).unwrap()),
            assigned
        );
        assert_eq!(pool.active(), 2);

        let release = Dhcp6Message {
            msg_type: RELEASE,
            txid: [7, 8, 9],
            options: vec![
                (OPT_CLIENT_ID, duid.to_vec()),
                ia_na_option(assigned[0].0, 0, 0, assigned[0].1, 0),
                (OPT_SERVER_ID, c.server_duid.clone()),
            ],
        };
        let released = handle(&release, &mut pool, &c).unwrap();
        assert_eq!(
            released.option(OPT_STATUS_CODE),
            Some(STATUS_SUCCESS.to_be_bytes().as_slice())
        );
        assert_eq!(pool.active(), 1);
        assert_eq!(pool.snapshot()[0].iaid, assigned[1].0);
        assert_eq!(pool.snapshot()[0].ip, assigned[1].1);
    }

    #[test]
    /** @brief SERVER_ID를 담은 SOLICIT를 RFC 9915에 따라 폐기하는지. */
    fn solicit_with_server_id_is_discarded() {
        let c = cfg();
        let mut pool = Lease6Pool::new(&c);
        let mut request = solicit(b"server-id-in-solicit", [0, 0, 0, 1]);
        request.options.push((OPT_SERVER_ID, c.server_duid.clone()));

        assert!(handle(&request, &mut pool, &c).is_none());
        assert_eq!(pool.dynamic_entries(), 0);
    }

    #[test]
    /** @brief 임대와 offer가 상한 하나를 공유하고 만료된 offer 주소를 다시 쓰는지. */
    fn dhcp6_offers_share_the_state_cap_and_expire() {
        let mut c = cfg();
        c.range_start = "2001:db8::10".parse().unwrap();
        c.range_end = "2001:db8::ffff:ffff".parse().unwrap();
        let mut pool = Lease6Pool::new(&c);
        let first = u128::from(c.range_start);
        let now = crate::unix_now();
        let half = MAX_LEASES / 2;
        for index in 0..half {
            insert_test_binding(
                &mut pool.leases,
                &duid_for(index),
                [0; 4],
                first + u128::try_from(index).unwrap(),
                u64::MAX,
            );
        }
        for index in half..MAX_LEASES {
            insert_test_binding(
                &mut pool.offers,
                &duid_for(index),
                [0; 4],
                first + u128::try_from(index).unwrap(),
                u64::MAX,
            );
        }
        pool.rebuild_runtime();
        assert_eq!(pool.dynamic_entries(), MAX_LEASES);
        assert!(pool.allocate(&duid_for(MAX_LEASES), [0; 4]).is_none());

        let mut small = cfg();
        small.range_end = small.range_start;
        let mut small_pool = Lease6Pool::new(&small);
        assert!(handle(&solicit(b"first", [1, 0, 0, 1]), &mut small_pool, &small).is_some());
        small_pool
            .offers
            .get_mut(b"first", [1, 0, 0, 1])
            .unwrap()
            .expiry = now;
        small_pool.next_expiry = now;
        assert!(handle(&solicit(b"second", [2, 0, 0, 2]), &mut small_pool, &small).is_some());
        assert!(small_pool.offers.get(b"first", [1, 0, 0, 1]).is_none());
        assert!(small_pool.offers.get(b"second", [2, 0, 0, 2]).is_some());
    }

    #[test]
    /** @brief 서로 다른 주소를 주고, 다 쓰면 못 준다고 하는지. */
    fn pool_distinct_and_exhaustion() {
        let c = cfg();
        let mut pool = Lease6Pool::new(&c);
        for (i, duid) in [b"a".as_slice(), b"b", b"c"].iter().enumerate() {
            let ip = pool.allocate(duid, [0; 4]).unwrap();
            assert!(pool.commit(duid, [0; 4], ip));
            assert_eq!(
                ip,
                u128::from("2001:db8::100".parse::<Ipv6Addr>().unwrap()) + i as u128
            );
        }
        assert!(pool.allocate(b"d", [0; 4]).is_none());
        assert!(pool.allocate(b"a", [0; 4]).is_some());
    }

    #[test]
    /** @brief 같은 IPv6 주소와 범위 밖 주소를 둘 이상의 DUID에 확정하지 않는지. */
    fn commit_rejects_duplicate_and_out_of_range_ip() {
        let c = cfg();
        let mut pool = Lease6Pool::new(&c);
        let ip = u128::from(c.range_start);
        assert!(pool.commit(b"first", [0; 4], ip));
        assert!(!pool.commit(b"second", [0; 4], ip));
        assert!(!pool.commit(b"outside", [0; 4], ip - 1));

        assert_eq!(pool.active(), 1);
        assert_eq!(pool.snapshot()[0].duid, b"first".to_vec());
    }

    #[test]
    /** @brief 중복 IPv6 주소가 든 저장 파일은 부분 복원하지 않는지. */
    fn persisted_duplicate_ip_rejects_the_whole_dhcp6_file() {
        let path = std::env::temp_dir().join(format!(
            "onetdns-duplicate-lease6-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let expiry = crate::unix_now() + 3_600;
        std::fs::write(
            &path,
            format!(
                "{LEASE_HEADER}0101 00000001 2001:db8::100 {expiry}\n\
                 0202 00000002 2001:db8::100 {expiry}\n"
            ),
        )
        .unwrap();

        assert!(load_leases6(&path).is_empty());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    /** @brief 대량 만료 뒤 임대와 주소 인덱스의 고수위 버킷을 모두 반환하는지. */
    fn dhcp6_expiry_releases_high_water_capacity() {
        let mut c = cfg();
        c.range_start = "2001:db8::10".parse().unwrap();
        c.range_end = "2001:db8::ffff:ffff".parse().unwrap();
        let mut pool = Lease6Pool::new(&c);
        let first = u128::from(c.range_start);
        let now = crate::unix_now();
        for index in 0..20_000 {
            insert_test_binding(
                &mut pool.leases,
                &duid_for(index),
                [0; 4],
                first + u128::try_from(index).unwrap(),
                now,
            );
        }
        pool.rebuild_runtime();
        assert!(pool.used.capacity() >= 20_000);

        pool.cleanup_expired(now);

        assert!(pool.leases.is_empty());
        assert_eq!(pool.leases.capacity(), 0);
        assert!(pool.used.is_empty());
        assert_eq!(pool.used.capacity(), 0);
    }

    #[test]
    #[ignore = "마이크로벤치: cargo test -p onetdns --release bench_dhcp6_new_client_allocation_scaling -- --ignored --nocapture"]
    /** @brief DHCPv6 새 클라이언트 할당 비용이 전체 임대 수에 비례하는지 측정한다. */
    fn bench_dhcp6_new_client_allocation_scaling() {
        const OPS: usize = 256;
        const ROUNDS: usize = 6;

        for preload in [1_000usize, 20_000] {
            for round in 0..ROUNDS {
                let mut c = cfg();
                c.range_start = "2001:db8::10".parse().unwrap();
                c.range_end = "2001:db8::ffff:ffff".parse().unwrap();
                let mut pool = Lease6Pool::new(&c);
                let first = u128::from(c.range_start);
                let expiry = crate::unix_now() + 3_600;
                for index in 0..preload {
                    insert_test_binding(
                        &mut pool.leases,
                        &duid_for(index),
                        [0; 4],
                        first + u128::try_from(index).unwrap(),
                        expiry,
                    );
                }
                pool.rebuild_runtime();

                let started = std::time::Instant::now();
                for index in preload..preload + OPS {
                    let duid = duid_for(index);
                    let ip = std::hint::black_box(pool.allocate(&duid, [0; 4]).unwrap());
                    assert!(pool.commit(&duid, [0; 4], ip));
                }
                let ns_per_op = started.elapsed().as_nanos() / OPS as u128;
                println!(
                    "dhcp6_allocate preload={preload} round={} ns_per_op={ns_per_op}",
                    round + 1
                );
            }
        }
    }

    #[test]
    /** @brief 만료된 임대가 슬롯을 계속 차지하지 않는지. */
    fn allocate_prunes_expired_leases() {
        let c = cfg();
        let mut pool = Lease6Pool::new(&c);
        insert_test_binding(
            &mut pool.leases,
            b"expired",
            [0; 4],
            u128::from(c.range_start),
            crate::unix_now(),
        );
        pool.rebuild_runtime();

        assert!(pool.allocate(b"new-client", [0; 4]).is_some());
        assert!(pool.leases.is_empty());
    }

    #[test]
    /** @brief 저장했다 읽으면 같은 기록이 되는지. */
    fn persistence_roundtrip_and_snapshot() {
        let path =
            std::env::temp_dir().join(format!("onetdns-lease6-persist-{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut c = cfg();
        c.lease_file = Some(path.clone());
        {
            let mut pool = Lease6Pool::new(&c);
            let first = pool.allocate(b"duid-x", [1, 2, 3, 4]).unwrap();
            assert!(pool.commit(b"duid-x", [1, 2, 3, 4], first));
            let second = pool.allocate(b"duid-x", [5, 6, 7, 8]).unwrap();
            assert!(pool.commit(b"duid-x", [5, 6, 7, 8], second));
            let snap = pool.snapshot();
            assert_eq!(snap.len(), 2);
            assert_eq!(snap[0].duid, b"duid-x".to_vec());
            assert_eq!(snap[0].iaid, [1, 2, 3, 4]);
            assert_eq!(snap[0].ip, "2001:db8::100".parse::<Ipv6Addr>().unwrap());
            assert_eq!(snap[1].duid, b"duid-x".to_vec());
            assert_eq!(snap[1].iaid, [5, 6, 7, 8]);
            assert_eq!(snap[1].ip, "2001:db8::101".parse::<Ipv6Addr>().unwrap());
        }

        let pool2 = Lease6Pool::new(&c);
        let snap = pool2.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].duid, b"duid-x".to_vec());
        assert_eq!(snap[0].iaid, [1, 2, 3, 4]);
        assert_eq!(snap[0].ip, "2001:db8::100".parse::<Ipv6Addr>().unwrap());
        assert_eq!(snap[1].duid, b"duid-x".to_vec());
        assert_eq!(snap[1].iaid, [5, 6, 7, 8]);
        assert_eq!(snap[1].ip, "2001:db8::101".parse::<Ipv6Addr>().unwrap());

        std::fs::write(
            &path,
            format!("647569642d78 2001:db8::100 {}\n", crate::unix_now() + 60),
        )
        .unwrap();
        assert!(Lease6Pool::new(&c).snapshot().is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    /** @brief 16진 변환 왕복. */
    fn hex_bytes_roundtrip() {
        assert_eq!(hex_bytes(&[0x00, 0x03, 0xff]), "0003ff");
        assert_eq!(bytes_from_hex("0003ff"), Some(vec![0x00, 0x03, 0xff]));
        assert!(bytes_from_hex("abc").is_none());
        assert!(bytes_from_hex("zz").is_none());
    }

    #[test]
    /** @brief 어떤 바이트열이 와도 파서가 패닉하지 않는지. */
    fn parse_never_panics_on_malformed_bytes() {
        use crate::fuzzutil::{havoc, Rng};

        let seed = solicit(b"client-duid", [9, 9, 9, 9]).encode();
        let mut rng = Rng::new(0x6D0C_F00D_9876_5432);
        for i in 0..20_000u32 {
            let bytes = if i % 3 == 0 {
                rng.rand_bytes(300)
            } else {
                havoc(&mut rng, &seed)
            };
            let _ = Dhcp6Message::parse(&bytes);
        }
    }
}
