/*!
 * @brief DNS 이름: 라벨 저장, 파싱, 압축 인코딩.
 *
 * @details 이름은 String이 아니라 라벨 옥텟을 그대로 담은 와이어 형태로 보관한다.
 *          DNS 라벨은 UTF-8일 의무가 없고, 문자열로 왕복시키면 0xFF 같은 옥텟이 손상되어
 *          서로 다른 이름이 같아 보이게 된다. 대소문자는 비교할 때만 무시한다.
 */

use std::borrow::Cow;
use std::collections::{hash_map::RandomState, HashMap};
use std::hash::{BuildHasher, BuildHasherDefault, Hasher};
use std::sync::{Arc, LazyLock};

use crate::wire::{Reader, Writer};
use crate::ProtoError;

/**
 * @brief 이름 하나를 파싱하며 따라갈 수 있는 압축 포인터 개수.
 *
 * @warning 상한이 없으면 서로를 가리키는 포인터로 무한 루프에 빠진다. 뒤쪽만 가리키게
 *          강제해도 체인 길이 자체는 제한해야 확장 비용이 유계가 된다.
 */
const MAX_JUMPS: usize = 20;

/** @brief RFC 1035가 정한 이름 전체 길이 상한. 길이 옥텟과 루트 라벨을 포함한 값이다. */
const MAX_NAME_LEN: usize = 255;

/**
 * @brief NameMap::clear가 재사용을 위해 남겨 두는 항목 수의 상한.
 *
 * @details 압축 상태는 메시지마다 버려지는데, 병적으로 큰 메시지 하나가 남긴 용량을 그대로
 *          가지고 있으면 그 메모리가 워커 수명 내내 묶인다. 상한을 넘긴 경우에만 전체를 버린다.
 */
const MAX_RETAINED_NAME_ENTRIES: usize = 64;

/** @brief 루트 이름의 공유 와이어. 모든 루트 Name이 이 하나를 가리켜 할당을 없앤다. */
static ROOT_WIRE: LazyLock<Arc<[u8]>> = LazyLock::new(|| Arc::from([0u8]));

/**
 * @brief 이름의 라벨을 앞뒤 양방향으로 훑는 반복자. 복사하지 않는다.
 *
 * @details front/back은 와이어 안의 바이트 오프셋이다. 길이 접두사 구조라 뒤에서
 *          한 칸 뒤로 가려면 앞에서부터 다시 훑어야 한다. next_back이 선형인 이유다.
 * @invariant back은 루트 라벨의 0 옥텟을 제외한 위치를 가리킨다.
 */
#[derive(Debug, Clone, Copy)]
pub struct Labels<'a> {
    /** @brief 이름이 담긴 바이트. */
    wire: &'a [u8],
    /** @brief 앞에서부터 볼 위치. */
    front: usize,
    /** @brief 뒤에서부터 볼 위치. */
    back: usize,
}

impl<'a> Labels<'a> {
    /** @brief 현재 위치를 그대로 복제한 독립 반복자. 원본은 소비되지 않는다. */
    pub fn iter(&self) -> Self {
        *self
    }

    /** @brief 가장 왼쪽 라벨. 와일드카드·단일 라벨 판정에 쓴다. */
    pub fn first(&self) -> Option<&'a [u8]> {
        let mut labels = *self;
        labels.next()
    }

    /**
     * @brief 남은 라벨 개수.
     * @note 저장 구조가 길이 접두사 체인이라 O(라벨 수)로 세어야 한다. 상수 시간이 아니다.
     */
    pub fn len(&self) -> usize {
        let mut count = 0;
        let mut cursor = self.front;
        while cursor < self.back {
            let Some(&len) = self.wire.get(cursor) else {
                break;
            };
            cursor += usize::from(len) + 1;
            count += 1;
        }
        count
    }

    /** @brief 남은 라벨이 없는지. 루트 이름이면 처음부터 참이다. */
    pub fn is_empty(&self) -> bool {
        self.front >= self.back
    }
}

impl<'a> Iterator for Labels<'a> {
    /** @brief 조각 하나. */
    type Item = &'a [u8];

    /** @brief 다음 조각. */
    fn next(&mut self) -> Option<Self::Item> {
        if self.front >= self.back {
            return None;
        }
        let len = usize::from(*self.wire.get(self.front)?);
        let start = self.front + 1;
        let end = start.checked_add(len)?;
        if end > self.back {
            return None;
        }
        let label = self.wire.get(start..end)?;
        self.front = end;
        Some(label)
    }

    /** @brief 남은 조각 수. */
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.back.saturating_sub(self.front) / 2))
    }
}

impl PartialEq for Labels<'_> {
    /** @brief 조각들이 같은지. */
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}

impl Eq for Labels<'_> {}

impl<'a> DoubleEndedIterator for Labels<'a> {
    /** @brief 뒤에서부터 다음 조각. */
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.front >= self.back {
            return None;
        }
        let mut last = self.front;
        let mut cursor = self.front;
        while cursor < self.back {
            last = cursor;
            cursor += usize::from(*self.wire.get(cursor)?) + 1;
        }
        let len = usize::from(*self.wire.get(last)?);
        self.back = last;
        self.wire.get(last + 1..last + 1 + len)
    }
}

/**
 * @brief DNS 이름. 압축을 푼 와이어 형태를 공유 소유로 담는다.
 *
 * @details Arc<[u8]>라 복제가 참조 증가로 끝난다. 이름은 응답 조립과 캐시 키 경로에서
 *          수없이 복제되므로 이 선택이 핫패스 할당을 지운다.
 * @warning 파생된 PartialEq는 대소문자를 구분한다. DNS 비교 의미가 필요하면
 *          eq_ignore_case를 써야 한다. Hash와 Ord도 같은 와이어 바이트를 보므로
 *          해시 맵의 키로 쓰면 대소문자가 다른 이름은 다른 항목이 된다.
 * @invariant wire는 항상 0 옥텟으로 끝나며 전체 길이가 MAX_NAME_LEN 이하다.
 */
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Name {
    /** @brief 이름 바이트. 복제해도 나눠 쓴다. */
    wire: Arc<[u8]>,
}

impl Default for Name {
    /** @brief 루트 이름. */
    fn default() -> Self {
        Self::root()
    }
}

impl Name {
    /** @brief 루트 이름 .. 전역 와이어를 공유하므로 할당하지 않는다. */
    pub fn root() -> Self {
        Self {
            wire: Arc::clone(&ROOT_WIRE),
        }
    }

    /** @brief 루트인지. 와이어가 0 옥텟 하나뿐인 것과 동치다. */
    pub fn is_root(&self) -> bool {
        self.wire.len() == 1
    }

    /** @brief 왼쪽부터 라벨을 훑는 반복자. 끝의 루트 라벨은 포함하지 않는다. */
    pub fn labels(&self) -> Labels<'_> {
        Labels {
            wire: &self.wire,
            front: 0,
            back: self.wire.len().saturating_sub(1),
        }
    }

    /** @brief 라벨 개수. 루트는 0이다. */
    pub fn num_labels(&self) -> usize {
        self.labels().len()
    }

    /**
     * @brief 표현 문자열을 이름으로 바꾼다.
     *
     * @details RFC 1035가 정한 이스케이프를 푼다. 역슬래시 뒤 세 자리 십진수는 그 값의
     *          옥텟 하나이고, 그 밖의 역슬래시 뒤 한 글자는 그 글자의 특별한 뜻을 없앤다.
     *          이스케이프한 점은 라벨 구분자가 아니라 라벨 안의 바이트다.
     * @warning 이것을 풀지 않으면 다른 서버가 쓴 영역 파일의 이름이 조용히 달라진다.
     *          점을 품은 라벨 하나가 라벨 둘이 되고, 십진 이스케이프는 네 글자로 남는다.
     * @param s 점으로 구분된 이름. 끝의 이스케이프하지 않은 . 하나는 루트 표기다.
     * @return 빈 라벨, 63옥텟 초과 라벨, 255옥텟 초과 전체 길이는 전부 거부한다.
     */
    pub fn from_str(s: &str) -> Result<Self, ProtoError> {
        let bytes = s.as_bytes();
        let mut labels: Vec<Vec<u8>> = Vec::new();
        let mut current: Vec<u8> = Vec::new();
        let mut index = 0usize;
        let mut ended_with_separator = false;

        while index < bytes.len() {
            match bytes[index] {
                b'\\' => {
                    let digits = bytes
                        .get(index + 1..index + 4)
                        .filter(|triple| triple.iter().all(|byte| byte.is_ascii_digit()));
                    if let Some(triple) = digits {
                        let value = triple
                            .iter()
                            .fold(0u16, |acc, byte| acc * 10 + u16::from(byte - b'0'));
                        if value > 255 {
                            return Err(ProtoError::Name("Decimal escape exceeds 255".into()));
                        }
                        current.push(value as u8);
                        index += 4;
                    } else if let Some(byte) = bytes.get(index + 1) {
                        current.push(*byte);
                        index += 2;
                    } else {
                        return Err(ProtoError::Name("Unterminated escape".into()));
                    }
                    ended_with_separator = false;
                }
                b'.' => {
                    labels.push(std::mem::take(&mut current));
                    index += 1;
                    ended_with_separator = true;
                }
                byte => {
                    current.push(byte);
                    index += 1;
                    ended_with_separator = false;
                }
            }
        }
        if !ended_with_separator {
            labels.push(current);
        }

        if labels.is_empty() || (labels.len() == 1 && labels[0].is_empty()) {
            return Ok(Self::root());
        }
        if labels.iter().any(Vec::is_empty) {
            return Err(ProtoError::Name("Root label appears more than once".into()));
        }
        Self::from_labels(labels)
    }

    /**
     * @brief 영역 파일에 적을 소문자 표현. 특별한 뜻을 가진 바이트는 이스케이프한다.
     *
     * @details to_ascii_lower는 표시 전용이라 점이나 공백을 품은 라벨을 되돌릴 수 없다.
     *          다시 읽을 문자열은 반드시 이쪽으로 만든다. 그러지 않으면 영역을 파일로
     *          적었다 읽는 것만으로 이름이 달라진다.
     * @return 끝점은 붙이지 않는다. 호출자가 절대 이름 표기를 정한다.
     */
    pub fn to_master_lower(&self) -> String {
        let mut out = String::with_capacity(self.wire.len());
        for (index, label) in self.labels().enumerate() {
            if index != 0 {
                out.push('.');
            }
            for &byte in label {
                match byte {
                    b'.' | b'\\' | b'"' | b'(' | b')' | b';' | b'@' | b'$' => {
                        out.push('\\');
                        out.push(byte as char);
                    }
                    0x21..=0x7e => out.push(byte.to_ascii_lowercase() as char),
                    other => out.push_str(&format!("\\{other:03}")),
                }
            }
        }
        out
    }

    /**
     * @brief 라벨 옥텟을 직접 받아 이름을 만든다. UTF-8이 아니어도 된다.
     * @param labels 왼쪽부터의 라벨. 각 1~63옥텟이어야 한다.
     * @return 길이 규칙을 어기면 오류. 합계 검사는 넘침까지 확인한다.
     */
    pub fn from_labels(labels: Vec<Vec<u8>>) -> Result<Self, ProtoError> {
        let mut total = 1usize;
        for label in &labels {
            if label.is_empty() || label.len() > 63 {
                return Err(ProtoError::Name("Invalid label length".into()));
            }
            total = total
                .checked_add(label.len() + 1)
                .ok_or_else(|| ProtoError::Name("Name too long".into()))?;
        }
        if total > MAX_NAME_LEN {
            return Err(ProtoError::Name("Name too long".into()));
        }
        let mut wire = Vec::with_capacity(total);
        for label in labels {
            wire.push(label.len() as u8);
            wire.extend_from_slice(&label);
        }
        wire.push(0);
        Ok(Self { wire: wire.into() })
    }

    /**
     * @brief 소문자로 바꾼 와이어 형태. 캐시·맵의 키로 쓴다.
     *
     * @details 라벨 길이 접두사를 그대로 남긴다. 점으로 잇지 않는 이유는 a.b+c와
     *          a+b.c가 같은 키가 되어 서로 다른 이름이 충돌하기 때문이다.
     * @note 할당한다. 핫패스에서는 canonical_key_into를 쓴다.
     */
    pub fn canonical_key(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.wire.len());
        for label in self.labels() {
            out.push(label.len() as u8);
            out.extend(label.iter().map(u8::to_ascii_lowercase));
        }
        out.push(0);
        out
    }

    /**
     * @brief 정규화 키를 호출자 버퍼에 쓴다. 할당하지 않는다.
     * @param out 최소 이름 길이만큼의 버퍼. 통상 [u8; 255] 스택 배열을 넘긴다.
     * @return 실제로 쓴 구간, 버퍼가 모자라면 None.
     */
    pub fn canonical_key_into<'a>(&self, out: &'a mut [u8]) -> Option<&'a [u8]> {
        self.write_canonical_from(0, out)
    }

    /**
     * @brief 오른쪽 label_count개 라벨만의 정규화 키를 버퍼에 쓴다.
     *
     * @details 접미사 이름을 따로 만들지 않고 조상 zone 키를 얻는 경로다. QNAME 최소화와
     *          zone 선택이 이름 하나에서 여러 접미사를 훑을 때 쓴다.
     * @param label_count 남길 라벨 수. 실제 개수보다 크면 이름 전체가 된다.
     */
    pub fn canonical_suffix_key_into<'a>(
        &self,
        label_count: usize,
        out: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        let total = self.num_labels();
        let skip = total.saturating_sub(label_count.min(total));
        let mut start = 0;
        for _ in 0..skip {
            start += usize::from(*self.wire.get(start)?) + 1;
        }
        self.write_canonical_from(start, out)
    }

    /**
     * @brief 와이어 오프셋 start부터의 소문자 키를 버퍼에 쓰는 공통 구현.
     * @param start 라벨 경계여야 한다. 중간을 가리키면 결과가 깨진 이름이 된다.
     */
    fn write_canonical_from<'a>(&self, start: usize, out: &'a mut [u8]) -> Option<&'a [u8]> {
        let needed = self.wire.len().checked_sub(start)?;
        if needed > out.len() {
            return None;
        }
        let mut offset = 0;
        let labels = Labels {
            wire: &self.wire,
            front: start,
            back: self.wire.len().checked_sub(1)?,
        };
        for label in labels {
            out[offset] = label.len() as u8;
            offset += 1;
            for &byte in label {
                out[offset] = byte.to_ascii_lowercase();
                offset += 1;
            }
        }
        out[offset] = 0;
        Some(&out[..needed])
    }

    /**
     * @brief 소문자 점 표기 문자열. 끝점은 붙이지 않는다.
     * @warning UTF-8이 아닌 라벨은 손실 변환되어 대체 문자가 된다. 표시·로그 전용이며
     *          이 결과를 다시 이름으로 되돌리면 안 된다.
     */
    pub fn to_ascii_lower(&self) -> String {
        let mut out = String::with_capacity(self.wire.len().saturating_sub(1));
        for (index, label) in self.labels().enumerate() {
            if index != 0 {
                out.push('.');
            }
            out.push_str(&String::from_utf8_lossy(label).to_ascii_lowercase());
        }
        out
    }

    /**
     * @brief 소문자로 내린 이름.
     *
     * @details 파생된 PartialEq와 Hash는 대소문자를 구분하므로, 이름을 해시 맵의 키로
     *          모을 때 이것으로 바꿔야 같은 이름이 갈라지지 않는다.
     * @return 이미 소문자면 자기 자신을 빌려 준다. 참조계수조차 건드리지 않으려는 것이다.
     *         집계 경로는 이름이 이미 있으면 복제 없이 계수만 올린다.
     * @invariant 압축을 푼 와이어의 길이 옥텟은 1..=63이고 끝은 0이라, ASCII 대문자 범위
     *            (65..=90)와 겹치지 않는다. 그래서 와이어 전체를 훑고 내려도 안전하다.
     */
    pub fn to_ascii_lower_name(&self) -> Cow<'_, Name> {
        if !self.wire.iter().any(|byte| byte.is_ascii_uppercase()) {
            return Cow::Borrowed(self);
        }
        let lowered: Vec<u8> = self.wire.iter().map(|b| b.to_ascii_lowercase()).collect();
        Cow::Owned(Self {
            wire: Arc::from(lowered),
        })
    }

    /**
     * @brief 오른쪽 n개 라벨로 이루어진 조상 이름.
     * @param n 남길 라벨 수. 실제보다 크면 자기 자신의 복사본이 나온다.
     */
    pub fn suffix(&self, n: usize) -> Name {
        let total = self.num_labels();
        let mut skip = total.saturating_sub(n.min(total));
        let mut start = 0;
        while skip != 0 {
            start += usize::from(self.wire[start]) + 1;
            skip -= 1;
        }
        Name {
            wire: Arc::from(&self.wire[start..]),
        }
    }

    /** @brief DNS 의미의 이름 비교. 라벨 옥텟을 ASCII 대소문자 무시로 비교한다. */
    pub fn eq_ignore_case(&self, other: &Name) -> bool {
        self.wire.eq_ignore_ascii_case(&other.wire)
    }

    /**
     * @brief suffix가 이 이름의 조상인지(자기 자신 포함).
     * @note 라벨 경계에서만 맞춘다. x.test는 test의 자손이지만 attest는 아니다.
     *       bailiwick 판정과 zone 소속 판정이 이 성질에 기댄다.
     */
    pub fn ends_with_ignore_case(&self, suffix: &Name) -> bool {
        let own_labels = self.num_labels();
        let suffix_labels = suffix.num_labels();
        if own_labels < suffix_labels {
            return false;
        }
        let mut start = 0;
        for _ in 0..own_labels - suffix_labels {
            start += usize::from(self.wire[start]) + 1;
        }
        self.wire[start..].eq_ignore_ascii_case(&suffix.wire)
    }

    /**
     * @brief 압축 없는 와이어 바이트를 검사해 이름으로 받아들인다.
     *
     * @details 라벨 체인이 정확히 슬라이스 끝에서 0 옥텟으로 끝나야 한다. 잔여 바이트나
     *          압축 포인터가 있으면 거부한다. 저장 형식에서 읽은 이름은 메시지 문맥이
     *          없어 포인터를 풀 방법이 없기 때문이다.
     */
    pub fn from_uncompressed_wire(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() || bytes.len() > MAX_NAME_LEN {
            return None;
        }
        let mut pos = 0usize;
        loop {
            let len = *bytes.get(pos)? as usize;
            if len == 0 {
                return (pos + 1 == bytes.len()).then(|| {
                    if bytes.len() == 1 {
                        Self::root()
                    } else {
                        Self {
                            wire: Arc::from(bytes),
                        }
                    }
                });
            }
            if len & 0xC0 != 0 {
                return None;
            }
            pos = pos.checked_add(1)?.checked_add(len)?;
        }
    }

    /** @brief 내부 와이어를 그대로 빌려 준다. 항상 압축이 풀린 형태다. */
    pub fn as_uncompressed_wire(&self) -> &[u8] {
        &self.wire
    }

    /**
     * @brief 압축 포인터를 따라가며 이름을 읽는다.
     *
     * @details 포인터는 뒤쪽만 가리킬 수 있다(ptr >= pos 거부). 이것이 루프를 막는
     *          1차 방어이고, MAX_JUMPS가 체인 길이의 2차 방어다. 확장 결과도 매 라벨마다
     *          255옥텟 상한으로 검사한다. 짧은 메시지가 거대한 이름으로 부풀지 못하게 한다.
     * @note 커서는 최초 점프 직전 위치의 다음으로 놓인다. 포인터를 따라간 곳이 아니라
     *       원래 흐름을 이어야 뒤따르는 필드가 제자리에서 읽힌다.
     * @return 루프, 예약 비트, 길이 초과, 범위 초과는 전부 오류다.
     */
    pub fn parse(r: &mut Reader) -> Result<Self, ProtoError> {
        let buf = r.buf;
        let mut wire = [0u8; MAX_NAME_LEN];
        let mut wire_len = 0usize;
        let mut pos = r.pos;
        let mut jumped = false;
        let mut jumps = 0usize;
        let mut end = r.pos;
        let mut total = 1usize;

        loop {
            if !jumped && pos >= r.limit {
                return Err(ProtoError::Eof);
            }
            let len = *buf.get(pos).ok_or(ProtoError::Eof)? as usize;
            match len & 0xC0 {
                0x00 => {
                    if len == 0 {
                        if !jumped {
                            end = pos + 1;
                        }
                        break;
                    }
                    let start = pos.checked_add(1).ok_or(ProtoError::Eof)?;
                    let label_end = start.checked_add(len).ok_or(ProtoError::Eof)?;
                    if !jumped && label_end > r.limit {
                        return Err(ProtoError::Eof);
                    }
                    let lab = buf.get(start..label_end).ok_or(ProtoError::Eof)?;
                    total = total
                        .checked_add(len + 1)
                        .ok_or_else(|| ProtoError::Name("Name too long".into()))?;
                    if total > MAX_NAME_LEN {
                        return Err(ProtoError::Name("Name too long".into()));
                    }
                    wire[wire_len] = len as u8;
                    wire_len += 1;
                    let wire_end = wire_len + len;
                    wire[wire_len..wire_end].copy_from_slice(lab);
                    wire_len = wire_end;
                    pos = label_end;
                }
                0xC0 => {
                    if !jumped && pos.checked_add(2).ok_or(ProtoError::Eof)? > r.limit {
                        return Err(ProtoError::Eof);
                    }
                    let b2 = *buf.get(pos + 1).ok_or(ProtoError::Eof)? as usize;
                    if !jumped {
                        end = pos + 2;
                    }
                    jumped = true;
                    jumps += 1;
                    if jumps > MAX_JUMPS {
                        return Err(ProtoError::Name("Compression pointer loop".into()));
                    }
                    let ptr = ((len & 0x3F) << 8) | b2;
                    if ptr >= pos {
                        return Err(ProtoError::Name("Invalid compression pointer".into()));
                    }
                    pos = ptr;
                }
                _ => return Err(ProtoError::Name("Reserved label length bits".into())),
            }
        }
        r.pos = end;
        if wire_len == 0 {
            return Ok(Self::root());
        }
        wire[wire_len] = 0;
        Ok(Self {
            wire: Arc::from(&wire[..=wire_len]),
        })
    }

    /**
     * @brief 압축을 허용하지 않는 이름을 읽는다.
     * @details DNSSEC 정규 형식과 일부 RDATA는 포인터를 금지한다. 0xC0 비트가 보이면
     *          역참조하지 않고 즉시 거부한다.
     */
    pub(crate) fn parse_uncompressed(r: &mut Reader) -> Result<Self, ProtoError> {
        let mut wire = [0u8; MAX_NAME_LEN];
        let mut wire_len = 0usize;
        let mut total = 1usize;
        loop {
            let len = r.u8()? as usize;
            if len == 0 {
                if wire_len == 0 {
                    return Ok(Self::root());
                }
                wire[wire_len] = 0;
                return Ok(Self {
                    wire: Arc::from(&wire[..=wire_len]),
                });
            }
            if len & 0xc0 != 0 || len > 63 {
                return Err(ProtoError::Name(
                    "Invalid label in a DNS name that cannot be compressed".into(),
                ));
            }
            total = total
                .checked_add(len + 1)
                .ok_or_else(|| ProtoError::Name("Name too long".into()))?;
            if total > MAX_NAME_LEN {
                return Err(ProtoError::Name("Name too long".into()));
            }
            wire[wire_len] = len as u8;
            wire_len += 1;
            let wire_end = wire_len + len;
            wire[wire_len..wire_end].copy_from_slice(r.bytes(len)?);
            wire_len = wire_end;
        }
    }

    /**
     * @brief 이름을 쓰면서 가능한 접미사를 압축 포인터로 대체한다.
     *
     * @details 매 라벨 경계에서 남은 접미사의 정규화 키를 조회한다. 대소문자가 달라도
     *          같은 접미사면 압축이 걸리게 하려는 것이다.
     * @note 포인터 오프셋은 14비트뿐이라 0x4000 이후 위치는 사전에 등록하지 않는다.
     *       표현할 수 없는 오프셋을 넣으면 나중에 잘못된 포인터가 나간다.
     */
    pub fn encode(&self, w: &mut Writer) {
        let mut key_buf = [0u8; MAX_NAME_LEN];
        let Some(key) = self.canonical_key_into(&mut key_buf) else {
            w.fail("Canonical DNS name key exceeds 255 bytes");
            return;
        };
        let mut key_offset = 0;
        for label in self.labels() {
            let key = &key[key_offset..];
            if let Some(off) = w.names.get(key) {
                w.push_u16(0xC000 | off);
                return;
            }
            if !w.is_failed() && w.buf.len() < 0x4000 {
                w.names.insert(key, w.buf.len() as u16);
            }
            w.push_u8(label.len() as u8);
            w.push_bytes(label);
            key_offset += label.len() + 1;
        }
        w.push_u8(0);
    }

    /**
     * @brief 압축 없이 이름을 그대로 쓴다.
     * @details 서명 대상 정규 형식과, 재직렬화 시 압축이 깨질 수 있는 RDATA에 쓴다.
     */
    pub(crate) fn encode_uncompressed(&self, w: &mut Writer) {
        w.push_bytes(&self.wire);
    }
}

impl std::fmt::Display for Name {
    /** @brief 사람이 읽을 표기. */
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_root() {
            return write!(f, ".");
        }
        for l in self.labels() {
            write!(f, "{}.", String::from_utf8_lossy(l))?;
        }
        Ok(())
    }
}

/**
 * @brief 인코딩 중인 메시지의 이름 압축 오프셋 테이블.
 *
 * @details 항목은 아레나(entries)에 쌓고 heads는 해시 → 체인 머리 인덱스만 가지고 있다.
 *          active가 논리적 길이라, clear가 항목의 Vec 할당을 그대로 재사용한다.
 *          메시지마다 테이블을 새로 만들면 응답 하나마다 할당이 붙는다.
 * @invariant 오프셋은 14비트로 표현 가능한 값(< 0x4000)만 들어온다. 호출자가 보장한다.
 */
#[derive(Default)]
pub(crate) struct NameMap {
    /** @brief 해시값에서 항목으로 가는 인덱스. */
    heads: HashMap<u64, usize, BuildHasherDefault<IdentityHasher>>,
    /** @brief 이미 적어 둔 이름들과 그 위치. */
    entries: Vec<NameMapEntry>,
    /** @brief 지금 쓰이고 있는 항목 수. */
    active: usize,
    /** @brief 해시 함수. */
    hash_builder: RandomState,
}

/** @brief 압축 테이블의 한 항목. next는 해시 충돌 체인의 다음 아레나 인덱스다. */
struct NameMapEntry {
    /** @brief 적어 둔 이름. */
    key: Vec<u8>,
    /** @brief 그 이름이 놓인 위치. 압축 지시자가 여기를 가리킨다. */
    offset: u16,
    /** @brief 같은 위치로 몰린 다음 항목. */
    next: Option<usize>,
}

/**
 * @brief 이미 해시된 값을 그대로 통과시키는 해셔.
 *
 * @details 키 해싱은 hash_builder(무작위 시드)가 한 번만 수행하고, 맵은 그 u64를 재해싱
 *          없이 쓴다. 무작위 시드는 그대로 유지되므로 충돌 유도 공격 내성은 잃지 않는다.
 */
#[derive(Default)]
struct IdentityHasher(u64);

impl Hasher for IdentityHasher {
    /** @brief 지금까지 섞은 값. */
    fn finish(&self) -> u64 {
        self.0
    }

    /** @brief 바이트열을 섞어 넣는다. */
    fn write(&mut self, bytes: &[u8]) {
        let mut value = 0u64;
        for (shift, byte) in bytes.iter().take(8).enumerate() {
            value |= u64::from(*byte) << (shift * 8);
        }
        self.0 = value;
    }

    /** @brief 64비트 수를 섞어 넣는다. */
    fn write_u64(&mut self, value: u64) {
        self.0 = value;
    }
}

impl NameMap {
    /** @brief 무작위 시드 해셔로 키 해시를 구한다. */
    fn hash(&self, key: &[u8]) -> u64 {
        let mut hasher = self.hash_builder.build_hasher();
        hasher.write(key);
        hasher.finish()
    }

    /**
     * @brief 이 접미사 키가 이미 나온 적 있으면 그 오프셋을 준다.
     * @note 해시가 같아도 키 전체를 비교한다. 충돌 하나가 잘못된 포인터로 이어지면 응답이
     *       엉뚱한 이름을 담게 된다.
     */
    pub(crate) fn get(&self, key: &[u8]) -> Option<u16> {
        let mut current = self.heads.get(&self.hash(key)).copied();
        while let Some(index) = current {
            let entry = self.entries.get(index)?;
            if entry.key == key {
                return Some(entry.offset);
            }
            current = entry.next;
        }
        None
    }

    /**
     * @brief 접미사 키의 오프셋을 등록한다.
     * @details 이미 쓰인 아레나 슬롯이 있으면 그 Vec을 비워 다시 채운다. 할당 대신 재사용.
     */
    pub(crate) fn insert(&mut self, key: &[u8], offset: u16) {
        let hash = self.hash(key);
        let next = self.heads.insert(hash, self.active);
        if let Some(entry) = self.entries.get_mut(self.active) {
            entry.key.clear();
            entry.key.extend_from_slice(key);
            entry.offset = offset;
            entry.next = next;
        } else {
            self.entries.push(NameMapEntry {
                key: key.to_vec(),
                offset,
                next,
            });
        }
        self.active += 1;
    }

    /**
     * @brief 다음 메시지를 위해 테이블을 비운다.
     * @details 보통은 인덱스만 비워 아레나를 재사용하지만, 병적으로 커진 경우에는 전부
     *          버려 워커가 그 메모리를 영구 점유하지 않게 한다.
     */
    pub(crate) fn clear(&mut self) {
        if self.entries.len() > MAX_RETAINED_NAME_ENTRIES {
            self.entries = Vec::new();
            self.heads = HashMap::default();
        } else {
            self.heads.clear();
        }
        self.active = 0;
    }

    /** @brief 이번 메시지에서 등록된 이름이 아직 없는지. */
    pub(crate) fn is_empty(&self) -> bool {
        self.active == 0
    }
}

#[cfg(test)]
/** @brief 압축 지시자, 길이 상한, 그리고 원래 바이트가 보존되는지. */
mod tests {
    use super::*;

    #[test]
    /**
     * @brief RFC 1035의 이스케이프를 풀고 다시 적는지.
     *
     * @details 풀지 않으면 다른 서버가 쓴 영역 파일의 이름이 조용히 달라진다. 점을 품은
     *          라벨 하나가 라벨 둘이 되고, 십진 이스케이프는 네 글자로 남는다. 적는 쪽도
     *          같이 맞아야 파일로 내보냈다 읽는 것만으로 이름이 바뀌지 않는다.
     */
    fn escapes_in_names_are_decoded_and_written_back() {
        /* \X 는 그 글자의 특별한 뜻을 없앤다. 점을 품은 라벨 하나다. */
        let dotted = Name::from_str(r"a\.b.example").unwrap();
        let labels: Vec<&[u8]> = dotted.labels().collect();
        assert_eq!(labels, vec![b"a.b".as_slice(), b"example".as_slice()]);

        /* \DDD 는 십진수가 가리키는 옥텟 하나다. 065는 A다. */
        let decimal = Name::from_str(r"esc\065ape.example").unwrap();
        let labels: Vec<&[u8]> = decimal.labels().collect();
        assert_eq!(labels[0], b"escAape".as_slice());

        /* 공백도 십진 이스케이프로 적는다. */
        let spaced = Name::from_str(r"sp\032ace.example").unwrap();
        assert_eq!(spaced.labels().next().unwrap(), b"sp ace".as_slice());

        /* 적는 쪽이 다시 이스케이프해야 왕복한다. */
        for name in [r"a\.b.example", r"esc\065ape.example", r"sp\032ace.example"] {
            let parsed = Name::from_str(name).unwrap();
            let written = parsed.to_master_lower();
            let again = Name::from_str(&written).unwrap();
            /* 적는 쪽이 소문자로 내리므로 대소문자는 접고 본다. DNS에서 같은 이름이다. */
            assert!(
                parsed.eq_ignore_case(&again),
                "{name} 이 왕복하지 않습니다: {written}"
            );
            assert_eq!(
                parsed.num_labels(),
                again.num_labels(),
                "{name} 의 라벨 경계가 달라졌습니다: {written}"
            );
        }

        /* 이스케이프하지 않은 끝점만 루트 표기다. */
        assert_eq!(
            Name::from_str("example.").unwrap(),
            Name::from_str("example").unwrap()
        );
        assert!(Name::from_str("a..b").is_err(), "빈 라벨은 거부한다");
        assert!(
            Name::from_str(r"a\").is_err(),
            "끝나지 않은 이스케이프는 거부한다"
        );
        assert!(
            Name::from_str(r"a\999").is_err(),
            "255를 넘는 십진값은 거부한다"
        );

        /* 평범한 이름은 그대로다. */
        assert_eq!(
            Name::from_str("www.example.com").unwrap().to_master_lower(),
            "www.example.com"
        );
    }

    #[test]
    /** @brief 적었다 읽으면 같은지. */
    fn roundtrip_simple() {
        let n = Name::from_str("www.example.com").unwrap();
        let mut w = Writer::new();
        n.encode(&mut w);

        assert_eq!(w.buf.len(), 17);
        let mut r = Reader::new(&w.buf);
        let back = Name::parse(&mut r).unwrap();
        assert!(n.eq_ignore_case(&back));
        assert_eq!(back.to_ascii_lower(), "www.example.com");
    }

    #[test]
    /** @brief 복제해도 조각 저장소를 나눠 쓰는지. 매번 복사하면 이름 하나마다 할당이 는다. */
    fn clone_shares_immutable_label_storage() {
        let name = Name::from_str("www.example.com").unwrap();
        let cloned = name.clone();

        assert!(Arc::ptr_eq(&name.wire, &cloned.wire));
        assert_eq!(name, cloned);
    }

    #[test]
    /** @brief 이어진 바이트에서도 조각을 제대로 보는지. */
    fn contiguous_wire_preserves_label_views_and_reverse_iteration() {
        let name = Name::from_labels(vec![b"WwW".to_vec(), vec![0xff], b"TEST".to_vec()]).unwrap();

        assert_eq!(&*name.wire, b"\x03WwW\x01\xff\x04TEST\0");
        assert!(name
            .labels()
            .eq([b"WwW".as_slice(), [0xff].as_slice(), b"TEST".as_slice()]));
        assert!(name
            .labels()
            .rev()
            .eq([b"TEST".as_slice(), [0xff].as_slice(), b"WwW".as_slice()]));
        let mut alternating = name.labels();
        assert_eq!(alternating.next(), Some(b"WwW".as_slice()));
        assert_eq!(alternating.next_back(), Some(b"TEST".as_slice()));
        assert_eq!(alternating.next(), Some([0xff].as_slice()));
        assert_eq!(alternating.next_back(), None);
        assert!(name.ends_with_ignore_case(&Name::from_str("test").unwrap()));
        assert!(!name.ends_with_ignore_case(&Name::from_str("x.test").unwrap()));
    }

    #[test]
    /** @brief 압축 지시자를 따라가는지. */
    fn compression_pointer() {
        let base = Name::from_str("example.com").unwrap();
        let sub = Name::from_str("www.example.com").unwrap();
        let mut w = Writer::new();
        base.encode(&mut w);
        let after_base = w.buf.len();
        sub.encode(&mut w);

        assert_eq!(w.buf.len() - after_base, 6);

        let mut r = Reader::new(&w.buf);
        let _ = Name::parse(&mut r).unwrap();
        let parsed_sub = Name::parse(&mut r).unwrap();
        assert_eq!(parsed_sub.to_ascii_lower(), "www.example.com");
    }

    #[test]
    /** @brief 앞을 가리키는 지시자를 거부하는지. 허용하면 순환을 만들어 무한히 돌게 할 수 있다. */
    fn rejects_forward_pointer_loop() {
        let buf = [0xC0u8, 0x00];
        let mut r = Reader::new(&buf);
        assert!(Name::parse(&mut r).is_err());
    }

    #[test]
    /** @brief 루트 이름. */
    fn root_name() {
        let n = Name::root();
        let mut w = Writer::new();
        n.encode(&mut w);
        assert_eq!(w.buf, vec![0]);
    }

    #[test]
    /** @brief 루트 이름이 저장소를 새로 잡지 않는지. */
    fn parsed_root_names_share_the_global_storage() {
        let mut compressed_reader = Reader::new(&[0]);
        let compressed = Name::parse(&mut compressed_reader).unwrap();
        assert!(Arc::ptr_eq(&compressed.wire, &ROOT_WIRE));

        let mut uncompressed_reader = Reader::new(&[0]);
        let uncompressed = Name::parse_uncompressed(&mut uncompressed_reader).unwrap();
        assert!(Arc::ptr_eq(&uncompressed.wire, &ROOT_WIRE));

        let borrowed = Name::from_uncompressed_wire(&[0]).unwrap();
        assert!(Arc::ptr_eq(&borrowed.wire, &ROOT_WIRE));
    }

    #[test]
    /** @brief 비교용 키가 조각 경계와 원래 바이트를 지키는지. */
    fn canonical_key_preserves_label_boundaries_and_raw_octets() {
        let a = Name::from_labels(vec![b"a.b".to_vec(), b"c".to_vec()]).unwrap();
        let b = Name::from_labels(vec![b"a".to_vec(), b"b.c".to_vec()]).unwrap();
        assert_ne!(a.canonical_key(), b.canonical_key());

        let raw1 = Name::from_labels(vec![vec![0xff]]).unwrap();
        let raw2 = Name::from_labels(vec![vec![0xfe]]).unwrap();
        assert_ne!(raw1.canonical_key(), raw2.canonical_key());
    }

    #[test]
    /** @brief 빌려 만든 키와 소유한 키가 같은지. */
    fn borrowed_canonical_keys_match_owned_keys() {
        let name = Name::from_labels(vec![b"WWW".to_vec(), vec![0xff], b"TEST".to_vec()]).unwrap();
        let mut key = [0u8; 255];
        assert_eq!(
            name.canonical_key_into(&mut key).unwrap(),
            name.canonical_key()
        );

        let mut suffix = [0u8; 255];
        assert_eq!(
            name.canonical_suffix_key_into(2, &mut suffix).unwrap(),
            name.suffix(2).canonical_key()
        );
    }

    /** @brief 지시자를 길게 이은 테스트용 바이트열. */
    fn backward_pointer_chain(count: usize) -> (Vec<u8>, usize) {
        let mut wire = vec![0u8];
        for index in 0..count {
            let target = if index == 0 {
                0usize
            } else {
                1 + 2 * (index - 1)
            };
            wire.push(0xC0 | ((target >> 8) as u8 & 0x3F));
            wire.push(target as u8);
        }
        let last = 1 + 2 * (count - 1);
        (wire, last)
    }

    #[test]
    /** @brief 지시자를 따라가는 횟수에 상한이 있는지. 없으면 짧은 패킷으로 오래 돌게 만든다. */
    fn wire_parse_bounds_pointer_jumps() {
        for count in [1usize, 20] {
            let (wire, last) = backward_pointer_chain(count);
            let mut reader = Reader::new(&wire);
            reader.pos = last;
            assert!(
                Name::parse(&mut reader).is_ok(),
                "점프 {count}회는 예산 안이다"
            );
        }
        let (wire, last) = backward_pointer_chain(21);
        let mut reader = Reader::new(&wire);
        reader.pos = last;
        let error = Name::parse(&mut reader).expect_err("점프 21회는 예산을 넘는다");
        assert!(
            error.to_string().contains("Compression pointer loop"),
            "{error}"
        );
    }

    #[test]
    /** @brief 펼친 이름 길이에 상한이 있는지. */
    fn wire_parse_bounds_expanded_name_length() {
        let mut wire = Vec::new();

        let mut previous = usize::MAX;
        let mut starts = Vec::new();
        for _ in 0..4 {
            let start = wire.len();
            wire.push(63);
            wire.extend(std::iter::repeat_n(b'a', 63));
            if previous == usize::MAX {
                wire.push(0);
            } else {
                wire.push(0xC0 | ((previous >> 8) as u8 & 0x3F));
                wire.push(previous as u8);
            }
            starts.push(start);
            previous = start;
        }
        let last = *starts.last().expect("라벨을 넣었다");
        let mut reader = Reader::new(&wire);
        reader.pos = last;
        let error = Name::parse(&mut reader).expect_err("확장 후 255바이트를 넘는다");
        assert!(error.to_string().contains("Name too long"), "{error}");
    }

    #[test]
    /** @brief 조각으로 만들 때도 길이 상한을 지키는지. */
    fn from_labels_enforces_wire_limits() {
        assert!(Name::from_labels(vec![vec![]]).is_err());
        assert!(Name::from_labels(vec![vec![b'a'; 64]]).is_err());
        assert!(Name::from_labels(vec![vec![b'a'; 63]; 5]).is_err());
    }

    #[test]
    /** @brief 끝의 점이 여럿이면 거부하는지. */
    fn from_str_rejects_multiple_trailing_root_labels() {
        assert!(Name::from_str("example..").is_err());
        assert!(Name::from_str("..").is_err());
        assert_eq!(
            Name::from_str("example.").unwrap().to_ascii_lower(),
            "example"
        );
        assert!(Name::from_str(".").unwrap().is_root());
    }

    #[test]
    /** @brief 소문자 접기가 키를 하나로 모으고, 이미 소문자면 할당하지 않는지. */
    fn to_ascii_lower_name_folds_case_and_shares_when_already_lower() {
        use std::collections::HashSet;

        let mixed = Name::from_str("WWW.Example.COM").unwrap();
        let lower = Name::from_str("www.example.com").unwrap();
        assert_eq!(mixed.to_ascii_lower_name().as_ref(), &lower);
        assert_eq!(
            mixed.to_ascii_lower_name().as_uncompressed_wire(),
            lower.as_uncompressed_wire()
        );

        let folded: HashSet<Name> = ["WWW.Example.COM", "www.EXAMPLE.com", "www.example.com"]
            .iter()
            .map(|s| {
                Name::from_str(s)
                    .unwrap()
                    .to_ascii_lower_name()
                    .into_owned()
            })
            .collect();
        assert_eq!(folded.len(), 1, "소문자로 바꾼 뒤에는 키가 하나여야 합니다");

        /* 이미 소문자면 빌려 준다. 집계 경로가 질의마다 참조계수조차 건드리지 않게 한다. */
        assert!(matches!(lower.to_ascii_lower_name(), Cow::Borrowed(_)));
        assert!(matches!(mixed.to_ascii_lower_name(), Cow::Owned(_)));

        /*
         * 길이 옥텟이 대문자 범위와 겹치지 않는다는 전제를 라벨 길이 65로 넘겨볼 수 없으므로
         * 상한인 63으로 확인한다.
         */
        let long = Name::from_labels(vec![vec![b'A'; 63]]).unwrap();
        assert_eq!(long.to_ascii_lower_name().to_ascii_lower(), "a".repeat(63));
        assert_eq!(long.to_ascii_lower_name().num_labels(), 1);
    }

    #[test]
    /** @brief 비울 때 크게 자란 내부 상태도 함께 놓아주는지. */
    fn name_map_clear_discards_pathological_retained_state() {
        let mut names = NameMap::default();
        for index in 0..1024u16 {
            let mut key = vec![63];
            key.extend(std::iter::repeat_n((index & 0xff) as u8, 63));
            key.extend_from_slice(&index.to_be_bytes());
            names.insert(&key, index);
        }
        assert_eq!(names.entries.len(), 1024);

        names.clear();

        assert!(names.entries.is_empty());
        assert!(names.entries.capacity() <= 64);
        assert!(names.heads.capacity() < 1024);
    }
}
