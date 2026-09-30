/*!
 * @brief 바이트 커서와 이름 압축 상태를 유지하는 읽기/쓰기 원시 타입.
 *
 * @details 상위 코덱(message/name/rdata)이 공유하는 유일한 바이트 접근 경로다. 경계 검사가
 *          여기 한곳에 모여 있어야 상위 파서가 슬라이스를 직접 인덱싱하지 않게 된다.
 */

use crate::name::NameMap;
use crate::ProtoError;

/** @brief TCP 2바이트 길이 접두사가 표현할 수 있는 DNS 메시지의 절대 상한. */
pub const MAX_DNS_WIRE_LEN: usize = u16::MAX as usize;

/**
 * @brief 경계 검사가 붙은 전진 전용 바이트 커서.
 *
 * @details pos는 자유롭게 되감을 수 있다. 이름 압축 포인터를 따라갈 때 필요하다.
 *          limit은 RDATA를 읽는 동안 임시로 줄여, 레코드가 자기 길이 밖을 넘겨다보지
 *          못하게 막는 장치다.
 * @invariant pos <= limit <= buf.len(). 모든 읽기는 이를 확인한 뒤에만 진행한다.
 */
pub struct Reader<'a> {
    /** @brief 읽어 들일 바이트. */
    pub buf: &'a [u8],
    /** @brief 지금 위치. */
    pub pos: usize,
    /** @brief 여기까지만 읽는다. 구간을 넘어 읽지 않으려는 것이다. */
    pub(crate) limit: usize,
}

impl<'a> Reader<'a> {
    /** @brief 버퍼 전체를 읽기 범위로 삼는 커서를 만든다. */
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            limit: buf.len(),
        }
    }

    /**
     * @brief 1바이트를 읽고 커서를 전진시킨다.
     * @return 남은 바이트가 없으면 ProtoError::Eof.
     */
    pub fn u8(&mut self) -> Result<u8, ProtoError> {
        if self.pos >= self.limit {
            return Err(ProtoError::Eof);
        }
        let b = *self.buf.get(self.pos).ok_or(ProtoError::Eof)?;
        self.pos += 1;
        Ok(b)
    }

    /** @brief 빅엔디언 16비트를 읽는다. 두 번째 바이트가 없으면 실패한다. */
    pub fn u16(&mut self) -> Result<u16, ProtoError> {
        let hi = self.u8()? as u16;
        let lo = self.u8()? as u16;
        Ok((hi << 8) | lo)
    }

    /** @brief 빅엔디언 32비트를 읽는다. TTL과 SOA 타이머가 이 폭이다. */
    pub fn u32(&mut self) -> Result<u32, ProtoError> {
        let a = self.u16()? as u32;
        let b = self.u16()? as u32;
        Ok((a << 16) | b)
    }

    /**
     * @brief n바이트를 빌려 온다. 복사하지 않는다.
     *
     * @param n 요청 길이. 신뢰할 수 없는 입력에서 온 값이므로 덧셈부터 넘침을 검사한다.
     * @return 원본 버퍼를 가리키는 슬라이스, 또는 범위를 넘으면 Eof.
     */
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], ProtoError> {
        let end = self.pos.checked_add(n).ok_or(ProtoError::Eof)?;
        if end > self.limit {
            return Err(ProtoError::Eof);
        }
        let s = self.buf.get(self.pos..end).ok_or(ProtoError::Eof)?;
        self.pos = end;
        Ok(s)
    }

    /** @brief 현재 한계까지 남은 바이트 수. 한계 밖이면 0이다. */
    pub fn remaining(&self) -> usize {
        self.limit.saturating_sub(self.pos)
    }
}

/**
 * @brief 이름 압축을 기억하는, 한 번 실패하면 끝인 인코딩 버퍼.
 *
 * @details 첫 오류에서 error를 설정하고 이후 쓰기를 전부 버린다. 덕분에 인코딩 경로가
 *          매 push마다 결과를 검사하지 않아도 되지만, 호출자는 반드시 error() 또는
 *          finish()로 결과를 확인해야 한다. 확인하지 않으면 잘린 메시지를 성공으로
 *          착각한다.
 * @invariant buf.len() <= limit. 한계를 넘기려는 시도는 쓰기 대신 실패로 바뀐다.
 */
pub struct Writer {
    /** @brief 적어 넣을 바이트. */
    pub buf: Vec<u8>,
    /** @brief 이미 적은 이름들. 압축 지시자를 만드는 데 쓴다. */
    pub(crate) names: NameMap,
    /** @brief 적다 난 오류. 한 번 나면 이후 쓰기는 버린다. */
    error: Option<ProtoError>,
    /** @brief 적을 수 있는 크기 상한. */
    limit: usize,
}

impl Default for Writer {
    /** @brief 빈 버퍼. */
    fn default() -> Self {
        Self {
            buf: Vec::new(),
            names: NameMap::default(),
            error: None,
            limit: MAX_DNS_WIRE_LEN,
        }
    }
}

impl Writer {
    /** @brief 와이어 절대 상한(64KiB)까지 쓸 수 있는 버퍼를 만든다. */
    pub fn new() -> Self {
        Self::default()
    }

    /**
     * @brief 길이 상한을 좁힌 버퍼를 만든다. UDP 응답을 협상된 크기에 맞출 때 쓴다.
     * @param limit 요청 상한. 와이어 절대 상한보다 크면 절대 상한으로 깎인다.
     */
    pub fn with_limit(limit: usize) -> Self {
        Self {
            limit: limit.min(MAX_DNS_WIRE_LEN),
            ..Self::default()
        }
    }

    /**
     * @brief 할당을 유지한 채 버퍼를 재사용 가능한 상태로 되돌린다.
     * @warning 압축 오프셋은 메시지마다 무효하므로 names도 함께 비운다. 빼먹으면 다음
     *          메시지가 이전 메시지의 오프셋을 가리키는 포인터를 쓴다.
     */
    pub fn clear(&mut self) {
        self.buf.clear();
        self.names.clear();
        self.error = None;
    }

    /** @brief 인코딩을 실패로 고정한다. 첫 오류만 남기고 이후 호출은 무시한다. */
    pub fn fail(&mut self, message: impl Into<String>) {
        if self.error.is_none() {
            self.error = Some(ProtoError::Message(message.into()));
        }
    }

    /** @brief 이미 실패했는지. 긴 인코딩 루프를 조기 종료할 때 본다. */
    pub fn is_failed(&self) -> bool {
        self.error.is_some()
    }

    /** @brief 버퍼를 소비하지 않고 실패 사유를 들여다본다. */
    pub fn error(&self) -> Option<&ProtoError> {
        self.error.as_ref()
    }

    /**
     * @brief additional바이트를 덧붙여도 되는지 판정한다.
     * @return 써도 되면 true. false면 이미 실패했거나 방금 실패로 바뀐 것이다.
     */
    fn reserve_append(&mut self, additional: usize) -> bool {
        if self.error.is_some() {
            return false;
        }
        let Some(total) = self.buf.len().checked_add(additional) else {
            self.fail("DNS message length arithmetic overflowed");
            return false;
        };
        if total > self.limit {
            self.fail(format!("DNS message exceeds the {}-byte limit", self.limit));
            return false;
        }
        true
    }

    /** @brief 1바이트를 덧붙인다. 한계를 넘으면 조용히 버리고 실패로 표시한다. */
    pub fn push_u8(&mut self, v: u8) {
        if self.reserve_append(1) {
            self.buf.push(v);
        }
    }

    /** @brief 빅엔디언 16비트를 덧붙인다. */
    pub fn push_u16(&mut self, v: u16) {
        if self.reserve_append(2) {
            self.buf.extend_from_slice(&v.to_be_bytes());
        }
    }

    /** @brief 빅엔디언 32비트를 덧붙인다. */
    pub fn push_u32(&mut self, v: u32) {
        if self.reserve_append(4) {
            self.buf.extend_from_slice(&v.to_be_bytes());
        }
    }

    /** @brief 슬라이스를 그대로 덧붙인다. */
    pub fn push_bytes(&mut self, b: &[u8]) {
        if self.reserve_append(b.len()) {
            self.buf.extend_from_slice(b);
        }
    }

    /**
     * @brief 같은 모양의 레코드를 여럿 이어 쓸 공간을 한 번에 확보한다.
     *
     * @details 레코드마다 push_bytes를 부르면 상한 검사와 용량 검사, 그리고 길이가
     *          실행 시점에 정해지는 작은 memcpy 호출이 레코드 수만큼 생긴다. 공간을 한
     *          번 잡고 돌려받은 구간에 고정 크기로 직접 쓰면 그 호출들이 없어진다.
     * @param additional 잡을 바이트 수.
     * @return 0으로 채워진 구간. 상한을 넘었거나 이미 실패했으면 None이고 버퍼는
     *         건드리지 않은 상태다.
     */
    pub fn reserve_block(&mut self, additional: usize) -> Option<&mut [u8]> {
        if !self.reserve_append(additional) {
            return None;
        }
        let start = self.buf.len();
        self.buf.resize(start + additional, 0);
        Some(&mut self.buf[start..])
    }

    /**
     * @brief 나중에 채울 16비트 길이 슬롯을 예약한다.
     * @return 예약 위치. 내용을 다 쓴 뒤 backpatch_len에 그대로 넘긴다.
     */
    pub fn placeholder_u16(&mut self) -> usize {
        let at = self.buf.len();
        self.push_u16(0);
        at
    }

    /**
     * @brief 예약해 둔 슬롯에 그 뒤로 쓴 바이트 수를 기록한다.
     *
     * @param at placeholder_u16이 돌려준 위치.
     * @note RDLENGTH는 16비트라, 65,535바이트를 넘긴 RDATA는 잘라 내지 않고 실패시킨다.
     */
    pub fn backpatch_len(&mut self, at: usize) {
        if self.error.is_some() {
            return;
        }
        let Some(start) = at.checked_add(2) else {
            self.fail("DNS length placeholder overflowed");
            return;
        };
        let Some(slice) = self.buf.get(at..start) else {
            self.fail("Invalid DNS length placeholder range");
            return;
        };
        let _ = slice;
        let Some(len) = self.buf.len().checked_sub(start) else {
            self.fail("Invalid DNS RDATA length range");
            return;
        };
        let Ok(len) = u16::try_from(len) else {
            self.fail("DNS record data exceeds 65,535 bytes");
            return;
        };
        self.buf[at..start].copy_from_slice(&len.to_be_bytes());
    }

    /**
     * @brief 버퍼를 소비해 완성된 와이어를 꺼낸다.
     * @return 인코딩 중 한 번이라도 실패했으면 그 오류, 아니면 바이트열.
     */
    pub fn finish(self) -> Result<Vec<u8>, ProtoError> {
        match self.error {
            Some(error) => Err(error),
            None => Ok(self.buf),
        }
    }
}
