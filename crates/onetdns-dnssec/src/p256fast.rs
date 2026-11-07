//! Fast P-256 ECDSA verification, for the algorithm DNSSEC uses most. It uses a Montgomery-form
//! field, Jacobian coordinates and a precomputed generator table. A field element is four
//! little-endian limbs, index 0 least significant.
//!
//! Nothing here is constant time. That is acceptable for verification, which handles only public
//! values; signing with this code would leak the secret scalar.

const P: [u64; 4] = [
    0xffff_ffff_ffff_ffff,
    0x0000_0000_ffff_ffff,
    0x0000_0000_0000_0000,
    0xffff_ffff_0000_0001,
];

/// 2^512 mod P, multiplied in to enter Montgomery form.
const R2: [u64; 4] = [
    0x0000_0000_0000_0003,
    0xffff_fffb_ffff_ffff,
    0xffff_ffff_ffff_fffe,
    0x0000_0004_ffff_fffd,
];

const B_MONT: [u64; 4] = [
    0xd89c_df62_29c4_bddf,
    0xacf0_05cd_7884_3090,
    0xe5a2_20ab_f721_2ed6,
    0xdc30_061d_0487_4834,
];

const GX_MONT: [u64; 4] = [
    0x79e7_30d4_18a9_143c,
    0x75ba_95fc_5fed_b601,
    0x79fb_732b_7762_2510,
    0x1890_5f76_a537_55c6,
];
const GY_MONT: [u64; 4] = [
    0xddf2_5357_ce95_560a,
    0x8b4a_b8e4_ba19_e45c,
    0xd2e8_8688_dd21_f325,
    0x8571_ff18_2588_5d85,
];

fn fe_add(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut r = [0u64; 4];
    let mut carry = 0u128;
    for i in 0..4 {
        let v = u128::from(a[i]) + u128::from(b[i]) + carry;
        r[i] = v as u64;
        carry = v >> 64;
    }

    if carry != 0 || !fe_lt(&r, &P) {
        fe_sub_p(&mut r);
    }
    r
}

fn fe_sub(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut r = [0u64; 4];
    let mut borrow = 0i128;
    for i in 0..4 {
        let v = i128::from(a[i]) - i128::from(b[i]) - borrow;
        r[i] = v as u64;
        borrow = if v < 0 { 1 } else { 0 };
    }
    if borrow != 0 {
        let mut carry = 0u128;
        for i in 0..4 {
            let v = u128::from(r[i]) + u128::from(P[i]) + carry;
            r[i] = v as u64;
            carry = v >> 64;
        }
    }
    r
}

/// Callers guarantee the result is in range, so the borrow is dropped.
fn fe_sub_p(r: &mut [u64; 4]) {
    let mut borrow = 0i128;
    for i in 0..4 {
        let v = i128::from(r[i]) - i128::from(P[i]) - borrow;
        r[i] = v as u64;
        borrow = if v < 0 { 1 } else { 0 };
    }
}

fn fe_lt(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

fn fe_is_zero(a: &[u64; 4]) -> bool {
    a == &[0u64; 4]
}

/// Montgomery multiplication (CIOS). P has n0' = 1, so each round's m is t[0] itself and needs no
/// multiplication.
fn fe_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut t = [0u64; 6];
    for &ai in a.iter() {
        let ai = u128::from(ai);

        let mut carry = 0u128;
        for j in 0..4 {
            let v = u128::from(t[j]) + ai * u128::from(b[j]) + carry;
            t[j] = v as u64;
            carry = v >> 64;
        }
        let v = u128::from(t[4]) + carry;
        t[4] = v as u64;
        t[5] = (v >> 64) as u64;

        let m = u128::from(t[0]);

        let mut carry = (u128::from(t[0]) + m * u128::from(P[0])) >> 64;
        for j in 1..4 {
            let v = u128::from(t[j]) + m * u128::from(P[j]) + carry;
            t[j - 1] = v as u64;
            carry = v >> 64;
        }
        let v = u128::from(t[4]) + carry;
        t[3] = v as u64;
        t[4] = t[5] + (v >> 64) as u64;
    }
    let mut r = [t[0], t[1], t[2], t[3]];
    if t[4] != 0 || !fe_lt(&r, &P) {
        fe_sub_p(&mut r);
    }
    r
}

fn fe_sqr(a: &[u64; 4]) -> [u64; 4] {
    fe_mul(a, a)
}

fn to_mont(a: &[u64; 4]) -> [u64; 4] {
    fe_mul(a, &R2)
}

/// Multiplying by 1 leaves only the Montgomery reduction.
fn from_mont(a: &[u64; 4]) -> [u64; 4] {
    fe_mul(a, &[1, 0, 0, 0])
}

/// a^(P-2) by Fermat's little theorem. The exponent is a constant, so no branch depends on the
/// input.
fn fe_inv(a: &[u64; 4]) -> [u64; 4] {
    let exp: [u64; 4] = [
        0xffff_ffff_ffff_fffd,
        0x0000_0000_ffff_ffff,
        0x0000_0000_0000_0000,
        0xffff_ffff_0000_0001,
    ];
    let one_mont = to_mont(&[1, 0, 0, 0]);
    let mut result = one_mont;
    let mut started = false;
    for limb in exp.iter().rev() {
        for bit in (0..64).rev() {
            if started {
                result = fe_sqr(&result);
            }
            if (limb >> bit) & 1 == 1 {
                if started {
                    result = fe_mul(&result, a);
                } else {
                    result = *a;
                    started = true;
                }
            }
        }
    }
    result
}

/// Rejects values of P or more: accepting them would give one point two encodings.
fn fe_from_be(be: &[u8]) -> Option<[u64; 4]> {
    if be.len() != 32 {
        return None;
    }
    let mut l = [0u64; 4];
    for i in 0..4 {
        let mut v = 0u64;
        for j in 0..8 {
            v = (v << 8) | u64::from(be[i * 8 + j]);
        }
        l[3 - i] = v;
    }
    if !fe_lt(&l, &P) {
        return None;
    }
    Some(l)
}

fn fe_to_be(a: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        let v = a[3 - i];
        for j in 0..8 {
            out[i * 8 + j] = (v >> (56 - 8 * j)) as u8;
        }
    }
    out
}

const ONE_MONT: [u64; 4] = [
    0x0000_0000_0000_0001,
    0xffff_ffff_0000_0000,
    0xffff_ffff_ffff_ffff,
    0x0000_0000_ffff_fffe,
];

/// The group order; r and s must be in [1, N).
const N: [u64; 4] = [
    0xf3b9_cac2_fc63_2551,
    0xbce6_faad_a717_9e84,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_0000_0000,
];

fn fe_dbl(a: &[u64; 4]) -> [u64; 4] {
    fe_add(a, a)
}
fn fe_mul3(a: &[u64; 4]) -> [u64; 4] {
    fe_add(&fe_dbl(a), a)
}
fn fe_mul4(a: &[u64; 4]) -> [u64; 4] {
    fe_dbl(&fe_dbl(a))
}
fn fe_mul8(a: &[u64; 4]) -> [u64; 4] {
    fe_dbl(&fe_mul4(a))
}

/// Affine (x/z^2, y/z^3), so additions need no inversion until the end.
#[derive(Clone, Copy)]
struct Jac {
    x: [u64; 4],
    y: [u64; 4],
    /// Zero for the point at infinity.
    z: [u64; 4],
}

/// Only z = 0 matters; x and y are arbitrary.
const INF: Jac = Jac {
    x: ONE_MONT,
    y: ONE_MONT,
    z: [0, 0, 0, 0],
};

impl Jac {
    fn is_inf(&self) -> bool {
        fe_is_zero(&self.z)
    }

    /// The doubling formula for a = -3, which P-256 satisfies.
    fn double(&self) -> Jac {
        if self.is_inf() {
            return INF;
        }
        let delta = fe_sqr(&self.z);
        let gamma = fe_sqr(&self.y);
        let beta = fe_mul(&self.x, &gamma);
        let alpha = fe_mul3(&fe_mul(&fe_sub(&self.x, &delta), &fe_add(&self.x, &delta)));
        let x3 = fe_sub(&fe_sqr(&alpha), &fe_mul8(&beta));
        let z3 = fe_sub(&fe_sub(&fe_sqr(&fe_add(&self.y, &self.z)), &gamma), &delta);
        let y3 = fe_sub(
            &fe_mul(&alpha, &fe_sub(&fe_mul4(&beta), &x3)),
            &fe_mul8(&fe_sqr(&gamma)),
        );
        Jac {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// When the x coordinates match (h = 0), equal y means the same point, handed to `double`, and
    /// different y means inverses, giving infinity. Without this branch the formula divides by
    /// zero.
    fn add(&self, other: &Jac) -> Jac {
        if self.is_inf() {
            return *other;
        }
        if other.is_inf() {
            return *self;
        }
        let z1z1 = fe_sqr(&self.z);
        let z2z2 = fe_sqr(&other.z);
        let u1 = fe_mul(&self.x, &z2z2);
        let u2 = fe_mul(&other.x, &z1z1);
        let s1 = fe_mul(&fe_mul(&self.y, &other.z), &z2z2);
        let s2 = fe_mul(&fe_mul(&other.y, &self.z), &z1z1);
        let h = fe_sub(&u2, &u1);
        let r = fe_sub(&s2, &s1);
        if fe_is_zero(&h) {
            if fe_is_zero(&r) {
                return self.double();
            }
            return INF;
        }
        let hh = fe_sqr(&h);
        let i = fe_mul4(&hh);
        let j = fe_mul(&h, &i);
        let rr = fe_dbl(&r);
        let v = fe_mul(&u1, &i);
        let x3 = fe_sub(&fe_sub(&fe_sqr(&rr), &j), &fe_dbl(&v));
        let y3 = fe_sub(&fe_mul(&rr, &fe_sub(&v, &x3)), &fe_dbl(&fe_mul(&s1, &j)));
        let z3 = fe_mul(
            &fe_sub(&fe_sub(&fe_sqr(&fe_add(&self.z, &other.z)), &z1z1), &z2z2),
            &h,
        );
        Jac {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    fn neg(&self) -> Jac {
        Jac {
            x: self.x,
            y: fe_sub(&P, &self.y),
            z: self.z,
        }
    }

    /// Verification needs only x, so y is not recovered. `None` at infinity.
    fn affine_x(&self) -> Option<[u64; 4]> {
        if self.is_inf() {
            return None;
        }
        let zinv = fe_inv(&self.z);
        let zinv2 = fe_sqr(&zinv);
        Some(from_mont(&fe_mul(&self.x, &zinv2)))
    }
}

fn affine_to_jac(x_mont: [u64; 4], y_mont: [u64; 4]) -> Jac {
    Jac {
        x: x_mont,
        y: y_mont,
        z: ONE_MONT,
    }
}

const G_JAC: Jac = Jac {
    x: GX_MONT,
    y: GY_MONT,
    z: ONE_MONT,
};

/// Checks the curve equation; an unchecked point would allow an invalid-curve attack. `None` when
/// a coordinate is out of range or the point is not on the curve.
fn public_point(qx_be: &[u8], qy_be: &[u8]) -> Option<Jac> {
    let x = fe_from_be(qx_be)?;
    let y = fe_from_be(qy_be)?;
    let xm = to_mont(&x);
    let ym = to_mont(&y);

    let lhs = fe_sqr(&ym);
    let x3 = fe_mul(&fe_sqr(&xm), &xm);
    let three_x = fe_mul3(&xm);
    let rhs = fe_add(&fe_sub(&x3, &three_x), &B_MONT);
    if lhs != rhs {
        return None;
    }
    Some(affine_to_jac(xm, ym))
}

/// Plain double-and-add, the reference for the wNAF path in tests.
#[cfg(test)]
fn scalar_mul(p: &Jac, k_be: &[u8]) -> Jac {
    let mut acc = INF;
    let mut started = false;
    for &byte in k_be {
        for bit in (0..8).rev() {
            if started {
                acc = acc.double();
            }
            if (byte >> bit) & 1 == 1 {
                acc = if started { acc.add(p) } else { *p };
                started = true;
            }
        }
    }
    acc
}

/// The generator table is built once, so its window is wide.
const WG: u32 = 8;
/// A public key's table is built per verification, so its window balances build cost against
/// additions.
const WQ: u32 = 5;

/// 1P, 3P, 5P, ...; wNAF digits are always odd.
fn odd_multiples(p: &Jac, w: u32) -> Vec<Jac> {
    let n = 1usize << (w - 2);
    let mut table = Vec::with_capacity(n);
    table.push(*p);
    let twice = p.double();
    for i in 1..n {
        table.push(table[i - 1].add(&twice));
    }
    table
}

/// Built on the first verification and kept for the process lifetime.
fn g_table() -> &'static [Jac] {
    static T: std::sync::OnceLock<Vec<Jac>> = std::sync::OnceLock::new();
    T.get_or_init(|| odd_multiples(&G_JAC, WG))
}

/// Signed width-w digits with at least w-1 zeros between nonzero ones, which cuts additions. A
/// digit above half becomes negative and carries into the rest; a negative digit adds the negated
/// point. Returns the digits and how many are used.
fn wnaf(be: &[u8], w: u32) -> ([i32; 257], usize) {
    let mut k = [0u64; 4];
    for i in 0..4 {
        let mut v = 0u64;
        for j in 0..8 {
            v = (v << 8) | u64::from(be[i * 8 + j]);
        }
        k[3 - i] = v;
    }
    let base = 1i64 << w;
    let half = 1i64 << (w - 1);
    let mut digits = [0i32; 257];
    let mut i = 0usize;
    while k != [0u64; 4] && i < 257 {
        if k[0] & 1 == 1 {
            let mut d = (k[0] & ((1u64 << w) - 1)) as i64;
            if d >= half {
                d -= base;
            }
            digits[i] = d as i32;
            if d >= 0 {
                let mut borrow = d as u64;
                for limb in k.iter_mut() {
                    let (v, b) = limb.overflowing_sub(borrow);
                    *limb = v;
                    borrow = u64::from(b);
                    if borrow == 0 {
                        break;
                    }
                }
            } else {
                let mut carry = (-d) as u64;
                for limb in k.iter_mut() {
                    let (v, c) = limb.overflowing_add(carry);
                    *limb = v;
                    carry = u64::from(c);
                    if carry == 0 {
                        break;
                    }
                }
            }
        }
        for j in 0..3 {
            k[j] = (k[j] >> 1) | (k[j + 1] << 63);
        }
        k[3] >>= 1;
        i += 1;
    }
    (digits, i)
}

/// u1*G + u2*Q in one pass (Shamir's trick), sharing the doublings.
fn lincomb(u1_be: &[u8], u2_be: &[u8], q: &Jac) -> Jac {
    let gt = g_table();
    let qt = odd_multiples(q, WQ);
    let (ng, leng) = wnaf(u1_be, WG);
    let (nq, lenq) = wnaf(u2_be, WQ);
    let len = leng.max(lenq);
    let pick = |table: &[Jac], d: i32| -> Jac {
        let idx = ((d.unsigned_abs() - 1) / 2) as usize;
        if d > 0 {
            table[idx]
        } else {
            table[idx].neg()
        }
    };
    let mut acc = INF;
    for i in (0..len).rev() {
        acc = acc.double();
        if ng[i] != 0 {
            acc = acc.add(&pick(gt, ng[i]));
        }
        if nq[i] != 0 {
            acc = acc.add(&pick(&qt, nq[i]));
        }
    }
    acc
}

/// R's x coordinate reduced mod N, for comparison with r. P - N is small, so one subtraction
/// suffices. `None` when the key is not on the curve or R is infinity.
pub(crate) fn lincomb_rx(
    u1_be: &[u8],
    u2_be: &[u8],
    qx_be: &[u8],
    qy_be: &[u8],
) -> Option<[u8; 32]> {
    let q = public_point(qx_be, qy_be)?;
    let r = lincomb(u1_be, u2_be, &q);
    let x = r.affine_x()?;

    let mut xn = x;
    if !fe_lt(&xn, &N) {
        let mut borrow = 0i128;
        for i in 0..4 {
            let v = i128::from(xn[i]) - i128::from(N[i]) - borrow;
            xn[i] = v as u64;
            borrow = if v < 0 { 1 } else { 0 };
        }
    }
    Some(fe_to_be(&xn))
}

/// Scalar arithmetic stays in the p256 crate; only point arithmetic runs here. r and s must be in
/// [1, N): a zero would let a signature pass for any key. `pubkey` is the 64-byte x||y of an
/// algorithm 13 DNSKEY, and `sig` is r||s.
pub(crate) fn verify(pubkey: &[u8], digest32: &[u8; 32], sig: &[u8]) -> Result<(), ()> {
    use p256::elliptic_curve::ff::Field;
    use p256::elliptic_curve::ops::Reduce;
    use p256::elliptic_curve::PrimeField;
    use p256::Scalar;
    if sig.len() != 64 || pubkey.len() != 64 {
        return Err(());
    }
    let r_bytes: [u8; 32] = sig[..32].try_into().map_err(|_| ())?;
    let s_bytes: [u8; 32] = sig[32..].try_into().map_err(|_| ())?;
    let r = Option::<Scalar>::from(Scalar::from_repr(r_bytes.into())).ok_or(())?;
    let s = Option::<Scalar>::from(Scalar::from_repr(s_bytes.into())).ok_or(())?;
    if bool::from(r.is_zero()) || bool::from(s.is_zero()) {
        return Err(());
    }
    let z = <Scalar as Reduce<p256::FieldBytes>>::reduce(&(*digest32).into());
    let s_inv = Option::<Scalar>::from(s.invert_vartime()).ok_or(())?;
    let u1 = z * s_inv;
    let u2 = r * s_inv;
    let rx = lincomb_rx(
        u1.to_repr().as_slice(),
        u2.to_repr().as_slice(),
        &pubkey[..32],
        &pubkey[32..],
    )
    .ok_or(())?;
    if rx.as_slice() == r.to_repr().as_slice() {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference multiplication, independent of the Montgomery path.
    fn ref_mulmod(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
        let mut wide = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let v = u128::from(wide[i + j]) + u128::from(a[i]) * u128::from(b[j]) + carry;
                wide[i + j] = v as u64;
                carry = v >> 64;
            }
            wide[i + 4] = carry as u64;
        }
        barrett_like_mod(&wide)
    }

    fn barrett_like_mod(wide: &[u64; 8]) -> [u64; 4] {
        let mut rem = [0u64; 4];
        for bit in (0..512).rev() {
            let mut carry = 0u64;
            for limb in rem.iter_mut() {
                let nc = *limb >> 63;
                *limb = (*limb << 1) | carry;
                carry = nc;
            }
            let hi = carry;
            let wb = (wide[bit / 64] >> (bit % 64)) & 1;
            rem[0] |= wb;

            if hi == 1 || !fe_lt(&rem, &P) {
                fe_sub_p(&mut rem);
            }
        }
        rem
    }

    fn p256_scalar_g_x(k_be: &[u8; 32]) -> Option<[u8; 32]> {
        use p256::elliptic_curve::group::GroupEncoding;
        use p256::elliptic_curve::PrimeField;
        let sc = Option::<p256::Scalar>::from(p256::Scalar::from_repr((*k_be).into()))?;
        let pt = p256::ProjectivePoint::GENERATOR * sc;
        let enc = pt.to_affine().to_bytes();
        let mut x = [0u8; 32];
        x.copy_from_slice(&enc[1..33]);
        Some(x)
    }

    #[test]
    #[ignore = "타이밍 측정 전용: cargo test --release -- --ignored --nocapture"]
    fn timing() {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
        use sha2::Digest as _;
        let sk = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let vk = VerifyingKey::from(&sk);
        let pk = vk.to_sec1_point(false);
        let pubkey = pk.as_bytes()[1..].to_vec();
        let digest: [u8; 32] = sha2::Sha256::digest(b"timing").into();
        let sig: Signature = sk.sign_prehash(&digest).unwrap();
        let raw = sig.to_bytes();
        assert!(verify(&pubkey, &digest, &raw).is_ok());
        let n = 3000u32;
        let t = std::time::Instant::now();
        for _ in 0..n {
            let _ = std::hint::black_box(verify(
                std::hint::black_box(&pubkey),
                &digest,
                std::hint::black_box(&raw),
            ));
        }
        let us = t.elapsed().as_micros() as f64 / f64::from(n);
        println!("p256fast::verify: {us:.1} us/op");
    }

    /// Accepting a tampered signature only here would be a bypass, so both sides must agree on
    /// every case, not just on valid signatures.
    #[test]
    fn verify_differential_against_p256() {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
        use sha2::Digest as _;
        for round in 0u32..1000 {
            let mut seed = [0u8; 32];
            seed[..4].copy_from_slice(&round.to_le_bytes());
            seed[31] = 3;
            let sk = SigningKey::from_slice(&seed).unwrap();
            let vk = VerifyingKey::from(&sk);
            let pk = vk.to_sec1_point(false);
            let pubkey = &pk.as_bytes()[1..];
            let digest: [u8; 32] = sha2::Sha256::digest(format!("msg {round}")).into();
            let sig: Signature = sk.sign_prehash(&digest).unwrap();
            let raw = sig.to_bytes();

            assert!(
                verify(pubkey, &digest, &raw).is_ok(),
                "accept round {round}"
            );

            let mut bad = raw.to_vec();
            bad[(round as usize) % 64] ^= 1;
            let mine = verify(pubkey, &digest, &bad).is_ok();
            let theirs = Signature::from_slice(&bad)
                .map(|s2| {
                    use p256::ecdsa::signature::hazmat::PrehashVerifier;
                    vk.verify_prehash(&digest, &s2).is_ok()
                })
                .unwrap_or(false);
            assert_eq!(mine, theirs, "tamper round {round}");

            let mut d2 = digest;
            d2[(round as usize) % 32] ^= 1;
            assert!(verify(pubkey, &d2, &raw).is_err(), "wrong digest {round}");
        }
    }

    #[test]
    fn scalar_g_matches_p256() {
        for round in 1u32..40 {
            let mut kb = [0u8; 32];
            kb[28..].copy_from_slice(&round.to_be_bytes());
            kb[0] = (round as u8).wrapping_mul(13).wrapping_add(1);
            let mine = scalar_mul(&G_JAC, &kb).affine_x().map(|x| fe_to_be(&x));
            let want = p256_scalar_g_x(&kb);
            assert_eq!(mine, want, "round {round}");
        }
    }

    #[test]
    fn field_basic_diagnostics() {
        let a = [0x1234_5678u64, 0xabcd, 0, 0];
        assert_eq!(from_mont(&to_mont(&a)), a, "roundtrip");

        let six = from_mont(&fe_mul(&to_mont(&[2, 0, 0, 0]), &to_mont(&[3, 0, 0, 0])));
        assert_eq!(six, [6, 0, 0, 0], "2*3");

        let r_mod_p = [
            0x0000_0000_0000_0001u64,
            0xffff_ffff_0000_0000,
            0xffff_ffff_ffff_ffff,
            0x0000_0000_ffff_fffe,
        ];
        assert_eq!(to_mont(&[1, 0, 0, 0]), r_mod_p, "to_mont(1)=R mod p");

        let pm1 = super::fe_sub(&P, &[1, 0, 0, 0]);
        let got = from_mont(&fe_mul(&to_mont(&a), &to_mont(&pm1)));
        let want = super::fe_sub(&P, &a);
        assert_eq!(got, want, "a*(p-1)=p-a  got={got:x?} want={want:x?}");
    }

    #[test]
    fn field_mul_matches_reference() {
        let cases: [[u64; 4]; 5] = [
            [1, 0, 0, 0],
            [0xdead_beef, 0x1234, 0, 0],
            [
                0xffff_ffff_ffff_fffe,
                0x0000_0000_ffff_ffff,
                0,
                0xffff_ffff_0000_0001,
            ],
            [0x1111_2222_3333_4444, 0x5555_6666_7777_8888, 0x9999, 0xaaaa],
            P,
        ];
        for a in &cases {
            for b in &cases {
                let am = if fe_lt(a, &P) { *a } else { fe_sub(a, &P) };
                let bm = if fe_lt(b, &P) { *b } else { fe_sub(b, &P) };

                let got = from_mont(&fe_mul(&to_mont(&am), &to_mont(&bm)));
                let want = ref_mulmod(&am, &bm);
                assert_eq!(got, want, "a={am:?} b={bm:?}");
            }
        }
    }

    #[test]
    fn field_inverse_roundtrip() {
        let a = [0x1234_5678_9abc_def0u64, 0x2, 0x3, 0x4];
        let am = to_mont(&a);
        let inv = fe_inv(&am);
        let prod = from_mont(&fe_mul(&am, &inv));
        assert_eq!(prod, [1, 0, 0, 0], "a * a^-1 == 1");
    }

    #[test]
    fn bytes_roundtrip() {
        let be: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
        let f = fe_from_be(&be).unwrap();
        assert_eq!(fe_to_be(&f), be);
    }
}
