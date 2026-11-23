//! RFC 9463 DNR: announces the encrypted listeners DDR advertises through DHCPv4, DHCPv6 and router
//! advertisements, at the DNS server addresses each of them already hands out.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use onetdns_config::Config;
use onetdns_proto::Name;

use crate::layers::DdrEndpoint;

pub(crate) const OPTION_V4_DNR: u8 = 162;
pub(crate) const OPTION_V6_DNR: u16 = 144;
pub(crate) const RA_ENCRYPTED_DNS: u8 = 144;

/// The DDR name as the ADN and the encrypted endpoints with the addresses they listen on. Edge
/// services put it in their identity, so a change to it restarts them.
#[derive(Debug, PartialEq)]
pub(crate) struct Source {
    adn: String,
    endpoints: Vec<(DdrEndpoint, Vec<IpAddr>)>,
}

impl Source {
    /// `None` without `ddr_name`, which turns DDR off as well.
    pub(crate) fn new(cfg: &Config) -> Option<Self> {
        (!cfg.ddr_name.is_empty()).then(|| Source {
            adn: cfg.ddr_name.clone(),
            endpoints: crate::encrypted_endpoints(cfg),
        })
    }

    /// One instance per endpoint, carrying the `announced` DNS server addresses it listens on. An
    /// endpoint that listens on none of them is left out, so the result is empty when no encrypted
    /// listener is reachable at an announced address.
    pub(crate) fn instances<A>(&self, announced: &[A]) -> Result<Vec<Instance<A>>, String>
    where
        A: Copy + Into<IpAddr>,
    {
        let adn = Name::from_str(&self.adn).map_err(|error| {
            format!(
                "Could not turn ddr_name '{}' into a DNS name: {error}",
                self.adn
            )
        })?;
        let mut out = Vec::new();
        for (endpoint, listen) in &self.endpoints {
            let addrs: Vec<A> = announced
                .iter()
                .copied()
                .filter(|addr| {
                    let addr = (*addr).into();
                    usable(addr) && listens_on(listen, addr)
                })
                .collect();
            if addrs.is_empty() {
                continue;
            }
            let mut params = Vec::new();
            for (key, value) in endpoint.svc_params()? {
                params.extend_from_slice(&key.to_be_bytes());
                push_len16_prefixed(&mut params, &value)
                    .ok_or("A DDR service parameter exceeds 65,535 bytes")?;
            }
            out.push(Instance {
                priority: endpoint.priority,
                adn: Box::from(adn.as_uncompressed_wire()),
                addrs,
                params: params.into_boxed_slice(),
            });
        }
        Ok(out)
    }
}

/// Clients discard loopback and multicast addresses, and one discarded address can void a whole
/// DHCPv4 option.
fn usable(addr: IpAddr) -> bool {
    !(addr.is_unspecified() || addr.is_loopback() || addr.is_multicast())
}

fn listens_on(listen: &[IpAddr], addr: IpAddr) -> bool {
    listen.iter().any(|bound| {
        *bound == addr
            || match bound {
                IpAddr::V4(ip) => ip.is_unspecified() && addr.is_ipv4(),
                IpAddr::V6(_) => onetdns_core::listen::is_dual_stack(SocketAddr::new(*bound, 0)),
            }
    })
}

/// One encrypted endpoint as DNR announces it on one link.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Instance<A> {
    priority: u16,
    /// Uncompressed wire form.
    adn: Box<[u8]>,
    addrs: Vec<A>,
    /// SvcParams wire form.
    params: Box<[u8]>,
}

fn push_len16_prefixed(out: &mut Vec<u8>, bytes: &[u8]) -> Option<()> {
    out.extend_from_slice(&u16::try_from(bytes.len()).ok()?.to_be_bytes());
    out.extend_from_slice(bytes);
    Some(())
}

impl Instance<Ipv4Addr> {
    /// DNR Instance Data, length first; one option 162 holds several. `None` when a field outgrows
    /// its length.
    pub(crate) fn dhcp4(&self) -> Option<Vec<u8>> {
        let adn_len = u8::try_from(self.adn.len()).ok()?;
        let addr_len = u8::try_from(self.addrs.len().checked_mul(4)?).ok()?;
        let mut data = Vec::with_capacity(4 + self.adn.len() + 4 * self.addrs.len() + 32);
        data.extend_from_slice(&self.priority.to_be_bytes());
        data.push(adn_len);
        data.extend_from_slice(&self.adn);
        data.push(addr_len);
        for addr in &self.addrs {
            data.extend_from_slice(&addr.octets());
        }
        data.extend_from_slice(&self.params);
        let mut out = Vec::with_capacity(2 + data.len());
        push_len16_prefixed(&mut out, &data)?;
        Some(out)
    }
}

impl Instance<Ipv6Addr> {
    fn addr_bytes(&self) -> Vec<u8> {
        self.addrs.iter().flat_map(|addr| addr.octets()).collect()
    }

    /// The OPTION_V6_DNR value. `None` when it outgrows the option length.
    pub(crate) fn dhcp6(&self) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.priority.to_be_bytes());
        push_len16_prefixed(&mut out, &self.adn)?;
        push_len16_prefixed(&mut out, &self.addr_bytes())?;
        out.extend_from_slice(&self.params);
        u16::try_from(out.len()).ok()?;
        Some(out)
    }

    /// The Encrypted DNS option, zero-padded to whole 8-byte units. `None` when it outgrows the
    /// length byte.
    pub(crate) fn ra(&self, lifetime: u32) -> Option<Vec<u8>> {
        let mut out = vec![RA_ENCRYPTED_DNS, 0];
        out.extend_from_slice(&self.priority.to_be_bytes());
        out.extend_from_slice(&lifetime.to_be_bytes());
        push_len16_prefixed(&mut out, &self.adn)?;
        push_len16_prefixed(&mut out, &self.addr_bytes())?;
        push_len16_prefixed(&mut out, &self.params)?;
        let units = out.len().div_ceil(8);
        out[1] = u8::try_from(units).ok()?;
        out.resize(units * 8, 0);
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `doh1.example.com.` from the RFC 9463 example, 18 bytes.
    const ADN: &[u8] = b"\x04doh1\x07example\x03com\x00";
    /// alpn h2, port 443, dohpath `/q{?dns}`; 25 bytes.
    const DOH_PARAMS: &[u8] =
        b"\x00\x01\x00\x03\x02h2\x00\x03\x00\x02\x01\xbb\x00\x07\x00\x08/q{?dns}";
    /// alpn h2, port 443, dohpath `/{?dns}`; 24 bytes.
    const SHORT_DOH_PARAMS: &[u8] =
        b"\x00\x01\x00\x03\x02h2\x00\x03\x00\x02\x01\xbb\x00\x07\x00\x07/{?dns}";
    /// alpn dot, port 853.
    const DOT_PARAMS: &[u8] = b"\x00\x01\x00\x04\x03dot\x00\x03\x00\x02\x03\x55";

    fn config(listen: &str) -> Config {
        Config::from_toml_str(&format!(
            "ddr_name = \"doh1.example.com\"\ndoh_path = \"/q\"\n{listen}\n\
             tls_self_signed_host = \"doh1.example.com\"\n"
        ))
        .expect("유효한 DDR 설정")
    }

    fn instance<A>(addrs: Vec<A>) -> Instance<A> {
        Instance {
            priority: 1,
            adn: Box::from(ADN),
            addrs,
            params: Box::from(DOH_PARAMS),
        }
    }

    #[test]
    fn instances_reuse_the_ddr_name_and_parameters() {
        let cfg = config("listen_doh = [\"0.0.0.0:443\"]\nlisten_dot = [\"0.0.0.0:853\"]");
        let source = Source::new(&cfg).expect("ddr_name이 있으면 DNR도 켜짐");
        let lan = Ipv4Addr::new(192, 168, 1, 10);
        let instances = source.instances(&[lan]).unwrap();
        assert_eq!(instances.len(), 2);
        assert_eq!(instances[0], instance(vec![lan]));
        assert_eq!(&*instances[1].params, DOT_PARAMS);
        assert_eq!(instances[1].priority, 3);
    }

    #[test]
    fn nothing_is_announced_without_ddr_name_or_a_reachable_listener() {
        assert!(Source::new(&Config::default()).is_none());

        let lan = Ipv4Addr::new(192, 168, 1, 10);
        for listen in [
            "listen_doh = [\"127.0.0.1:443\"]",
            "listen_doh = [\"192.168.1.20:443\"]",
        ] {
            let source = Source::new(&config(listen)).unwrap();
            assert!(
                source.instances(&[lan]).unwrap().is_empty(),
                "{listen}: 알린 주소에서 받지 않는 리스너는 알리지 않습니다"
            );
        }
        let source = Source::new(&config("listen_doh = [\"0.0.0.0:443\"]")).unwrap();
        assert!(source.instances::<Ipv4Addr>(&[]).unwrap().is_empty());
        for unusable in [
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::new(224, 0, 0, 1),
        ] {
            assert!(
                source.instances(&[unusable]).unwrap().is_empty(),
                "클라이언트가 버리는 {unusable}"
            );
        }
    }

    #[test]
    fn an_announced_address_needs_a_listener_that_takes_it() {
        let lan4 = Ipv4Addr::new(192, 168, 1, 10);
        let other4 = Ipv4Addr::new(192, 168, 1, 11);
        let lan6: Ipv6Addr = "fd00::53".parse().unwrap();

        let exact = Source::new(&config("listen_doh = [\"192.168.1.10:443\"]")).unwrap();
        assert_eq!(exact.instances(&[lan4, other4]).unwrap()[0].addrs, [lan4]);

        let any4 = Source::new(&config("listen_doh = [\"0.0.0.0:443\"]")).unwrap();
        assert!(any4.instances(&[lan6]).unwrap().is_empty());

        // The unspecified IPv6 address takes IPv4 as well.
        let any6 = Source::new(&config("listen_doh = [\"[::]:443\"]")).unwrap();
        assert_eq!(any6.instances(&[lan6]).unwrap()[0].addrs, [lan6]);
        assert_eq!(any6.instances(&[lan4]).unwrap()[0].addrs, [lan4]);
    }

    #[test]
    fn dhcp4_instance_bytes() {
        let wire = instance(vec![
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(10, 0, 0, 1),
        ])
        .dhcp4()
        .unwrap();
        let mut expected = vec![0, 0, 0, 1, 18];
        expected.extend_from_slice(ADN);
        expected.extend_from_slice(&[8, 192, 168, 1, 10, 10, 0, 0, 1]);
        expected.extend_from_slice(DOH_PARAMS);
        let len = (expected.len() - 2) as u16;
        expected[..2].copy_from_slice(&len.to_be_bytes());
        assert_eq!(wire, expected);
        assert_eq!(usize::from(len), 4 + ADN.len() + 8 + DOH_PARAMS.len());
    }

    #[test]
    fn dhcp4_address_length_fits_one_byte() {
        let addrs = |count: u8| {
            (0..count)
                .map(|i| Ipv4Addr::new(10, 0, 0, i))
                .collect::<Vec<_>>()
        };
        let fits = instance(addrs(63))
            .dhcp4()
            .expect("252바이트는 한 바이트 길이에 들어감");
        assert_eq!(fits[2 + 2 + 1 + ADN.len()], 252);
        assert!(
            instance(addrs(64)).dhcp4().is_none(),
            "256바이트는 들어가지 않음"
        );
    }

    #[test]
    fn dhcp6_option_bytes() {
        let addr: Ipv6Addr = "fd00::53".parse().unwrap();
        let value = instance(vec![addr]).dhcp6().unwrap();
        let mut expected = vec![0, 1, 0, 18];
        expected.extend_from_slice(ADN);
        expected.extend_from_slice(&[0, 16]);
        expected.extend_from_slice(&addr.octets());
        expected.extend_from_slice(DOH_PARAMS);
        assert_eq!(value, expected);
        assert_eq!(value.len(), 6 + ADN.len() + 16 + DOH_PARAMS.len());
    }

    fn v6_addrs(count: u16) -> Vec<Ipv6Addr> {
        (0..count)
            .map(|i| Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, i))
            .collect()
    }

    #[test]
    fn dhcp6_option_length_fits_two_bytes() {
        // 6 + 18 + 16n + 25 bytes must stay within 65,535.
        assert_eq!(instance(v6_addrs(4092)).dhcp6().unwrap().len(), 65_521);
        assert!(instance(v6_addrs(4093)).dhcp6().is_none());
    }

    #[test]
    fn ra_option_bytes_are_padded_to_eight() {
        let addr: Ipv6Addr = "fd00::53".parse().unwrap();
        let option = instance(vec![addr]).ra(1_800).unwrap();
        let mut expected = vec![144, 10, 0, 1, 0, 0, 0x07, 0x08, 0, 18];
        expected.extend_from_slice(ADN);
        expected.extend_from_slice(&[0, 16]);
        expected.extend_from_slice(&addr.octets());
        expected.extend_from_slice(&[0, 25]);
        expected.extend_from_slice(DOH_PARAMS);
        assert_eq!(expected.len(), 73);
        expected.extend_from_slice(&[0; 7]);
        assert_eq!(option, expected);

        // A body of whole units gets no padding.
        let mut exact = instance(vec![addr]);
        exact.params = Box::from(SHORT_DOH_PARAMS);
        let option = exact.ra(1_800).unwrap();
        assert_eq!((option.len(), option[1]), (72, 9));
        assert_eq!(&option[48..], SHORT_DOH_PARAMS);
    }

    #[test]
    fn ra_option_length_fits_one_byte_of_units() {
        // 57 + 16n bytes must round up to at most 255 units of 8 bytes.
        let largest = instance(v6_addrs(123)).ra(0).unwrap();
        assert_eq!((largest.len(), largest[1]), (2_032, 254));
        assert!(instance(v6_addrs(124)).ra(0).is_none());
    }
}
