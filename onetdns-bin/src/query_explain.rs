//! Verdict preview and explanation for the management API.

use std::net::Ipv4Addr;

use onetdns_config::{BackendKind, Config};

use crate::native_config::qtype_numbers;
use crate::{authority_sources_configured, localtime, native};

/// Without sending a query.
pub(crate) fn simulate_policy(
    policy: &onetdns_policy::PolicyEngine,
    filter: &onetdns_filter::SharedFilter,
    body: &str,
) -> String {
    use onetdns_core::{ClientInfo, FilterEngine, FilterVerdict, Transport};
    let j = onetdns_core::json::parse(body).unwrap_or(onetdns_core::json::Json::Null);
    let gets = |k: &str, d: &str| -> String {
        j.get(k)
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| d.to_string())
    };
    let client: std::net::IpAddr = gets("client", "127.0.0.1")
        .parse()
        .unwrap_or(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST));

    let client_id = j
        .get("client_id")
        .and_then(|v| v.as_str())
        .map(String::from);
    let qname = gets("qname", "");
    if qname.is_empty() {
        return "{\"error\":\"qname is required\"}".to_string();
    }
    let Some(qtype) = requested_qtype(&gets("qtype", "A")) else {
        return "{\"error\":\"qtype is malformed\"}".to_string();
    };

    let name = match onetdns_proto::Name::from_str(&qname) {
        Ok(n) => n,
        Err(_) => return "{\"error\":\"qname is malformed\"}".to_string(),
    };

    let Some(policy_qname) = native::normalized_text_name(&name) else {
        return "{\"error\":\"Names that cannot be written in UTF-8 are excluded from policy evaluation\"}"
            .to_string();
    };

    let now = std::time::SystemTime::now();
    let pin = onetdns_policy::PolicyInput {
        client,
        qname: &policy_qname,
        qtype,
        unix_time: localtime::unix_seconds(now),
        local_minute_of_week: localtime::local_minute_of_week(now),
        transport: onetdns_policy::QueryTransport::Do53Udp,
        client_id: None,
        authenticated: false,
    };
    let pol = match policy.evaluate(&pin) {
        onetdns_policy::Action::Continue => "continue".to_string(),
        onetdns_policy::Action::Allow => "allow".to_string(),
        onetdns_policy::Action::Block => "block".to_string(),
        onetdns_policy::Action::Refuse => "refuse".to_string(),
        onetdns_policy::Action::Rewrite(ip) => format!("rewrite:{ip}"),
    };
    let ci = ClientInfo {
        source_ip: client,
        client_id,
        transport: Transport::Do53Udp,
        authenticated: false,
    };

    let exp = filter
        .load()
        .explain(&name, onetdns_proto::RecordType(qtype), &ci);
    let flt = match &exp.verdict {
        FilterVerdict::Allow => "allow",
        FilterVerdict::Block(_) | FilterVerdict::Drop => "block",
        FilterVerdict::Rewrite(_) => "rewrite",
    };
    let stage = exp.stage.as_str();
    let matched_json = match &exp.matched {
        Some(m) => onetdns_core::json::escape(m),
        None => "null".to_string(),
    };
    let list_json = match &exp.source {
        Some(list) => onetdns_core::json::escape(list),
        None => "null".to_string(),
    };

    let decision = if pol != "continue" {
        pol.clone()
    } else {
        flt.to_string()
    };
    format!(
        "{{\"policy\":{},\"filter\":{},\"filter_stage\":{},\"filter_matched\":{matched_json},\"filter_list\":{list_json},\"decision\":{}}}",
        onetdns_core::json::escape(&pol),
        onetdns_core::json::escape(flt),
        onetdns_core::json::escape(stage),
        onetdns_core::json::escape(&decision),
    )
}

pub(crate) fn backend_label(kind: BackendKind) -> &'static str {
    match kind {
        BackendKind::Recurse => "recurse",
        BackendKind::Forward => "forward",
        BackendKind::Split => "split",
    }
}

/// The backend and upstreams come from the config at call time; values captured at boot would
/// explain the old path after a config change.
///
/// `cfg` and `zones` are the ones in effect now.
pub(crate) fn explain_query(
    policy: &onetdns_policy::PolicyEngine,
    filter: &onetdns_filter::SharedFilter,
    cfg: &Config,
    zones: &onetdns_authority::ZoneStore,
    body: &str,
) -> String {
    use onetdns_core::{ClientInfo, FilterEngine, FilterVerdict, Transport};
    let esc = onetdns_core::json::escape;
    let j = onetdns_core::json::parse(body).unwrap_or(onetdns_core::json::Json::Null);
    let gets = |k: &str, d: &str| -> String {
        j.get(k)
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| d.to_string())
    };
    let client: std::net::IpAddr = gets("client", "127.0.0.1")
        .parse()
        .unwrap_or(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST));
    let client_id = j
        .get("client_id")
        .and_then(|v| v.as_str())
        .map(String::from);
    let qname = gets("qname", "");
    if qname.is_empty() {
        return "{\"error\":\"qname is required\"}".to_string();
    }
    let Some(qtype) = requested_qtype(&gets("qtype", "A")) else {
        return "{\"error\":\"qtype is malformed\"}".to_string();
    };
    let name = match onetdns_proto::Name::from_str(&qname) {
        Ok(n) => n,
        Err(_) => return "{\"error\":\"qname is malformed\"}".to_string(),
    };
    let ci = ClientInfo {
        source_ip: client,
        client_id: client_id.clone(),
        transport: Transport::Do53Udp,
        authenticated: false,
    };

    let Some(policy_qname) = native::normalized_text_name(&name) else {
        return "{\"error\":\"Names that cannot be written in UTF-8 are excluded from policy evaluation\"}"
            .to_string();
    };
    let now = std::time::SystemTime::now();
    let pin = onetdns_policy::PolicyInput {
        client,
        qname: &policy_qname,
        qtype,
        unix_time: localtime::unix_seconds(now),
        local_minute_of_week: localtime::local_minute_of_week(now),
        transport: onetdns_policy::QueryTransport::Do53Udp,
        client_id: client_id.as_deref(),
        authenticated: false,
    };
    let pol = match policy.evaluate(&pin) {
        onetdns_policy::Action::Continue => "continue".to_string(),
        onetdns_policy::Action::Allow => "allow".to_string(),
        onetdns_policy::Action::Block => "block".to_string(),
        onetdns_policy::Action::Refuse => "refuse".to_string(),
        onetdns_policy::Action::Rewrite(ip) => format!("rewrite:{ip}"),
    };

    let eng = filter.load();
    let exp = eng.explain(&name, onetdns_proto::RecordType(qtype), &ci);
    let flt = match &exp.verdict {
        FilterVerdict::Allow => "allow",
        FilterVerdict::Block(_) | FilterVerdict::Drop => "block",
        FilterVerdict::Rewrite(_) => "rewrite",
    };
    let stage = exp.stage.as_str();
    let matched_json = exp
        .matched
        .as_deref()
        .map(esc)
        .unwrap_or_else(|| "null".to_string());
    let list_json = exp
        .source
        .as_deref()
        .map(esc)
        .unwrap_or_else(|| "null".to_string());
    let safe_search = eng.client_safe_search(&ci);

    let decision = if pol != "continue" {
        pol.clone()
    } else {
        flt.to_string()
    };
    // A policy action skips the filter, so a dropped query only comes from one the policy passed
    // on.
    let dropped = pol == "continue" && matches!(exp.verdict, FilterVerdict::Drop);
    let rcode = match (&exp.verdict, decision.as_str()) {
        (_, "refuse") => "REFUSED".to_string(),
        _ if dropped => "DROPPED".to_string(),
        (FilterVerdict::Block(response), "block") if pol == "continue" => native::rcode_str(
            native::block_rcode(response, onetdns_proto::RecordType(qtype)),
        )
        .into_owned(),
        (_, "block") => "NXDOMAIN".to_string(),
        _ => "NOERROR".to_string(),
    };

    let mut stages: Vec<String> = Vec::new();
    if pol != "continue" {
        stages.push(format!("{{\"stage\":\"policy\",\"action\":{}}}", esc(&pol)));
    }
    stages.push(format!(
        "{{\"stage\":{},\"rule\":{matched_json}}}",
        esc(&format!("filter:{stage}"))
    ));

    let backend = backend_label(cfg.backend);
    let authority = authority_sources_configured(cfg)
        .then(|| zones.zone_for(&name))
        .flatten()
        .map(|zone| zone.origin().to_ascii_lower());
    let (route, resolution) = match decision.as_str() {
        "allow" | "continue" => match &authority {
            Some(origin) => ("authority", format!("local authoritative zone {origin}")),
            None => (
                backend,
                match cfg.backend {
                    BackendKind::Recurse => "recursive root resolution".to_string(),
                    BackendKind::Split => "split (forward/recurse by zone)".to_string(),
                    BackendKind::Forward => {
                        let upstreams: Vec<String> = cfg
                            .upstreams
                            .iter()
                            .map(|ip| ip.to_string())
                            .chain(cfg.upstream_urls.iter().cloned())
                            .collect();
                        format!("forward to [{}]", upstreams.join(", "))
                    }
                },
            ),
        },
        "rewrite" => ("rewrite", "answered by rewrite rule".to_string()),
        d if d.starts_with("rewrite:") => ("rewrite", "answered by policy rewrite".to_string()),
        "refuse" => ("refused", "refused before resolution".to_string()),
        _ if dropped => (
            "blocked",
            "dropped before resolution without a response".to_string(),
        ),
        _ => ("blocked", "blocked before resolution".to_string()),
    };
    let ss = safe_search
        .map(|b| b.to_string())
        .unwrap_or_else(|| "null".to_string());
    let cid = client_id
        .as_deref()
        .map(esc)
        .unwrap_or_else(|| "null".to_string());

    format!(
        "{{\"client\":{},\"client_id\":{cid},\"qname\":{qn},\"qtype\":{qt},\
\"decision\":{},\"rcode\":{},\
\"policy\":{},\"filter\":{},\"filter_stage\":{},\"filter_matched\":{matched_json},\
\"filter_list\":{list_json},\"client_safe_search\":{ss},\"matched\":[{matched_arr}],\
\"backend\":{},\"route\":{},\"dnssec\":{dnssec},\"resolution\":{},\
\"note\":{}}}",
        esc(&client.to_string()),
        esc(&decision),
        esc(&rcode),
        esc(&pol),
        esc(flt),
        esc(stage),
        esc(backend),
        esc(route),
        esc(&resolution),
        esc("This is a preview; the cache, upstream DNS servers, and DNSSEC validation were not consulted"),
        qn = esc(&qname),
        qt = esc(&qtype_text(qtype)),
        matched_arr = stages.join(","),
        dnssec = cfg.dnssec_validation_active(),
    )
}

/// Falling back to A for an unknown name would explain a different type without an error, so it is
/// a format error, like a bad qname. None when unreadable.
fn requested_qtype(text: &str) -> Option<u16> {
    qtype_numbers(&[text.to_string()]).first().copied()
}

/// The same mnemonic form the request takes, so the dashboard can show it as is. Types without one
/// use the RFC 3597 TYPEnnn form, since UNKNOWN would lose the number.
pub(crate) fn qtype_text(qtype: u16) -> String {
    let name = onetdns_proto::RecordType(qtype).name();
    if name == "UNKNOWN" {
        format!("TYPE{qtype}")
    } else {
        name.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use onetdns_config::Config;

    #[test]
    /// The block rcode follows the configured block mode, and a name in a local zone is answered by
    /// the zone, not forwarded; an explanation that differs would contradict the real response on
    /// the same screen.
    fn explain_matches_block_response_and_local_zone() {
        let policy =
            onetdns_policy::PolicyEngine::new(onetdns_policy::RuleEngine::new(vec![]), vec![]);
        let filter = |response| {
            onetdns_filter::SharedFilter::from_pointee(onetdns_filter::build_from_str(
                "||ads.example^",
                "",
                response,
            ))
        };
        let dir = std::env::temp_dir().to_string_lossy().replace('\\', "/");
        let cfg = |backend: &str| {
            Config::from_toml_str(&format!(
                "backend = \"{backend}\"\nupstreams = [\"192.0.2.1\"]\nzones_dir = \"{dir}\"\n"
            ))
            .unwrap()
        };
        let mut zones = onetdns_authority::ZoneStore::new();
        zones.add(
            onetdns_authority::parse_zone(
                "$ORIGIN d.test.\n@ 300 IN SOA ns1 h 1 3600 600 86400 300\n@ 300 IN NS ns1\nwww 300 IN A 192.0.2.10\n",
                "d.test",
            )
            .unwrap(),
        );
        let ask = |flt: &onetdns_filter::SharedFilter, cfg: &Config, qname: &str| {
            let out = explain_query(
                &policy,
                flt,
                cfg,
                &zones,
                &format!("{{\"qname\":\"{qname}\"}}"),
            );
            let j = onetdns_core::json::parse(&out).unwrap();
            let field = |k: &str| j.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
            (field("rcode"), field("route"))
        };
        let forward = cfg("forward");

        let zero = filter(onetdns_core::BlockResponse::ZeroIp);
        assert_eq!(
            ask(&zero, &forward, "ads.example"),
            ("NOERROR".to_string(), "blocked".to_string())
        );
        let nx = filter(onetdns_core::BlockResponse::NxDomain);
        assert_eq!(
            ask(&nx, &forward, "ads.example"),
            ("NXDOMAIN".to_string(), "blocked".to_string())
        );
        assert_eq!(ask(&nx, &forward, "www.d.test").1, "authority");
        assert_eq!(ask(&nx, &forward, "other.example").1, "forward");
        assert_eq!(ask(&nx, &cfg("recurse"), "other.example").1, "recurse");
    }

    #[test]
    /// An explanation with the block rcode would make the operator expect an answer that never
    /// comes. A name the policy decides skips the filter, so it must not be explained as no
    /// response.
    fn explain_reports_noresponse_as_dropped() {
        let filter = onetdns_filter::SharedFilter::from_pointee(onetdns_filter::build_from_str(
            "||quiet.example^$dnsrewrite=NORESPONSE",
            "",
            onetdns_core::BlockResponse::NxDomain,
        ));
        let cfg =
            Config::from_toml_str("backend = \"forward\"\nupstreams = [\"192.0.2.1\"]\n").unwrap();
        let zones = onetdns_authority::ZoneStore::new();
        let ask = |policy: &onetdns_policy::PolicyEngine| {
            let out = explain_query(
                policy,
                &filter,
                &cfg,
                &zones,
                "{\"qname\":\"quiet.example\"}",
            );
            let j = onetdns_core::json::parse(&out).unwrap();
            let field = |k: &str| j.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
            (
                field("decision"),
                field("rcode"),
                field("filter_stage"),
                field("resolution"),
            )
        };

        let open =
            onetdns_policy::PolicyEngine::new(onetdns_policy::RuleEngine::new(vec![]), vec![]);
        let (decision, rcode, stage, resolution) = ask(&open);
        assert_eq!(decision, "block");
        assert_eq!(rcode, "DROPPED");
        assert_eq!(stage, "noresponse");
        assert!(resolution.contains("without a response"), "{resolution}");
        let simulated = simulate_policy(&open, &filter, "{\"qname\":\"quiet.example\"}");
        assert!(
            simulated.contains("\"filter\":\"block\"")
                && simulated.contains("\"filter_stage\":\"noresponse\""),
            "{simulated}"
        );

        let allowing = onetdns_policy::PolicyEngine::new(
            onetdns_policy::RuleEngine::new(vec![onetdns_policy::Rule::new(
                onetdns_policy::Action::Allow,
            )
            .with_suffixes(&["quiet.example".to_string()])]),
            vec![],
        );
        let (decision, rcode, _, _) = ask(&allowing);
        assert_eq!(decision, "allow");
        assert_eq!(
            rcode, "NOERROR",
            "정책이 허용한 이름을 무응답으로 설명했습니다"
        );
    }

    #[test]
    /// Otherwise the preview would lie.
    fn simulate_policy_normalizes_qname_like_live_path() {
        let policy = onetdns_policy::PolicyEngine::new(
            onetdns_policy::RuleEngine::new(vec![onetdns_policy::Rule::new(
                onetdns_policy::Action::Block,
            )
            .with_suffixes(&["blocked.example".to_string()])]),
            vec![],
        );
        let filter = onetdns_filter::SharedFilter::from_pointee(
            onetdns_filter::BlockEngine::empty(onetdns_core::BlockResponse::NxDomain),
        );
        let out = simulate_policy(&policy, &filter, "{\"qname\":\"Sub.Blocked.EXAMPLE\"}");
        assert!(
            out.contains("\"policy\":\"block\""),
            "대소문자 섞인 입력도 실경로처럼 소문자 정규화 후 평가: {out}"
        );
    }

    #[test]
    fn simulate_policy_honors_client_id_like_explain() {
        let policy =
            onetdns_policy::PolicyEngine::new(onetdns_policy::RuleEngine::new(vec![]), vec![]);
        let filter = onetdns_filter::SharedFilter::from_pointee(
            onetdns_filter::build_from_str("", "", onetdns_core::BlockResponse::NxDomain)
                .with_clients(vec![onetdns_filter::ClientPolicy::with_options(
                    vec![],
                    vec!["kid".to_string()],
                    vec![],
                    &["tracker.example".to_string()],
                    &[],
                    false,
                    None,
                )]),
        );
        let without = simulate_policy(&policy, &filter, "{\"qname\":\"tracker.example\"}");
        let with_id = simulate_policy(
            &policy,
            &filter,
            "{\"qname\":\"tracker.example\",\"client_id\":\"kid\"}",
        );
        assert!(
            !without.contains("\"filter\":\"block"),
            "클라이언트 ID가 없으면 그 클라이언트 규칙은 적용되지 않는다: {without}"
        );
        assert!(
            with_id.contains("\"filter\":\"block"),
            "클라이언트 ID를 주면 그 클라이언트 규칙이 반영돼야 한다: {with_id}"
        );
    }
}
