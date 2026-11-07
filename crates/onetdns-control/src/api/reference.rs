/*!
 * @brief 저장소 루트의 API.md 가운데 엔드포인트 절을 OpenAPI 문서에서 만들어 맞댄다.
 *
 * @details 엔드포인트와 그 설명은 openapi_json 이 정답이고, 누가 부를 수 있는지는 Role::allows 가
 *          정한다. API.md 에서 두 표지 주석 사이는 이 둘로 만든 글이고, 표지 바깥은 사람이 쓴다.
 *          명세나 권한 규칙을 바꾸고 API.md 를 그대로 두면 이 테스트가 실패한다. 환경 변수
 *          ONETDNS_WRITE_API_DOC 를 주고 다시 돌리면 그 절을 새로 쓴다.
 */

use onetdns_core::json::{self, Json};

use super::{openapi_json, Role};

/** @brief 만든 절이 시작하는 표지. */
const BEGIN: &str = "<!-- endpoints:begin -->";
/** @brief 만든 절이 끝나는 표지. */
const END: &str = "<!-- endpoints:end -->";
/** @brief 이 크레이트에서 본 API.md 의 경로. */
const DOC: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../API.md");
/** @brief 있으면 비교하지 않고 엔드포인트 절을 새로 쓰는 환경 변수. */
const WRITE_ENV: &str = "ONETDNS_WRITE_API_DOC";

/** @brief 명세의 연산 하나. */
struct Operation<'a> {
    /** @brief 대문자 HTTP 메서드. */
    method: String,
    /** @brief 경로 틀. */
    path: &'a str,
    /** @brief 명세의 연산 객체. */
    spec: &'a Json,
}

/** @brief 객체의 필드를 적힌 순서대로. 객체가 아니거나 없으면 빈 목록이다. */
fn fields(value: Option<&Json>) -> &[(String, Json)] {
    match value {
        Some(Json::Obj(fields)) => fields,
        _ => &[],
    }
}

/** @brief 배열의 원소. 배열이 아니거나 없으면 빈 목록이다. */
fn items(value: Option<&Json>) -> &[Json] {
    value.and_then(Json::as_array).unwrap_or(&[])
}

/** @brief 문자열 필드. */
fn text<'a>(value: &'a Json, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Json::as_str)
}

/**
 * @brief 본문과 표 칸에 넣는 글.
 * @details 꺾쇠는 GitHub 가 HTML 태그로 읽어 지우고, 세로 막대는 표 칸을 가른다.
 */
fn prose(raw: &str) -> String {
    raw.replace('|', "\\|")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/** @brief 응답 설명. 공백 없는 JSON 모양이면 코드로, 아니면 글로 넣는다. */
fn response_text(raw: &str) -> String {
    let shaped = raw.starts_with(['{', '['])
        && !raw.contains(char::is_whitespace)
        && !raw.contains(['`', '<', '>']);
    if shaped {
        format!("`{}`", raw.replace('|', "\\|"))
    } else {
        prose(raw)
    }
}

/** @brief 스키마에 적힌 값 하나. 문자열은 따옴표 없이, 정수는 소수점 없이 적는다. */
fn literal(value: &Json) -> String {
    match value {
        Json::Str(text) => text.clone(),
        other => other
            .as_u64()
            .map_or_else(|| other.to_text(), |number| number.to_string()),
    }
}

/** @brief 스키마의 형. 고를 수 있는 값과 길이 하한이 있으면 덧붙인다. */
fn type_name(schema: &Json) -> String {
    let options = items(schema.get("oneOf"));
    if !options.is_empty() {
        return options
            .iter()
            .map(type_name)
            .collect::<Vec<_>>()
            .join(" or ");
    }
    let mut name = match text(schema, "type") {
        Some("array") => match schema.get("items").and_then(|item| text(item, "type")) {
            Some(item) => format!("array of {item}s"),
            None => "array".to_string(),
        },
        Some(other) => other.to_string(),
        None => "any".to_string(),
    };
    let values = items(schema.get("enum"));
    if !values.is_empty() {
        let values: Vec<String> = values
            .iter()
            .map(|value| format!("`{}`", literal(value)))
            .collect();
        name.push_str(&format!(": {}", values.join(", ")));
    }
    if let Some(min) = schema.get("minLength").and_then(Json::as_u64) {
        name.push_str(&format!(", at least {min} characters"));
    }
    name
}

/** @brief 이 연산을 부를 수 있는 사람. 인증을 비운 연산은 아무나, 그 밖은 Role::allows 가 정한다. */
fn access(operation: &Operation) -> &'static str {
    let public = operation
        .spec
        .get("security")
        .and_then(Json::as_array)
        .is_some_and(<[Json]>::is_empty);
    if public {
        "none"
    } else if Role::ReadOnly.allows(&operation.method, operation.path) {
        "read-only"
    } else {
        "admin"
    }
}

/** @brief 연산이 단 태그 하나. 하나가 아니면 실패한다. */
fn tag_of<'a>(operation: &Operation<'a>) -> &'a str {
    match items(operation.spec.get("tags")) {
        [Json::Str(tag)] => tag,
        _ => panic!(
            "{} {} 에 태그가 정확히 하나 있어야 합니다",
            operation.method, operation.path
        ),
    }
}

/** @brief 경로 매개변수 표. */
fn render_parameters(out: &mut String, parameters: &[Json]) {
    out.push_str("| Parameter | In | Type |\n|---|---|---|\n");
    for parameter in parameters {
        let schema = parameter.get("schema").unwrap_or(&Json::Null);
        out.push_str(&format!(
            "| `{}` | {} | {} |\n",
            text(parameter, "name").unwrap_or(""),
            text(parameter, "in").unwrap_or(""),
            type_name(schema)
        ));
    }
    out.push('\n');
}

/** @brief 요청 본문. 필드가 적힌 객체는 표로, 그 밖은 한 줄로 적는다. */
fn render_body(out: &mut String, body: &Json) {
    for (media, content) in fields(body.get("content")) {
        let schema = content.get("schema").unwrap_or(&Json::Null);
        let properties = fields(schema.get("properties"));
        if properties.is_empty() {
            out.push_str(&format!(
                "Request body (`{media}`): {}.\n\n",
                type_name(schema)
            ));
        } else {
            let required: Vec<&str> = items(schema.get("required"))
                .iter()
                .filter_map(Json::as_str)
                .collect();
            out.push_str(&format!(
                "Request body (`{media}`):\n\n| Field | Type | Required |\n|---|---|---|\n"
            ));
            for (name, property) in properties {
                let needed = if required.contains(&name.as_str()) {
                    "yes"
                } else {
                    "no"
                };
                out.push_str(&format!(
                    "| `{name}` | {} | {needed} |\n",
                    type_name(property)
                ));
            }
            out.push('\n');
            if matches!(schema.get("additionalProperties"), Some(Json::Bool(false))) {
                out.push_str("Other fields are rejected.\n\n");
            }
        }
        if let Some(example) = schema.get("example") {
            out.push_str(&format!(
                "Example:\n\n```json\n{}\n```\n\n",
                example.to_text()
            ));
        }
    }
}

/** @brief 연산 하나의 자세한 설명. 요약과 권한은 절 머리의 표가 맡는다. */
fn render_operation(out: &mut String, operation: &Operation) {
    out.push_str(&format!(
        "#### `{} {}`\n\n",
        operation.method, operation.path
    ));
    if let Some(description) = text(operation.spec, "description") {
        out.push_str(&format!("{}\n\n", prose(description)));
    }
    let parameters = items(operation.spec.get("parameters"));
    if !parameters.is_empty() {
        render_parameters(out, parameters);
    }
    if let Some(body) = operation.spec.get("requestBody") {
        render_body(out, body);
    }
    out.push_str("| Status | Response |\n|---|---|\n");
    for (status, response) in fields(operation.spec.get("responses")) {
        out.push_str(&format!(
            "| {status} | {} |\n",
            response_text(text(response, "description").unwrap_or(""))
        ));
    }
    out.push('\n');
}

/**
 * @brief 엔드포인트 절. 명세에 적은 태그 순서대로 절을 나누고, 절마다 목록 표와 연산별 설명을 둔다.
 * @details 태그가 없거나 둘 이상인 연산, 선언하지 않은 태그, 쓰지 않는 태그는 실패로 본다. 하나라도
 *          허용하면 문서에서 조용히 빠지는 연산이 생긴다.
 */
fn render() -> String {
    let spec = json::parse(&openapi_json()).expect("OpenAPI 문서를 읽지 못했습니다");
    let operations: Vec<Operation> = fields(spec.get("paths"))
        .iter()
        .flat_map(|(path, item)| {
            fields(Some(item))
                .iter()
                .filter(|(method, _)| {
                    matches!(method.as_str(), "get" | "post" | "put" | "patch" | "delete")
                })
                .map(move |(method, spec)| Operation {
                    method: method.to_ascii_uppercase(),
                    path,
                    spec,
                })
        })
        .collect();
    let tags = items(spec.get("tags"));
    let declared: Vec<&str> = tags.iter().filter_map(|tag| text(tag, "name")).collect();
    for operation in &operations {
        let tag = tag_of(operation);
        assert!(
            declared.contains(&tag),
            "{} {} 의 태그 {tag} 가 선언되지 않았습니다",
            operation.method,
            operation.path
        );
    }

    let mut out = String::new();
    for tag in tags {
        let name = text(tag, "name").expect("태그 이름");
        let members: Vec<&Operation> = operations
            .iter()
            .filter(|operation| tag_of(operation) == name)
            .collect();
        assert!(!members.is_empty(), "태그 {name} 을 쓰는 연산이 없습니다");
        out.push_str(&format!("### {name}\n\n"));
        if let Some(description) = text(tag, "description") {
            out.push_str(&format!("{}\n\n", prose(description)));
        }
        out.push_str("| Method | Path | Access | Summary |\n|---|---|---|---|\n");
        for operation in &members {
            out.push_str(&format!(
                "| {} | `{}` | {} | {} |\n",
                operation.method,
                operation.path,
                access(operation),
                prose(text(operation.spec, "summary").unwrap_or(""))
            ));
        }
        out.push('\n');
        for operation in &members {
            render_operation(&mut out, operation);
        }
    }
    out
}

#[test]
/** @brief API.md 의 엔드포인트 절이 명세와 권한 규칙으로 만든 글과 같은지. */
fn api_reference_matches_the_openapi_document() {
    let current = std::fs::read_to_string(DOC)
        .expect("저장소 루트의 API.md 를 읽지 못했습니다")
        .replace("\r\n", "\n");
    let (head, rest) = current
        .split_once(BEGIN)
        .expect("API.md 에 시작 표지가 없습니다");
    let (_, tail) = rest.split_once(END).expect("API.md 에 끝 표지가 없습니다");
    let expected = format!("{head}{BEGIN}\n\n{}{END}{tail}", render());
    if std::env::var_os(WRITE_ENV).is_some() {
        std::fs::write(DOC, &expected).expect("API.md 를 쓰지 못했습니다");
        return;
    }
    let line = current
        .lines()
        .zip(expected.lines())
        .position(|(have, want)| have != want)
        .unwrap_or_else(|| current.lines().count().min(expected.lines().count()))
        + 1;
    assert!(
        current == expected,
        "API.md 의 {line}번째 줄부터 OpenAPI 문서와 다릅니다. {WRITE_ENV}=1 cargo test -p onetdns-control api::reference 로 다시 만드십시오"
    );
}
