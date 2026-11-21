//! Generates the endpoint section of docs/API.md from the OpenAPI document and
//! compares. openapi_json is the truth for endpoints and their descriptions, and Role::allows for
//! who may call them. Between the two marker comments, API.md is generated from these; outside
//! them, people write it. Changing the spec or access rules without updating API.md fails this
//! test; rerun with ONETDNS_WRITE_API_DOC set to rewrite the section.

use onetdns_core::json::{self, Json};

use super::{openapi_json, Role};

const BEGIN: &str = "<!-- endpoints:begin -->";
const END: &str = "<!-- endpoints:end -->";
const DOC: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/API.md");
const WRITE_ENV: &str = "ONETDNS_WRITE_API_DOC";

struct Operation<'a> {
    /// Uppercase.
    method: String,
    /// Path template.
    path: &'a str,
    spec: &'a Json,
}

/// Object fields in written order; empty when missing or not an object.
fn fields(value: Option<&Json>) -> &[(String, Json)] {
    match value {
        Some(Json::Obj(fields)) => fields,
        _ => &[],
    }
}

/// Empty when missing or not an array.
fn items(value: Option<&Json>) -> &[Json] {
    value.and_then(Json::as_array).unwrap_or(&[])
}

fn text<'a>(value: &'a Json, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Json::as_str)
}

/// GitHub reads angle brackets as HTML tags and drops them, and a vertical bar splits table cells.
fn prose(raw: &str) -> String {
    raw.replace('|', "\\|")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Compact JSON goes in as code, anything else as prose.
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

/// Strings without quotes, integers without a decimal point.
fn literal(value: &Json) -> String {
    match value {
        Json::Str(text) => text.clone(),
        other => other
            .as_u64()
            .map_or_else(|| other.to_text(), |number| number.to_string()),
    }
}

/// Appends allowed values and minimum length when present.
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

/// Anyone for operations with empty security; otherwise Role::allows decides.
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

/// Fails unless the operation has exactly one tag.
fn tag_of<'a>(operation: &Operation<'a>) -> &'a str {
    match items(operation.spec.get("tags")) {
        [Json::Str(tag)] => tag,
        _ => panic!(
            "{} {} 에 태그가 정확히 하나 있어야 합니다",
            operation.method, operation.path
        ),
    }
}

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

/// An object with fields becomes a table, anything else one line.
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

/// Summary and access are in the table at the head of the section.
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

/// One section per tag in spec order, each with a list table and per-operation details. Operations
/// with no tag or several, undeclared tags, and unused tags fail; allowing any would let an
/// operation drop out of the document silently.
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
fn api_reference_matches_the_openapi_document() {
    let current = std::fs::read_to_string(DOC)
        .expect("docs/API.md 를 읽지 못했습니다")
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
