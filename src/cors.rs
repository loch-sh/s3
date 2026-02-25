use quick_xml::Reader;
use quick_xml::events::Event;
use serde::{Deserialize, Serialize};

use crate::error::S3Error;

/// CORS configuration for a bucket (stored as JSON internally).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfiguration {
    pub rules: Vec<CorsRule>,
}

/// A single CORS rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsRule {
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    #[serde(default)]
    pub allowed_headers: Vec<String>,
    #[serde(default)]
    pub expose_headers: Vec<String>,
    #[serde(default)]
    pub max_age_seconds: Option<u32>,
}

impl CorsConfiguration {
    /// Find the first rule that matches the given origin and method.
    pub fn find_matching_rule(&self, origin: &str, method: &str) -> Option<&CorsRule> {
        self.rules
            .iter()
            .find(|rule| rule.matches_origin(origin) && rule.matches_method(method))
    }

    /// Find the first rule that matches the given origin (any method).
    pub fn find_rule_for_origin(&self, origin: &str) -> Option<&CorsRule> {
        self.rules.iter().find(|rule| rule.matches_origin(origin))
    }
}

impl CorsRule {
    fn matches_origin(&self, origin: &str) -> bool {
        self.allowed_origins
            .iter()
            .any(|o| o == "*" || o == origin || wildcard_match(o, origin))
    }

    fn matches_method(&self, method: &str) -> bool {
        self.allowed_methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(method))
    }
}

/// Simple wildcard matching (single "*" in the pattern).
fn wildcard_match(pattern: &str, value: &str) -> bool {
    if let Some(pos) = pattern.find('*') {
        let prefix = &pattern[..pos];
        let suffix = &pattern[pos + 1..];
        value.starts_with(prefix) && value.ends_with(suffix)
    } else {
        pattern == value
    }
}

/// Parse CORS XML input into our internal representation.
/// Uses event-based parsing for reliability with repeated elements.
pub fn parse_cors_xml(xml_bytes: &[u8]) -> Result<CorsConfiguration, S3Error> {
    let xml_str = std::str::from_utf8(xml_bytes).map_err(|_| S3Error::MalformedXML)?;
    let mut reader = Reader::from_str(xml_str);

    let mut rules = Vec::new();
    let mut in_rule = false;
    let mut current_element = String::new();

    // Current rule being built
    let mut allowed_origins = Vec::new();
    let mut allowed_methods = Vec::new();
    let mut allowed_headers = Vec::new();
    let mut expose_headers = Vec::new();
    let mut max_age_seconds: Option<u32> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if name == "CORSRule" {
                    in_rule = true;
                    allowed_origins.clear();
                    allowed_methods.clear();
                    allowed_headers.clear();
                    expose_headers.clear();
                    max_age_seconds = None;
                } else if in_rule {
                    current_element = name;
                }
            }
            Ok(Event::Text(ref e)) => {
                if in_rule && !current_element.is_empty() {
                    let text = e.decode().map_err(|_| S3Error::MalformedXML)?.to_string();
                    match current_element.as_str() {
                        "AllowedOrigin" => allowed_origins.push(text),
                        "AllowedMethod" => allowed_methods.push(text),
                        "AllowedHeader" => allowed_headers.push(text),
                        "ExposeHeader" => expose_headers.push(text),
                        "MaxAgeSeconds" => {
                            max_age_seconds =
                                Some(text.parse().map_err(|_| S3Error::MalformedXML)?);
                        }
                        _ => {}
                    }
                }
            }
            Ok(Event::End(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if name == "CORSRule" && in_rule {
                    if allowed_origins.is_empty() || allowed_methods.is_empty() {
                        return Err(S3Error::MalformedXML);
                    }
                    rules.push(CorsRule {
                        allowed_origins: allowed_origins.clone(),
                        allowed_methods: allowed_methods.clone(),
                        allowed_headers: allowed_headers.clone(),
                        expose_headers: expose_headers.clone(),
                        max_age_seconds,
                    });
                    in_rule = false;
                }
                current_element.clear();
            }
            Ok(Event::Eof) => break,
            Err(_) => return Err(S3Error::MalformedXML),
            _ => {}
        }
    }

    if rules.is_empty() {
        return Err(S3Error::MalformedXML);
    }

    Ok(CorsConfiguration { rules })
}

/// XML output structures for GET /{bucket}?cors.
#[derive(Serialize)]
#[serde(rename = "CORSConfiguration")]
struct CorsConfigurationOutput {
    #[serde(rename = "CORSRule")]
    rules: Vec<CorsRuleOutput>,
}

#[derive(Serialize)]
struct CorsRuleOutput {
    #[serde(rename = "AllowedOrigin")]
    allowed_origins: Vec<String>,
    #[serde(rename = "AllowedMethod")]
    allowed_methods: Vec<String>,
    #[serde(rename = "AllowedHeader", skip_serializing_if = "Vec::is_empty")]
    allowed_headers: Vec<String>,
    #[serde(rename = "ExposeHeader", skip_serializing_if = "Vec::is_empty")]
    expose_headers: Vec<String>,
    #[serde(rename = "MaxAgeSeconds", skip_serializing_if = "Option::is_none")]
    max_age_seconds: Option<u32>,
}

/// Convert a CorsConfiguration to XML string.
pub fn to_cors_xml(config: &CorsConfiguration) -> String {
    let output = CorsConfigurationOutput {
        rules: config
            .rules
            .iter()
            .map(|r| CorsRuleOutput {
                allowed_origins: r.allowed_origins.clone(),
                allowed_methods: r.allowed_methods.clone(),
                allowed_headers: r.allowed_headers.clone(),
                expose_headers: r.expose_headers.clone(),
                max_age_seconds: r.max_age_seconds,
            })
            .collect(),
    };
    crate::xml::to_xml(&output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cors_xml() {
        let xml = r#"<CORSConfiguration>
            <CORSRule>
                <AllowedOrigin>https://example.com</AllowedOrigin>
                <AllowedMethod>GET</AllowedMethod>
                <AllowedMethod>PUT</AllowedMethod>
                <AllowedHeader>*</AllowedHeader>
                <MaxAgeSeconds>3600</MaxAgeSeconds>
                <ExposeHeader>ETag</ExposeHeader>
            </CORSRule>
        </CORSConfiguration>"#;

        let config = parse_cors_xml(xml.as_bytes()).unwrap();
        assert_eq!(config.rules.len(), 1);
        let rule = &config.rules[0];
        assert_eq!(rule.allowed_origins, vec!["https://example.com"]);
        assert_eq!(rule.allowed_methods, vec!["GET", "PUT"]);
        assert_eq!(rule.allowed_headers, vec!["*"]);
        assert_eq!(rule.expose_headers, vec!["ETag"]);
        assert_eq!(rule.max_age_seconds, Some(3600));
    }

    #[test]
    fn test_parse_multiple_rules() {
        let xml = r#"<CORSConfiguration>
            <CORSRule>
                <AllowedOrigin>https://a.com</AllowedOrigin>
                <AllowedMethod>GET</AllowedMethod>
            </CORSRule>
            <CORSRule>
                <AllowedOrigin>https://b.com</AllowedOrigin>
                <AllowedMethod>PUT</AllowedMethod>
            </CORSRule>
        </CORSConfiguration>"#;

        let config = parse_cors_xml(xml.as_bytes()).unwrap();
        assert_eq!(config.rules.len(), 2);
    }

    #[test]
    fn test_parse_empty_rules_fails() {
        let xml = r#"<CORSConfiguration></CORSConfiguration>"#;
        assert!(parse_cors_xml(xml.as_bytes()).is_err());
    }

    #[test]
    fn test_origin_matching() {
        let rule = CorsRule {
            allowed_origins: vec!["https://example.com".to_string()],
            allowed_methods: vec!["GET".to_string()],
            allowed_headers: vec![],
            expose_headers: vec![],
            max_age_seconds: None,
        };
        assert!(rule.matches_origin("https://example.com"));
        assert!(!rule.matches_origin("https://evil.com"));
    }

    #[test]
    fn test_wildcard_origin() {
        let rule = CorsRule {
            allowed_origins: vec!["*".to_string()],
            allowed_methods: vec!["GET".to_string()],
            allowed_headers: vec![],
            expose_headers: vec![],
            max_age_seconds: None,
        };
        assert!(rule.matches_origin("https://anything.com"));
    }

    #[test]
    fn test_pattern_wildcard_origin() {
        let rule = CorsRule {
            allowed_origins: vec!["https://*.example.com".to_string()],
            allowed_methods: vec!["GET".to_string()],
            allowed_headers: vec![],
            expose_headers: vec![],
            max_age_seconds: None,
        };
        assert!(rule.matches_origin("https://sub.example.com"));
        assert!(!rule.matches_origin("https://evil.com"));
    }

    #[test]
    fn test_method_matching() {
        let rule = CorsRule {
            allowed_origins: vec!["*".to_string()],
            allowed_methods: vec!["GET".to_string(), "PUT".to_string()],
            allowed_headers: vec![],
            expose_headers: vec![],
            max_age_seconds: None,
        };
        assert!(rule.matches_method("GET"));
        assert!(rule.matches_method("get"));
        assert!(rule.matches_method("PUT"));
        assert!(!rule.matches_method("DELETE"));
    }

    #[test]
    fn test_find_matching_rule() {
        let config = CorsConfiguration {
            rules: vec![
                CorsRule {
                    allowed_origins: vec!["https://a.com".to_string()],
                    allowed_methods: vec!["GET".to_string()],
                    allowed_headers: vec![],
                    expose_headers: vec![],
                    max_age_seconds: None,
                },
                CorsRule {
                    allowed_origins: vec!["https://b.com".to_string()],
                    allowed_methods: vec!["PUT".to_string()],
                    allowed_headers: vec![],
                    expose_headers: vec![],
                    max_age_seconds: None,
                },
            ],
        };
        assert!(config.find_matching_rule("https://a.com", "GET").is_some());
        assert!(config.find_matching_rule("https://b.com", "PUT").is_some());
        assert!(config.find_matching_rule("https://a.com", "PUT").is_none());
        assert!(config.find_matching_rule("https://c.com", "GET").is_none());
    }
}
