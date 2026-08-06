use url::Url;

use crate::models::AcmeLinkHeader;

/// Mirrors `Acmebot.Acme.Internal.AcmeHeaderParser`.
///
/// Parses RFC 8288 `Link` header values, including comma-separated multi-link values
/// and angle-bracket/quote-aware splitting so commas inside URIs or quoted parameters
/// don't break the link boundary.
pub fn parse_link_headers<'a>(values: impl IntoIterator<Item = &'a str>) -> Vec<AcmeLinkHeader> {
    let mut links = Vec::new();

    for value in values {
        for link_value in split_header_value(value, ',') {
            let parts = split_header_value(&link_value, ';');

            let Some(uri_part) = parts.first() else {
                continue;
            };

            if !uri_part.starts_with('<') || !uri_part.ends_with('>') {
                continue;
            }

            let Ok(uri) = Url::parse(&uri_part[1..uri_part.len() - 1]) else {
                continue;
            };

            let mut relation = None;
            let mut media_type = None;
            let mut title = None;

            for parameter in &parts[1..] {
                let Some(separator_index) = parameter.find('=') else {
                    continue;
                };

                if separator_index == 0 {
                    continue;
                }

                let name = parameter[..separator_index].trim();
                let raw_value = parameter[separator_index + 1..].trim().trim_matches('"');

                match name {
                    "rel" => relation = Some(raw_value.to_owned()),
                    "type" => media_type = Some(raw_value.to_owned()),
                    "title" => title = Some(raw_value.to_owned()),
                    _ => {}
                }
            }

            links.push(AcmeLinkHeader {
                uri,
                relation,
                media_type,
                title,
            });
        }
    }

    links
}

fn split_header_value(value: &str, separator: char) -> Vec<String> {
    let chars: Vec<char> = value.chars().collect();
    let mut parts = Vec::new();
    let mut start_index = 0;
    let mut in_quotes = false;
    let mut in_angle_brackets = false;

    for i in 0..chars.len() {
        let current = chars[i];

        if current == '"' && !is_escaped(&chars, i) {
            in_quotes = !in_quotes;
            continue;
        }

        if in_quotes {
            continue;
        }

        if current == '<' {
            in_angle_brackets = true;
            continue;
        }

        if current == '>' {
            in_angle_brackets = false;
            continue;
        }

        if current == separator && !in_angle_brackets {
            add_part(&chars, start_index, i, &mut parts);
            start_index = i + 1;
        }
    }

    add_part(&chars, start_index, chars.len(), &mut parts);
    parts
}

fn add_part(chars: &[char], start: usize, end: usize, parts: &mut Vec<String>) {
    let segment: String = chars[start..end].iter().collect();
    let trimmed = segment.trim();

    if !trimmed.is_empty() {
        parts.push(trimmed.to_owned());
    }
}

fn is_escaped(chars: &[char], index: usize) -> bool {
    let mut backslash_count = 0;
    let mut i = index;

    while i > 0 && chars[i - 1] == '\\' {
        backslash_count += 1;
        i -= 1;
    }

    backslash_count % 2 == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_link_with_rel() {
        let links = parse_link_headers(["<https://example.com/acme/new-nonce>; rel=\"index\""]);

        assert_eq!(links.len(), 1);
        assert_eq!(links[0].uri.as_str(), "https://example.com/acme/new-nonce");
        assert_eq!(links[0].relation.as_deref(), Some("index"));
    }

    #[test]
    fn parses_multiple_comma_separated_links() {
        let links = parse_link_headers([
            "<https://example.com/a>; rel=\"up\", <https://example.com/b>; rel=\"alternate\"",
        ]);

        assert_eq!(links.len(), 2);
        assert_eq!(links[0].relation.as_deref(), Some("up"));
        assert_eq!(links[1].relation.as_deref(), Some("alternate"));
        assert_eq!(links[1].uri.as_str(), "https://example.com/b");
    }

    #[test]
    fn ignores_malformed_entries() {
        let links = parse_link_headers(["not-a-link; rel=\"up\""]);

        assert!(links.is_empty());
    }

    #[test]
    fn parses_media_type_and_title() {
        let links = parse_link_headers([
            "<https://example.com/cert>; rel=\"alternate\"; type=\"application/pem-certificate-chain\"; title=\"cert\"",
        ]);

        assert_eq!(links.len(), 1);
        assert_eq!(
            links[0].media_type.as_deref(),
            Some("application/pem-certificate-chain")
        );
        assert_eq!(links[0].title.as_deref(), Some("cert"));
    }
}
