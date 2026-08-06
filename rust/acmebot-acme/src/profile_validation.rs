use std::collections::HashMap;

use crate::models::AcmeDirectoryResource;

/// Mirrors `Acmebot.Acme.AcmeProfileValidation`.
pub fn get_advertised_profiles(directory: &AcmeDirectoryResource) -> HashMap<String, String> {
    directory
        .metadata
        .as_ref()
        .map(|m| m.profiles.clone())
        .unwrap_or_default()
}

pub fn is_profile_advertised(directory: &AcmeDirectoryResource, profile: &str) -> bool {
    get_advertised_profiles(directory).contains_key(profile)
}

pub fn get_profile_description(directory: &AcmeDirectoryResource, profile: &str) -> Option<String> {
    get_advertised_profiles(directory).get(profile).cloned()
}

pub fn ensure_profile_is_advertised(
    directory: &AcmeDirectoryResource,
    profile: &str,
) -> Result<(), String> {
    if is_profile_advertised(directory, profile) {
        Ok(())
    } else {
        Err(format!(
            "The ACME server does not advertise the '{profile}' profile."
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::AcmeDirectoryMetadata;
    use url::Url;

    fn directory_with_profiles(profiles: HashMap<String, String>) -> AcmeDirectoryResource {
        AcmeDirectoryResource {
            new_nonce: Url::parse("https://example.com/new-nonce").unwrap(),
            new_account: Url::parse("https://example.com/new-account").unwrap(),
            new_order: Url::parse("https://example.com/new-order").unwrap(),
            new_authorization: None,
            revoke_certificate: None,
            key_change: None,
            renewal_info: None,
            metadata: Some(AcmeDirectoryMetadata {
                profiles,
                ..Default::default()
            }),
            additional_data: HashMap::new(),
        }
    }

    #[test]
    fn returns_empty_map_when_metadata_is_missing() {
        let directory = AcmeDirectoryResource {
            new_nonce: Url::parse("https://example.com/new-nonce").unwrap(),
            new_account: Url::parse("https://example.com/new-account").unwrap(),
            new_order: Url::parse("https://example.com/new-order").unwrap(),
            new_authorization: None,
            revoke_certificate: None,
            key_change: None,
            renewal_info: None,
            metadata: None,
            additional_data: HashMap::new(),
        };

        assert!(get_advertised_profiles(&directory).is_empty());
        assert!(!is_profile_advertised(&directory, "shortlived"));
        assert!(ensure_profile_is_advertised(&directory, "shortlived").is_err());
    }

    #[test]
    fn detects_advertised_profile() {
        let mut profiles = HashMap::new();
        profiles.insert("shortlived".to_owned(), "short-lived certificates".to_owned());
        let directory = directory_with_profiles(profiles);

        assert!(is_profile_advertised(&directory, "shortlived"));
        assert_eq!(
            get_profile_description(&directory, "shortlived").as_deref(),
            Some("short-lived certificates")
        );
        assert!(ensure_profile_is_advertised(&directory, "shortlived").is_ok());
        assert!(ensure_profile_is_advertised(&directory, "other").is_err());
    }
}
