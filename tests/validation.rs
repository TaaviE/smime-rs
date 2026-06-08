#[cfg(test)]
mod tests {
    use smime::SenderResolver;

    // SenderResolver tests - RFC 5751 Section 3.1

    #[test]
    fn no_address_match() {
        let mut r = SenderResolver::default();
        let (updated, _) = r.update(Some("alice@example.com"), Some("Alice"), &["bob@example.com".to_string()], &["Bob".to_string()]);
        assert!(!updated);
        assert_eq!(r.from_address, None);
        assert_eq!(r.from_comment, None);
    }

    #[test]
    fn address_and_comment_match() {
        let mut r = SenderResolver::default();
        let (updated, _) = r.update(Some("alice@example.com"), Some("Alice"), &["alice@example.com".to_string()], &["Alice".to_string()]);
        assert!(updated);
        assert_eq!(r.from_address, Some("alice@example.com".to_string()));
        assert_eq!(r.from_comment, Some("Alice".to_string()));
    }

    #[test]
    fn address_match_comment_mismatch() {
        let mut r = SenderResolver::default();
        let (updated, _) = r.update(Some("alice@example.com"), Some("Eve"), &["alice@example.com".to_string()], &["Alice".to_string()]);
        assert!(updated);
        assert_eq!(r.from_address, Some("alice@example.com".to_string()));
        assert_eq!(r.from_comment, None);
    }

    #[test]
    fn no_inner_address() {
        let mut r = SenderResolver::default();
        let (updated, _) = r.update(None, Some("Alice"), &["alice@example.com".to_string()], &["Alice".to_string()]);
        assert!(!updated);
        assert_eq!(r.from_address, None);
        assert_eq!(r.from_comment, None);
    }

    #[test]
    fn already_fully_matched() {
        let mut r = SenderResolver::default();
        r.update(Some("alice@example.com"), Some("Alice"), &["alice@example.com".to_string()], &["Alice".to_string()]);
        let (updated, _) = r.update(Some("bob@example.com"), Some("Bob"), &["bob@example.com".to_string()], &["Bob".to_string()]);
        assert!(!updated);
        assert_eq!(r.from_address, Some("alice@example.com".to_string()));
        assert_eq!(r.from_comment, Some("Alice".to_string()));
    }

    #[test]
    fn upgrades_partial_match() {
        let mut r = SenderResolver::default();
        r.update(Some("alice@example.com"), Some("Eve"), &["alice@example.com".to_string()], &["Alice".to_string()]);
        assert_eq!(r.from_comment, None);

        let (updated, _) = r.update(Some("alice@example.com"), Some("Alice"), &["alice@example.com".to_string()], &["Alice".to_string()]);
        assert!(updated);
        assert_eq!(r.from_address, Some("alice@example.com".to_string()));
        assert_eq!(r.from_comment, Some("Alice".to_string()));
    }

    #[test]
    fn no_inner_name() {
        let mut r = SenderResolver::default();
        let (updated, _) = r.update(Some("alice@example.com"), None, &["alice@example.com".to_string()], &["Alice".to_string()]);
        assert!(updated);
        assert_eq!(r.from_address, Some("alice@example.com".to_string()));
        assert_eq!(r.from_comment, None);
    }

    #[test]
    fn case_insensitive_address_match() {
        let mut r = SenderResolver::default();
        let (updated, warnings) = r.update(Some("Alice@Example.COM"), None, &["alice@example.com".to_string()], &[]);
        assert!(updated);
        assert_eq!(r.from_address, Some("Alice@Example.COM".to_string()));
        // RFC 9598 §5: local-part case differs, expect a warning
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn case_insensitive_name_match() {
        let mut r = SenderResolver::default();
        let (updated, _) = r.update(Some("alice@example.com"), Some("ALICE"), &["alice@example.com".to_string()], &["Alice".to_string()]);
        assert!(updated);
        assert_eq!(r.from_comment, Some("ALICE".to_string()));
    }

    #[test]
    fn multiple_san_emails() {
        let mut r = SenderResolver::default();
        let (updated, _) = r.update(Some("alice@example.com"), None, &["bob@example.com".to_string(), "alice@example.com".to_string()], &[]);
        assert!(updated);
        assert_eq!(r.from_address, Some("alice@example.com".to_string()));
    }
}
