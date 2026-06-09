use smime::email_domain_to_a_label;

#[test]
fn test_email_to_ascii() {
    assert_eq!(email_domain_to_a_label("alice@example.com"), "alice@example.com");
    assert_eq!(email_domain_to_a_label("医生@大学.example.com"), "医生@xn--pss25c.example.com");
    assert_eq!(email_domain_to_a_label("user@δοκιμή.ελ"), "user@xn--jxalpdlp.xn--qxam");
    assert_eq!(email_domain_to_a_label("δοκιμή@δοκιμή.ελ"), "δοκιμή@xn--jxalpdlp.xn--qxam");
}
