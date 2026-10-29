use super::*;

fn kinds(text: &str) -> Vec<Kind> {
    Detector::new()
        .scan(text)
        .into_iter()
        .map(|f| f.kind)
        .collect()
}

fn values(text: &str) -> Vec<&str> {
    Detector::new()
        .scan(text)
        .into_iter()
        .map(|f| &text[f.start..f.end])
        .collect()
}

/// Asserts that each text yields exactly one finding of `kind` with value `value`.
fn finds(kind: Kind, cases: &[(&str, &str)]) {
    let detector = Detector::new();
    for (text, value) in cases {
        let found: Vec<_> = detector
            .scan(text)
            .into_iter()
            .map(|f| (f.kind, &text[f.start..f.end]))
            .collect();
        assert_eq!(found, [(kind, *value)], "in {text:?}");
    }
}

fn ignores(texts: &[&str]) {
    for text in texts {
        assert_eq!(kinds(text), [], "in {text:?}");
    }
}

#[test]
fn emails() {
    finds(
        Kind::Email,
        &[(
            "Write to jane.doe+news@example.co.uk today.",
            "jane.doe+news@example.co.uk",
        )],
    );
    ignores(&["no at sign here, just text"]);
}

#[test]
fn international_phone_numbers() {
    finds(
        Kind::Phone,
        &[
            ("Call +49 151 23456789 now", "+49 151 23456789"),
            ("or +44 (20) 7946-0958.", "+44 (20) 7946-0958"),
        ],
    );
    ignores(&["version +1.2 released"]);
}

#[test]
fn ibans_with_checksum() {
    finds(
        Kind::Iban,
        &[
            (
                "IBAN: DE89 3704 0044 0532 0130 00 thanks",
                "DE89 3704 0044 0532 0130 00",
            ),
            ("GB82WEST12345698765432", "GB82WEST12345698765432"),
            // An uppercase word after the IBAN is not swallowed.
            ("DE89370400440532013000 OK", "DE89370400440532013000"),
        ],
    );
    ignores(&["DE89 3704 0044 0532 0130 01"]);
}

#[test]
fn card_numbers_with_network_and_luhn() {
    finds(
        Kind::CreditCard,
        &[
            ("card 4111 1111 1111 1111 exp 12/29", "4111 1111 1111 1111"),
            ("5500-0000-0000-0004", "5500-0000-0000-0004"),
            ("amex 3782 822463 10005", "3782 822463 10005"),
        ],
    );
    // Wrong checksum; no network; Luhn-valid but no network uses that prefix and length.
    ignores(&[
        "4111 1111 1111 1112",
        "order 2024000000000000",
        "3704 0044 0532 0130 01",
    ]);
}

#[test]
fn bic_and_vat_need_context() {
    finds(
        Kind::Bic,
        &[
            ("BIC: COBADEFFXXX", "COBADEFFXXX"),
            ("SWIFT code DEUTDEDB", "DEUTDEDB"),
        ],
    );
    finds(
        Kind::VatId,
        &[
            ("USt-IdNr. DE123456789", "DE123456789"),
            ("VAT number ATU12345678", "ATU12345678"),
        ],
    );
    // Shouted words and bare codes without a keyword nearby are not reported.
    ignores(&["PLEASE READ THE DOCUMENTS CAREFULLY", "ticket DE123456789"]);
}

#[test]
fn german_tax_id() {
    finds(
        Kind::DeTaxId,
        &[
            ("Steuer-ID 86095742719", "86095742719"),
            ("IdNr: 86 095 742 719", "86 095 742 719"),
        ],
    );
    // Wrong check digit; no context; digit pattern not allowed for tax IDs.
    ignores(&[
        "Steuer-ID 86095742718",
        "order 86095742719",
        "Steuer-ID 12345678903",
    ]);
}

#[test]
fn dutch_bsn() {
    finds(Kind::NlBsn, &[("BSN 111222333", "111222333")]);
    ignores(&["BSN 111222334", "invoice 111222333"]);
}

#[test]
fn spanish_dni_and_nie() {
    finds(
        Kind::EsDni,
        &[
            ("DNI 12345678Z", "12345678Z"),
            ("NIE X-1234567-L", "X-1234567-L"),
        ],
    );
    ignores(&["12345678A"]);
}

#[test]
fn italian_fiscal_code() {
    finds(
        Kind::ItFiscalCode,
        &[("CF: RSSMRA85T10A562S", "RSSMRA85T10A562S")],
    );
    ignores(&["RSSMRA85T10A562T"]);
}

#[test]
fn french_nir() {
    finds(
        Kind::FrNir,
        &[
            ("NIR 2 55 08 14 168 025 38", "2 55 08 14 168 025 38"),
            ("255081416802538", "255081416802538"),
        ],
    );
    ignores(&["2 55 08 14 168 025 39"]);
}

#[test]
fn polish_pesel() {
    finds(Kind::PlPesel, &[("PESEL: 44051401359", "44051401359")]);
    ignores(&["PESEL: 44051401358", "phone 44051401359"]);
}

#[test]
fn uk_national_insurance_number() {
    finds(
        Kind::UkNino,
        &[
            ("NI number AB 12 34 56 C", "AB 12 34 56 C"),
            ("AB123456C", "AB123456C"),
        ],
    );
    ignores(&["GB123456C", "AB123456E"]);
}

#[test]
fn us_social_security_number() {
    finds(
        Kind::UsSsn,
        &[
            ("SSN 123-45-6789", "123-45-6789"),
            ("my social security number is 123456789", "123456789"),
        ],
    );
    ignores(&["000-12-3456", "666-12-3456", "id 123456789"]);
}

#[test]
fn ip_addresses() {
    finds(
        Kind::IpAddress,
        &[
            ("from 192.168.1.20 to", "192.168.1.20"),
            (
                "host 2001:0db8:85a3:0000:0000:8a2e:0370:7334",
                "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            ),
        ],
    );
    ignores(&["version 1.2.3.400", "build 01.02.03.04"]);
}

#[test]
fn secrets_with_known_formats() {
    let cases = [
        ("key=sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz012345", Kind::OpenAiKey),
        ("sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123", Kind::AnthropicKey),
        ("AKIAIOSFODNN7EXAMPLE", Kind::AwsAccessKey),
        ("ghp_abcdefghijklmnopqrstuvwxyz0123456789", Kind::GitHubToken),
        ("xoxb-1234567890-abcdefghij", Kind::SlackToken),
        ("sk_live_abcdefghijklmnopqrstuvwx", Kind::StripeKey),
        ("AIzaSyA-abcdefghijklmnopqrstuvwxyz01234", Kind::GoogleApiKey),
        ("hf_abcdefghijklmnopqrstuvwxyzABCDEFGH", Kind::HuggingFaceToken),
        ("npm_abcdefghijklmnopqrstuvwxyz0123456789", Kind::NpmToken),
        ("SK0123456789abcdef0123456789abcdef", Kind::TwilioKey),
        (
            "SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
            Kind::SendGridKey,
        ),
        (
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            Kind::Jwt,
        ),
    ];
    for (text, kind) in cases {
        assert_eq!(kinds(text), [kind], "{text}");
    }
}

#[test]
fn secrets_inside_config_snippets_report_only_the_value() {
    let azure_key = format!("{}==", "a".repeat(40) + &"B".repeat(46));
    let azure = format!("DefaultEndpointsProtocol=https;AccountName=x;AccountKey={azure_key};");
    finds(Kind::AzureStorageKey, &[(&azure, &azure_key)]);
    finds(
        Kind::GcpServiceAccount,
        &[(
            r#"{"type": "service_account", "private_key_id": "0123456789abcdef0123456789abcdef01234567"}"#,
            "0123456789abcdef0123456789abcdef01234567",
        )],
    );
    finds(
        Kind::UrlCredentials,
        &[(
            "DATABASE_URL=postgres://app:S3cr3t-pw@db.internal:5432/main",
            "S3cr3t-pw",
        )],
    );
    finds(
        Kind::Password,
        &[
            ("password = hunter2hunter2", "hunter2hunter2"),
            (
                r#"{"api_key": "a8f5f167f44f4964e6c998dee827110c"}"#,
                "a8f5f167f44f4964e6c998dee827110c",
            ),
        ],
    );
    // Placeholders in docs and templates are not secrets.
    ignores(&[
        "password: <your-password>",
        "API_KEY=${API_KEY}",
        "password=********",
        "pwd: changeme123",
    ]);
}

#[test]
fn whole_private_key_block() {
    let text =
        "here:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nIBAAK\n-----END RSA PRIVATE KEY-----\nbye";
    let found = values(text);
    assert_eq!(found.len(), 1);
    assert!(found[0].starts_with("-----BEGIN") && found[0].ends_with("KEY-----"));
    // A truncated key still counts.
    assert_eq!(
        kinds("-----BEGIN PRIVATE KEY-----\nMIIEv"),
        [Kind::PrivateKey]
    );
}

#[test]
fn plain_text_has_no_findings() {
    ignores(&[
        "Please summarise the attached quarterly report in three bullet points. \
         Revenue grew 12% to 4.5 million, orders reached 120000 and the skill \
         matrix lists sk-level staff. Ünïcödé text is fine too.",
        "Release 2.14.0 ships on 2026-11-03; see ticket 4821 and PR #1932 for details.",
        "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG AND READS THE DOCUMENTATION",
    ]);
}

#[test]
fn context_keyword_must_be_close() {
    let far = format!("BSN {} 111222333", "x".repeat(60));
    ignores(&[&far]);
    // A multi-byte character right at the window edge must not break slicing.
    let edge = format!("BSN {}é 111222333", "x".repeat(42));
    let _ = kinds(&edge);
}

#[test]
fn redacts_findings_and_keeps_the_rest() {
    let text = "Mail jane@example.com or call +49 151 23456789, café ✓";
    let detector = Detector::new();
    let findings = detector.scan(text);
    assert_eq!(
        detector.redact(text, &findings),
        "Mail [REDACTED:EMAIL] or call [REDACTED:PHONE], café ✓"
    );
}

#[test]
fn custom_patterns_and_keywords() {
    let mut builder = Detector::builder();
    let employee = builder.pattern("employee_id", r"\bEMP-[0-9]{6}\b").unwrap();
    let projects = builder
        .keywords(
            "project_names",
            &["Project Falcon".into(), "bluebird".into()],
        )
        .unwrap();
    let detector = builder.build();

    let text = "EMP-004211 works on project falcon and Bluebird, not bluebirds.";
    let found = detector.scan(text);
    let got: Vec<_> = found
        .iter()
        .map(|f| (f.kind, &text[f.start..f.end]))
        .collect();
    assert_eq!(
        got,
        [
            (employee, "EMP-004211"),
            (projects, "project falcon"),
            (projects, "Bluebird")
        ]
    );
    assert_eq!(detector.label(employee), "custom.employee_id");
    assert_eq!(
        detector.redact(text, &found),
        "[REDACTED:EMPLOYEE_ID] works on [REDACTED:PROJECT_NAMES] and [REDACTED:PROJECT_NAMES], not bluebirds."
    );

    assert!(matches!(
        Detector::builder().pattern("Bad Name", "x"),
        Err(BuildError::InvalidName(_))
    ));
    assert!(matches!(
        Detector::builder().pattern("x", "("),
        Err(BuildError::InvalidPattern(..))
    ));
    assert!(matches!(
        Detector::builder().keywords("x", &[" ".into()]),
        Err(BuildError::EmptyKeywords(_))
    ));
}

#[test]
fn entity_names_round_trip() {
    for kind in Kind::ALL {
        assert_eq!(
            Kind::from_entity(kind.category(), kind.entity()),
            Some(kind)
        );
    }
    assert_eq!(Kind::Iban.id(), "pii.iban");
    assert_eq!(Kind::OpenAiKey.id(), "secret.openai_key");
}

#[test]
fn every_kind_has_a_rule() {
    for kind in Kind::ALL {
        assert!(
            rules::RULES.iter().any(|r| r.kind == kind),
            "{kind:?} has no rule"
        );
    }
}
