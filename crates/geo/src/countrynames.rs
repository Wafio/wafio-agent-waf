//! ISO 3166-1 alpha-2 codes and their English names.

use std::collections::BTreeMap;

use wafio_bytetext::strings::{to_uppercase, trim_whitespace};

/// Sorted by code.
const COUNTRY_NAME_TABLE: [(&str, &str); 195] = [
    ("AD", "Andorra"),
    ("AE", "United Arab Emirates"),
    ("AF", "Afghanistan"),
    ("AG", "Antigua and Barbuda"),
    ("AI", "Anguilla"),
    ("AL", "Albania"),
    ("AM", "Armenia"),
    ("AO", "Angola"),
    ("AR", "Argentina"),
    ("AT", "Austria"),
    ("AU", "Australia"),
    ("AW", "Aruba"),
    ("AZ", "Azerbaijan"),
    ("BA", "Bosnia and Herzegovina"),
    ("BB", "Barbados"),
    ("BD", "Bangladesh"),
    ("BE", "Belgium"),
    ("BF", "Burkina Faso"),
    ("BG", "Bulgaria"),
    ("BH", "Bahrain"),
    ("BI", "Burundi"),
    ("BJ", "Benin"),
    ("BN", "Brunei"),
    ("BO", "Bolivia"),
    ("BR", "Brazil"),
    ("BS", "Bahamas"),
    ("BT", "Bhutan"),
    ("BW", "Botswana"),
    ("BY", "Belarus"),
    ("BZ", "Belize"),
    ("CA", "Canada"),
    ("CD", "Democratic Republic of the Congo"),
    ("CF", "Central African Republic"),
    ("CG", "Republic of the Congo"),
    ("CH", "Switzerland"),
    ("CI", "Ivory Coast"),
    ("CL", "Chile"),
    ("CM", "Cameroon"),
    ("CN", "China"),
    ("CO", "Colombia"),
    ("CR", "Costa Rica"),
    ("CU", "Cuba"),
    ("CV", "Cape Verde"),
    ("CY", "Cyprus"),
    ("CZ", "Czech Republic"),
    ("DE", "Germany"),
    ("DJ", "Djibouti"),
    ("DK", "Denmark"),
    ("DM", "Dominica"),
    ("DO", "Dominican Republic"),
    ("DZ", "Algeria"),
    ("EC", "Ecuador"),
    ("EE", "Estonia"),
    ("EG", "Egypt"),
    ("ER", "Eritrea"),
    ("ES", "Spain"),
    ("ET", "Ethiopia"),
    ("FI", "Finland"),
    ("FJ", "Fiji"),
    ("FR", "France"),
    ("GA", "Gabon"),
    ("GB", "United Kingdom"),
    ("GD", "Grenada"),
    ("GE", "Georgia"),
    ("GH", "Ghana"),
    ("GM", "Gambia"),
    ("GN", "Guinea"),
    ("GQ", "Equatorial Guinea"),
    ("GR", "Greece"),
    ("GT", "Guatemala"),
    ("GW", "Guinea-Bissau"),
    ("GY", "Guyana"),
    ("HK", "Hong Kong"),
    ("HN", "Honduras"),
    ("HR", "Croatia"),
    ("HT", "Haiti"),
    ("HU", "Hungary"),
    ("ID", "Indonesia"),
    ("IE", "Ireland"),
    ("IL", "Israel"),
    ("IN", "India"),
    ("IQ", "Iraq"),
    ("IR", "Iran"),
    ("IS", "Iceland"),
    ("IT", "Italy"),
    ("JM", "Jamaica"),
    ("JO", "Jordan"),
    ("JP", "Japan"),
    ("KE", "Kenya"),
    ("KG", "Kyrgyzstan"),
    ("KH", "Cambodia"),
    ("KI", "Kiribati"),
    ("KM", "Comoros"),
    ("KN", "Saint Kitts and Nevis"),
    ("KP", "North Korea"),
    ("KR", "South Korea"),
    ("KW", "Kuwait"),
    ("KZ", "Kazakhstan"),
    ("LA", "Laos"),
    ("LB", "Lebanon"),
    ("LC", "Saint Lucia"),
    ("LI", "Liechtenstein"),
    ("LK", "Sri Lanka"),
    ("LR", "Liberia"),
    ("LS", "Lesotho"),
    ("LT", "Lithuania"),
    ("LU", "Luxembourg"),
    ("LV", "Latvia"),
    ("LY", "Libya"),
    ("MA", "Morocco"),
    ("MC", "Monaco"),
    ("MD", "Moldova"),
    ("ME", "Montenegro"),
    ("MG", "Madagascar"),
    ("MK", "North Macedonia"),
    ("ML", "Mali"),
    ("MM", "Myanmar"),
    ("MN", "Mongolia"),
    ("MO", "Macau"),
    ("MR", "Mauritania"),
    ("MT", "Malta"),
    ("MU", "Mauritius"),
    ("MV", "Maldives"),
    ("MW", "Malawi"),
    ("MX", "Mexico"),
    ("MY", "Malaysia"),
    ("MZ", "Mozambique"),
    ("NA", "Namibia"),
    ("NE", "Niger"),
    ("NG", "Nigeria"),
    ("NI", "Nicaragua"),
    ("NL", "Netherlands"),
    ("NO", "Norway"),
    ("NP", "Nepal"),
    ("NZ", "New Zealand"),
    ("OM", "Oman"),
    ("PA", "Panama"),
    ("PE", "Peru"),
    ("PG", "Papua New Guinea"),
    ("PH", "Philippines"),
    ("PK", "Pakistan"),
    ("PL", "Poland"),
    ("PR", "Puerto Rico"),
    ("PS", "Palestine"),
    ("PT", "Portugal"),
    ("PY", "Paraguay"),
    ("QA", "Qatar"),
    ("RO", "Romania"),
    ("RS", "Serbia"),
    ("RU", "Russia"),
    ("RW", "Rwanda"),
    ("SA", "Saudi Arabia"),
    ("SB", "Solomon Islands"),
    ("SC", "Seychelles"),
    ("SD", "Sudan"),
    ("SE", "Sweden"),
    ("SG", "Singapore"),
    ("SI", "Slovenia"),
    ("SK", "Slovakia"),
    ("SL", "Sierra Leone"),
    ("SM", "San Marino"),
    ("SN", "Senegal"),
    ("SO", "Somalia"),
    ("SR", "Suriname"),
    ("SS", "South Sudan"),
    ("ST", "São Tomé and Príncipe"),
    ("SV", "El Salvador"),
    ("SY", "Syria"),
    ("SZ", "Eswatini"),
    ("TD", "Chad"),
    ("TG", "Togo"),
    ("TH", "Thailand"),
    ("TJ", "Tajikistan"),
    ("TL", "Timor-Leste"),
    ("TM", "Turkmenistan"),
    ("TN", "Tunisia"),
    ("TO", "Tonga"),
    ("TR", "Turkey"),
    ("TT", "Trinidad and Tobago"),
    ("TW", "Taiwan"),
    ("TZ", "Tanzania"),
    ("UA", "Ukraine"),
    ("UG", "Uganda"),
    ("US", "United States"),
    ("UY", "Uruguay"),
    ("UZ", "Uzbekistan"),
    ("VA", "Vatican City"),
    ("VE", "Venezuela"),
    ("VN", "Vietnam"),
    ("VU", "Vanuatu"),
    ("WS", "Samoa"),
    ("YE", "Yemen"),
    ("ZA", "South Africa"),
    ("ZM", "Zambia"),
    ("ZW", "Zimbabwe"),
];

fn lookup(code: &[u8]) -> Option<&'static str> {
    let upper = to_uppercase(trim_whitespace(code));
    COUNTRY_NAME_TABLE
        .binary_search_by(|(c, _)| c.as_bytes().cmp(&upper[..]))
        .ok()
        .map(|i| COUNTRY_NAME_TABLE[i].1)
}

/// The English name of a code, "" when the code is unknown or an em dash.
pub fn english_country_name(code: &[u8]) -> &'static str {
    if code.is_empty() || code == "—".as_bytes() {
        return "";
    }
    let upper = to_uppercase(trim_whitespace(code));
    if upper == b"XX" || upper == b"ZZ" {
        return "Unknown / Private";
    }
    lookup(code).unwrap_or("")
}

/// A valid ISO 3166-1 alpha-2 code, case-insensitive (the raw input
/// must be two bytes long before it is trimmed).
pub fn is_valid_country_code(code: &[u8]) -> bool {
    code.len() == 2 && lookup(code).is_some()
}

/// Every valid code in sorted order.
pub fn country_codes() -> Vec<&'static str> {
    COUNTRY_NAME_TABLE.iter().map(|(c, _)| *c).collect()
}

/// Code to name for every country.
pub fn country_code_names() -> BTreeMap<&'static str, &'static str> {
    COUNTRY_NAME_TABLE.iter().copied().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // TestCountryName
    #[test]
    fn country_name_table() {
        for (code, want) in [
            ("ID", "Indonesia"),
            ("id", "Indonesia"),
            ("US", "United States"),
            ("XX", "Unknown / Private"),
            ("xx", "Unknown / Private"),
            ("ZZ", "Unknown / Private"),
            ("", ""),
            ("—", ""),
            ("UNKNOWN", ""),
        ] {
            assert_eq!(english_country_name(code.as_bytes()), want, "{code:?}");
        }
    }

    // TestValidCountryCode
    #[test]
    fn valid_country_code_table() {
        assert!(is_valid_country_code(b"ID"));
        assert!(is_valid_country_code(b"us"));
        assert!(
            !is_valid_country_code(b"XX"),
            "XX is not a sovereign country code"
        );
        assert!(!is_valid_country_code(b"INVALID"));
    }

    #[test]
    fn table_is_sorted_and_complete() {
        assert!(COUNTRY_NAME_TABLE.windows(2).all(|w| w[0].0 < w[1].0));
        assert_eq!(country_codes().len(), COUNTRY_NAME_TABLE.len());
        assert_eq!(country_code_names()["ST"], "São Tomé and Príncipe");
    }
}
