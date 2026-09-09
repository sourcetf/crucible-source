//! GeoIP 数据 schema 定义。
/*
Schema:
- ip (TEXT PRIMARY KEY)
- cidr (TEXT)  // 可选，IP 范围
- country (TEXT)
- province (TEXT)
- city (TEXT)
- isp (TEXT)
- asn (INTEGER)
*/
pub const TABLE_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS ip2loc (
    ip TEXT PRIMARY KEY,
    cidr TEXT,
    country TEXT,
    province TEXT,
    city TEXT,
    isp TEXT,
    asn INTEGER
);
"#;