//! GeoIP 数据源配置（CERNET、RIR、云厂商等）。
#[derive(Debug, Clone, Default)]
pub struct DataSource {
    pub name: String,
    pub url: String,
    pub sync_days: u64,
    pub active: bool,
}

pub fn available_sources() -> Vec<DataSource> {
    vec![
        DataSource { name: "cernet".to_string(), url: "https://ip.cernet.cn".to_string(), sync_days: 1, active: true },
        DataSource { name: "ripe".to_string(), url: "https://ftp.ripe.net".to_string(), sync_days: 7, active: true },
        DataSource { name: "apnic".to_string(), url: "https://ftp.apnic.net".to_string(), sync_days: 7, active: true },
    ]
}