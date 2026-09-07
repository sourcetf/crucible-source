//! RFC 9460 HTTPS (type 65) DNS record API — /__admin/api/type65.
//! 内存表: name -> EchRecord{ech_config_b64, ttl}.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub struct EchRecord { pub ech_config_b64: String, pub ttl: Option<u32> }

pub static ECH_STATE: once_cell::sync::Lazy<parking_lot::RwLock<HashMap<String, EchRecord>>> =
    once_cell::sync::Lazy::new(|| parking_lot::RwLock::new(HashMap::new()));

#[derive(Debug, Deserialize)]
pub struct Type65Request {
    pub name: String,
    pub ech_config_list: Option<String>,
    pub ttl: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct Type65Record { pub name: String, pub rtype: u16, pub priority: u8, pub ech_config_list_b64: String, pub ttl: u32 }

pub fn list() -> String {
    let r = ECH_STATE.read();
    let records: Vec<Type65Record> = r.iter().map(|(n, c)| Type65Record { name: n.clone(), rtype: 65, priority: 1, ech_config_list_b64: c.ech_config_b64.clone(), ttl: c.ttl.unwrap_or(300) }).collect();
    serde_json::to_string_pretty(&records).unwrap_or_else(|_| "[]".into())
}

pub fn publish(req: Type65Request) -> Result<String, String> {
    let ttl = req.ttl.unwrap_or(300);
    let b64 = req.ech_config_list.ok_or("ech_config_list required")?;
    if b64.is_empty() { return Err("empty ech_config_list".into()); }
    let mut w = ECH_STATE.write();
    w.insert(req.name.clone(), EchRecord { ech_config_b64: b64.clone(), ttl: Some(ttl) });
    Ok(format!("published {} ttl={} ({} bytes b64)\n", req.name, ttl, b64.len()))
}

pub fn delete(name: &str) -> Result<(), String> {
    let mut w = ECH_STATE.write();
    w.remove(name).ok_or_else(|| format!("not found: {name}"))?;
    Ok(())
}

