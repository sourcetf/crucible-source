//! GeoIP 过滤聚合器。
#[derive(Debug, Clone, Default)]
pub struct FilterAgg {
    pub count: usize,
}
pub fn apply_filter(_agg: &mut FilterAgg) {}