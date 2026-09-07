//! §23 GeoIP unified schema helpers.

use super::covering::MergedFields;
use super::lookup::{self, GeoResult};

/// Human-readable label per §23.2 (delegates to [`lookup::format_label`]).
pub fn format_label(m: &MergedFields) -> String {
    lookup::format_label(&GeoResult::from_merged(m.clone()))
}
