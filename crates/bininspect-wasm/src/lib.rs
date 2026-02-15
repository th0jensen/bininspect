use bininspect::*;
use js_sys::Error;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn analyze(bytes: &[u8]) -> Result<AnalysisReport, JsValue> {
    analyze_bytes(bytes).map_err(to_js_error)
}

#[wasm_bindgen]
pub fn analyze_pretty(bytes: &[u8]) -> Result<String, JsValue> {
    analyze_to_json(bytes, true).map_err(to_js_error)
}

#[wasm_bindgen]
pub fn api_version() -> String {
    API_VERSION.to_string()
}

fn to_js_error(err: impl std::fmt::Display) -> JsValue {
    Error::new(&err.to_string()).into()
}

#[cfg(test)]
mod tests {
    use super::api_version;
    use bininspect::API_VERSION;

    #[test]
    fn api_version_matches_core_version() {
        assert_eq!(api_version(), API_VERSION);
    }
}
