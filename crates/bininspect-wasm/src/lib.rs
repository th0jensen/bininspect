use js_sys::Error;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn analyze(bytes: &[u8]) -> Result<bininspect::AnalysisReport, JsValue> {
    bininspect::analyze_bytes(bytes).map_err(to_js_error)
}

#[wasm_bindgen]
pub fn analyze_pretty(bytes: &[u8]) -> Result<String, JsValue> {
    bininspect::analyze_to_json(bytes, true).map_err(to_js_error)
}

#[wasm_bindgen]
pub fn api_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

fn to_js_error(err: impl std::fmt::Display) -> JsValue {
    Error::new(&err.to_string()).into()
}
