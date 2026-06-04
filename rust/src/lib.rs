use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

mod bank;
mod error;
mod flags;
mod formats;
mod ids;

use bank::NativeBank;

#[pyclass(name = "Bank")]
struct PyBank {
    inner: NativeBank,
}

#[pymethods]
impl PyBank {
    #[staticmethod]
    #[pyo3(signature = (source, format_hint=None, compile_options_json=None))]
    fn from_source_bytes(
        source: &[u8],
        format_hint: Option<&str>,
        compile_options_json: Option<&str>,
    ) -> PyResult<Self> {
        Ok(Self {
            inner: NativeBank::from_source_bytes(source, format_hint, compile_options_json)?,
        })
    }

    #[staticmethod]
    #[pyo3(signature = (source, compile_options_json=None))]
    fn from_canonical_json_bytes(
        source: &[u8],
        compile_options_json: Option<&str>,
    ) -> PyResult<Self> {
        Ok(Self {
            inner: NativeBank::from_canonical_json_bytes(source, compile_options_json)?,
        })
    }

    fn to_canonical_json_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.canonical_json())
    }

    fn metadata<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let metadata = PyDict::new(py);
        metadata.set_item("engine", "nerb_engine")?;
        metadata.set_item("schema", self.inner.canonical().schema)?;
        metadata.set_item("bank_hash", self.inner.hash())?;
        metadata.set_item("entity_count", self.inner.canonical().entities.len())?;
        let pattern_count: usize = self
            .inner
            .canonical()
            .entities
            .iter()
            .map(|entity| entity.patterns.len())
            .sum();
        metadata.set_item("pattern_count", pattern_count)?;

        let defaults = PyDict::new(py);
        defaults.set_item("engine", &self.inner.canonical().defaults.engine)?;
        defaults.set_item("unicode", self.inner.canonical().defaults.unicode)?;
        defaults.set_item(
            "case_insensitive",
            self.inner.canonical().defaults.case_insensitive,
        )?;
        defaults.set_item(
            "word_boundaries",
            self.inner.canonical().defaults.word_boundaries,
        )?;
        defaults.set_item(
            "normalization",
            &self.inner.canonical().defaults.normalization,
        )?;
        metadata.set_item("defaults", defaults)?;

        let json = py.import("json")?;
        let compile_options_json = serde_json::to_string(self.inner.compile_options())
            .expect("compile options must serialize");
        let compile_options = json.call_method1("loads", (compile_options_json,))?;
        metadata.set_item("compile_options", compile_options)?;

        Ok(metadata)
    }
}

#[pymodule]
fn _engine(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("__version__", env!("CARGO_PKG_VERSION"))?;
    module.add("ENGINE_NAME", "nerb_engine")?;
    module.add_class::<PyBank>()?;
    Ok(())
}
