use pyo3::prelude::*;

#[pymodule]
fn _engine(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("__version__", env!("CARGO_PKG_VERSION"))?;
    module.add("ENGINE_NAME", "nerb_engine")?;
    Ok(())
}
