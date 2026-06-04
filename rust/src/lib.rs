use pyo3::exceptions::{PyIndexError, PyNotImplementedError, PyRuntimeError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use std::panic::{catch_unwind, AssertUnwindSafe};

mod bank;
mod error;
mod flags;
mod formats;
mod ids;
mod match_buffer;

use bank::NativeBank;
use match_buffer::NativeMatchBuffer;

fn ffi_boundary<T>(operation: impl FnOnce() -> PyResult<T>) -> PyResult<T> {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(result) => result,
        Err(_) => Err(PyRuntimeError::new_err(
            "NERB native engine panicked while handling an FFI call",
        )),
    }
}

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
        ffi_boundary(|| {
            Ok(Self {
                inner: NativeBank::from_source_bytes(source, format_hint, compile_options_json)?,
            })
        })
    }

    #[staticmethod]
    #[pyo3(signature = (source, compile_options_json=None))]
    fn from_canonical_json_bytes(
        source: &[u8],
        compile_options_json: Option<&str>,
    ) -> PyResult<Self> {
        ffi_boundary(|| {
            Ok(Self {
                inner: NativeBank::from_canonical_json_bytes(source, compile_options_json)?,
            })
        })
    }

    fn to_canonical_json_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        ffi_boundary(|| Ok(PyBytes::new(py, self.inner.canonical_json())))
    }

    fn metadata<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        ffi_boundary(|| {
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
        })
    }

    #[pyo3(signature = (haystack, out=None))]
    fn scan_bytes(
        &self,
        py: Python<'_>,
        haystack: &[u8],
        out: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<PyMatchBuffer> {
        ffi_boundary(|| {
            let _ = (haystack, out);
            py.detach(|| ());
            Err(PyNotImplementedError::new_err(
                "Bank.scan_bytes is reserved for the Rust matching slice and is not implemented yet",
            ))
        })
    }

    #[pyo3(signature = (path, out=None))]
    fn scan_path(
        &self,
        py: Python<'_>,
        path: &str,
        out: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<PyMatchBuffer> {
        ffi_boundary(|| {
            let _ = (path, out);
            py.detach(|| ());
            Err(PyNotImplementedError::new_err(
                "Bank.scan_path is reserved for the Rust matching slice and is not implemented yet",
            ))
        })
    }
}

#[pyclass(name = "MatchBuffer")]
struct PyMatchBuffer {
    inner: NativeMatchBuffer,
}

#[pymethods]
impl PyMatchBuffer {
    #[new]
    #[pyo3(signature = (capacity=0))]
    fn new(capacity: usize) -> PyResult<Self> {
        ffi_boundary(|| {
            Ok(Self {
                inner: if capacity == 0 {
                    NativeMatchBuffer::new()
                } else {
                    NativeMatchBuffer::with_capacity(capacity)
                },
            })
        })
    }

    #[staticmethod]
    fn from_raw_matches(raw_matches: Vec<(u32, u64, u64)>) -> PyResult<Self> {
        ffi_boundary(|| {
            Ok(Self {
                inner: NativeMatchBuffer::from_raw_matches(&raw_matches)?,
            })
        })
    }

    fn __len__(&self) -> PyResult<usize> {
        ffi_boundary(|| Ok(self.inner.len()))
    }

    fn is_empty(&self) -> PyResult<bool> {
        ffi_boundary(|| Ok(self.inner.is_empty()))
    }

    fn capacity(&self) -> PyResult<usize> {
        ffi_boundary(|| Ok(self.inner.capacity()))
    }

    fn clear(&mut self) -> PyResult<()> {
        ffi_boundary(|| {
            self.inner.clear();
            Ok(())
        })
    }

    fn reserve(&mut self, additional: usize) -> PyResult<()> {
        ffi_boundary(|| {
            self.inner.reserve(additional);
            Ok(())
        })
    }

    fn get(&self, index: usize) -> PyResult<Option<(u32, u64, u64)>> {
        ffi_boundary(|| Ok(self.inner.get(index).map(|raw_match| raw_match.as_tuple())))
    }

    fn __getitem__(&self, index: isize) -> PyResult<(u32, u64, u64)> {
        ffi_boundary(|| {
            let len = self.inner.len();
            let normalized = normalize_index(index, len)?;
            self.inner
                .get(normalized)
                .map(|raw_match| raw_match.as_tuple())
                .ok_or_else(|| PyIndexError::new_err("match buffer index out of range"))
        })
    }
}

fn normalize_index(index: isize, len: usize) -> PyResult<usize> {
    if index >= 0 {
        let index = index as usize;
        if index < len {
            return Ok(index);
        }
    } else {
        let from_end = len as isize + index;
        if from_end >= 0 {
            return Ok(from_end as usize);
        }
    }
    Err(PyIndexError::new_err("match buffer index out of range"))
}

#[pymodule]
fn _engine(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("__version__", env!("CARGO_PKG_VERSION"))?;
    module.add("ENGINE_NAME", "nerb_engine")?;
    module.add_class::<PyBank>()?;
    module.add_class::<PyMatchBuffer>()?;
    Ok(())
}
