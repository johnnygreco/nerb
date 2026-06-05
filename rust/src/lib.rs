use pyo3::exceptions::{PyIndexError, PyOSError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PySequence, PySequenceMethods};
use std::fs;
use std::io::Read;
use std::panic::{catch_unwind, AssertUnwindSafe};

mod bank;
mod engine;
mod error;
mod flags;
mod formats;
mod ids;
mod match_buffer;

use bank::NativeBank;
use match_buffer::{NativeMatchBuffer, RawMatch};

const MAX_SCAN_PATH_BYTES: u64 = 10 * 1024 * 1024;

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

            let match_mode = self.inner.match_mode();
            let mode = PyDict::new(py);
            mode.set_item("name", match_mode.as_str())?;
            mode.set_item("status", match_mode.status())?;
            mode.set_item("production_default", match_mode.production_default())?;
            mode.set_item("internal_only", match_mode.internal_only())?;
            mode.set_item("semantic_notes", match_mode.semantic_notes())?;
            metadata.set_item("match_mode", mode)?;

            let detectors = PyList::empty(py);
            for detector in self.inner.detectors() {
                let item = PyDict::new(py);
                item.set_item("detector_index", detector.detector_index)?;
                item.set_item("entity", &detector.entity)?;
                item.set_item("canonical_name", &detector.canonical_name)?;
                item.set_item("surface_name", &detector.surface_name)?;
                item.set_item("stable_id", &detector.stable_id)?;
                item.set_item("priority", detector.priority)?;
                detectors.append(item)?;
            }
            metadata.set_item("detectors", detectors)?;

            Ok(metadata)
        })
    }

    #[pyo3(signature = (haystack, out=None))]
    fn scan_bytes(
        &self,
        py: Python<'_>,
        haystack: &[u8],
        out: Option<Py<PyMatchBuffer>>,
    ) -> PyResult<Py<PyMatchBuffer>> {
        ffi_boundary(|| match out {
            Some(out) => {
                let mut buffer = {
                    let mut borrowed = out.bind(py).borrow_mut();
                    std::mem::take(&mut borrowed.inner)
                };
                let scan_result = py.detach(|| self.inner.scan_bytes_into(haystack, &mut buffer));
                out.bind(py).borrow_mut().inner = buffer;
                scan_result?;
                Ok(out)
            }
            None => {
                let buffer = py.detach(|| self.inner.scan_bytes(haystack))?;
                Py::new(py, PyMatchBuffer { inner: buffer })
            }
        })
    }

    #[pyo3(signature = (haystack, out=None))]
    fn scan_bytes_leftmost_from_all_overlaps(
        &self,
        py: Python<'_>,
        haystack: &[u8],
        out: Option<Py<PyMatchBuffer>>,
    ) -> PyResult<Py<PyMatchBuffer>> {
        ffi_boundary(|| match out {
            Some(out) => {
                let mut buffer = {
                    let mut borrowed = out.bind(py).borrow_mut();
                    std::mem::take(&mut borrowed.inner)
                };
                let scan_result = py.detach(|| {
                    self.inner
                        .scan_bytes_leftmost_from_all_overlaps(haystack, &mut buffer)
                });
                out.bind(py).borrow_mut().inner = buffer;
                scan_result?;
                Ok(out)
            }
            None => {
                let mut buffer = NativeMatchBuffer::new();
                py.detach(|| {
                    self.inner
                        .scan_bytes_leftmost_from_all_overlaps(haystack, &mut buffer)
                })?;
                Py::new(py, PyMatchBuffer { inner: buffer })
            }
        })
    }

    #[pyo3(signature = (path, out=None))]
    fn scan_path(
        &self,
        py: Python<'_>,
        path: &str,
        out: Option<Py<PyMatchBuffer>>,
    ) -> PyResult<Py<PyMatchBuffer>> {
        ffi_boundary(|| match out {
            Some(out) => {
                let mut buffer = {
                    let mut borrowed = out.bind(py).borrow_mut();
                    std::mem::take(&mut borrowed.inner)
                };
                let scan_result = py.detach(|| {
                    buffer.clear();
                    let haystack = read_scan_path(path)?;
                    self.inner.scan_bytes_into(&haystack, &mut buffer)?;
                    Ok::<(), PyErr>(())
                });
                out.bind(py).borrow_mut().inner = buffer;
                scan_result?;
                Ok(out)
            }
            None => {
                let buffer = py.detach(|| {
                    let haystack = read_scan_path(path)?;
                    self.inner.scan_bytes(&haystack).map_err(PyErr::from)
                })?;
                Py::new(py, PyMatchBuffer { inner: buffer })
            }
        })
    }

    fn scan_path_with_bytes<'py>(
        &self,
        py: Python<'py>,
        path: &str,
    ) -> PyResult<(Py<PyMatchBuffer>, Bound<'py, PyBytes>)> {
        ffi_boundary(|| {
            let (buffer, haystack) = py.detach(|| {
                let haystack = read_scan_path(path)?;
                let buffer = self.inner.scan_bytes(&haystack).map_err(PyErr::from)?;
                Ok::<(NativeMatchBuffer, Vec<u8>), PyErr>((buffer, haystack))
            })?;
            Ok((
                Py::new(py, PyMatchBuffer { inner: buffer })?,
                PyBytes::new(py, &haystack),
            ))
        })
    }
}

fn read_scan_path(path: &str) -> PyResult<Vec<u8>> {
    let metadata = fs::metadata(path).map_err(|error| {
        PyOSError::new_err(format!("Could not inspect document path {path:?}: {error}"))
    })?;
    if !metadata.file_type().is_file() {
        return Err(PyValueError::new_err(format!(
            "Document path {path:?} must be a regular file"
        )));
    }
    if metadata.len() > MAX_SCAN_PATH_BYTES {
        return Err(PyValueError::new_err(format!(
            "Document path {path:?} exceeds the configured limit of {MAX_SCAN_PATH_BYTES} bytes"
        )));
    }
    let file = fs::File::open(path).map_err(|error| {
        PyOSError::new_err(format!("Could not read document path {path:?}: {error}"))
    })?;
    let mut haystack = Vec::new();
    file.take(MAX_SCAN_PATH_BYTES + 1)
        .read_to_end(&mut haystack)
        .map_err(|error| PyOSError::new_err(format!("Could not read document path {path:?}: {error}")))?;
    if haystack.len() as u64 > MAX_SCAN_PATH_BYTES {
        return Err(PyValueError::new_err(format!(
            "Document path {path:?} exceeds the configured limit of {MAX_SCAN_PATH_BYTES} bytes"
        )));
    }
    Ok(haystack)
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
                    NativeMatchBuffer::with_capacity(capacity)?
                },
            })
        })
    }

    #[staticmethod]
    fn from_raw_matches(raw_matches: &Bound<'_, PyAny>) -> PyResult<Self> {
        ffi_boundary(|| {
            let sequence = raw_matches.cast::<PySequence>()?;
            let len = sequence.len()?;
            let mut buffer = NativeMatchBuffer::with_capacity(len)?;
            for index in 0..len {
                let item = sequence.get_item(index)?;
                let (detector_index, start_byte, end_byte): (u32, u64, u64) = item.extract()?;
                buffer.push(RawMatch::new(detector_index, start_byte, end_byte)?)?;
            }
            Ok(Self { inner: buffer })
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
            self.inner.reserve(additional)?;
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
