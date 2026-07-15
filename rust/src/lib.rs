use pyo3::exceptions::{PyIndexError, PyOSError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{
    PyByteArray, PyByteArrayMethods, PyBytes, PyDict, PyList, PySequence, PySequenceMethods,
};
#[cfg(unix)]
use std::ffi::CString;
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
use engine::{
    validate_scan_input_size, ENTITY_INDEPENDENT_REGEX_CACHE_CAPACITY,
    MAX_CONCURRENT_SCANS_PER_ENGINE, MAX_ENTITY_INDEPENDENT_REGEX_ACCOUNTED_BYTES,
    MAX_ENTITY_INDEPENDENT_REGEX_LAYERS_PER_ENTITY, MAX_LAZY_DFA_CACHES_PER_META_REGEX,
    MAX_PATTERNS_PER_BOUNDED_REGEX_LAYER, MAX_SCAN_INPUT_BYTES, PIKEVM_STACK_NFA_MEMORY_MULTIPLIER,
};
use match_buffer::{NativeMatchBuffer, RawMatch};

const MAX_SCAN_PATH_BYTES: u64 = MAX_SCAN_INPUT_BYTES as u64;
#[cfg(unix)]
const DIRECTORY_OPEN_FLAGS: i32 =
    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW;
#[cfg(unix)]
const PRIVATE_FILE_OPEN_FLAGS: i32 =
    libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW;
#[cfg(unix)]
const EXISTING_PRIVATE_FILE_OPEN_FLAGS: i32 = libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW;

#[cfg(target_os = "linux")]
fn expected_owned_directory(info: &libc::stat, expected_device: u64, expected_inode: u64) -> bool {
    (info.st_mode & libc::S_IFMT) == libc::S_IFDIR
        && info.st_uid == unsafe { libc::geteuid() }
        && info.st_dev as u64 == expected_device
        && info.st_ino as u64 == expected_inode
}

#[cfg(target_os = "linux")]
fn last_errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

#[cfg(target_os = "linux")]
fn repair_and_open_directory_at(
    path: &CString,
    dir_fd: i32,
    expected_device: u64,
    expected_inode: u64,
) -> (i32, i32) {
    let authority = unsafe {
        libc::openat(
            dir_fd,
            path.as_ptr(),
            libc::O_PATH | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    };
    if authority < 0 {
        return (-1, last_errno());
    }
    let result = (|| {
        let mut before = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe { libc::fstat(authority, &mut before) } != 0 {
            return (-1, last_errno());
        }
        if !expected_owned_directory(&before, expected_device, expected_inode) {
            return (-1, libc::ESTALE);
        }
        let proc_path = match CString::new(format!("/proc/self/fd/{authority}")) {
            Ok(value) => value,
            Err(_) => return (-1, libc::EINVAL),
        };
        if unsafe { libc::chmod(proc_path.as_ptr(), libc::S_IRWXU as libc::mode_t) } != 0 {
            return (-1, last_errno());
        }
        let current_directory = c".";
        let descriptor =
            unsafe { libc::openat(authority, current_directory.as_ptr(), DIRECTORY_OPEN_FLAGS) };
        if descriptor < 0 {
            return (-1, last_errno());
        }
        let mut opened = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe { libc::fstat(descriptor, &mut opened) } != 0
            || !expected_owned_directory(&opened, expected_device, expected_inode)
            || opened.st_mode & 0o7777 != libc::S_IRWXU
        {
            unsafe { libc::close(descriptor) };
            return (-1, libc::ESTALE);
        }
        (descriptor, 0)
    })();
    unsafe { libc::close(authority) };
    result
}

#[cfg(all(unix, not(target_os = "linux")))]
fn repair_and_open_directory_at(
    _path: &CString,
    _dir_fd: i32,
    _expected_device: u64,
    _expected_inode: u64,
) -> (i32, i32) {
    (-1, libc::ENOTSUP)
}

fn ffi_boundary<T>(operation: impl FnOnce() -> PyResult<T>) -> PyResult<T> {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(result) => result,
        Err(_) => Err(PyRuntimeError::new_err(
            "NERB native engine panicked while handling an FFI call",
        )),
    }
}

#[pyfunction]
fn _is_word_character(character: &str) -> PyResult<bool> {
    ffi_boundary(|| {
        let mut characters = character.chars();
        let Some(character) = characters.next() else {
            return Err(PyValueError::new_err(
                "Native word-character input must contain exactly one Unicode scalar",
            ));
        };
        if characters.next().is_some() {
            return Err(PyValueError::new_err(
                "Native word-character input must contain exactly one Unicode scalar",
            ));
        }
        Ok(native_is_word_character(character))
    })
}

fn native_is_word_character(character: char) -> bool {
    regex_syntax::is_word_character(character)
}

#[cfg(unix)]
fn write_status_bytes(status: &Bound<'_, PyByteArray>, value: &[u8]) -> PyResult<()> {
    if status.len() != value.len() {
        return Err(PyValueError::new_err(
            "Native descriptor status buffer has invalid length",
        ));
    }
    // SAFETY: the caller-created bytearray is exclusively borrowed by this
    // GIL-held native call and no Python interaction occurs while mutating it.
    unsafe { status.as_bytes_mut() }.copy_from_slice(value);
    Ok(())
}

#[pyfunction]
#[cfg(unix)]
fn _close_fd_once(attempted: &Bound<'_, PyByteArray>, descriptor: i32) -> PyResult<i32> {
    ffi_boundary(|| {
        if attempted.len() != 1 || attempted.to_vec() != [0] {
            return Err(PyValueError::new_err(
                "Native close-attempt status buffer must contain one zero byte",
            ));
        }
        // Python control flow cannot run between the syscall and the status
        // commit because this function retains the interpreter lock.
        let result = unsafe { libc::close(descriptor) };
        let errno = if result == 0 {
            0
        } else {
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO)
        };
        write_status_bytes(attempted, &[1])?;
        Ok(errno)
    })
}

#[pyfunction]
#[cfg(not(unix))]
fn _close_fd_once(_attempted: &Bound<'_, PyByteArray>, _descriptor: i32) -> PyResult<i32> {
    Err(PyOSError::new_err(
        "Native descriptor transactions require a Unix platform",
    ))
}

#[pyfunction]
#[cfg(unix)]
fn _fsync_fd_commit(committed: &Bound<'_, PyByteArray>, descriptor: i32) -> PyResult<i32> {
    ffi_boundary(|| {
        if committed.len() != 1 || committed.to_vec() != [0] {
            return Err(PyValueError::new_err(
                "Native fsync-commit status buffer must contain one zero byte",
            ));
        }
        // Retaining the interpreter lock across both the syscall and status
        // mutation makes the successful durability boundary caller-visible
        // without a Python control-flow gap.
        let result = unsafe { libc::fsync(descriptor) };
        let errno = if result == 0 {
            0
        } else {
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO)
        };
        if result == 0 {
            write_status_bytes(committed, &[1])?;
        }
        Ok(errno)
    })
}

#[pyfunction]
#[cfg(not(unix))]
fn _fsync_fd_commit(_committed: &Bound<'_, PyByteArray>, _descriptor: i32) -> PyResult<i32> {
    Err(PyOSError::new_err(
        "Native descriptor transactions require a Unix platform",
    ))
}

#[pyfunction]
#[cfg(unix)]
#[pyo3(signature = (opened_fd, path, dir_fd=None))]
fn _open_directory_fd_once(
    opened_fd: &Bound<'_, PyByteArray>,
    path: &[u8],
    dir_fd: Option<i32>,
) -> PyResult<i32> {
    ffi_boundary(|| {
        if opened_fd.len() != std::mem::size_of::<i32>()
            || opened_fd.to_vec() != (-1_i32).to_ne_bytes()
        {
            return Err(PyValueError::new_err(
                "Native directory-open status buffer must contain one negative descriptor",
            ));
        }
        let path = CString::new(path)
            .map_err(|_| PyValueError::new_err("Native directory path contains a null byte"))?;
        let descriptor = unsafe {
            match dir_fd {
                Some(parent) => libc::openat(parent, path.as_ptr(), DIRECTORY_OPEN_FLAGS),
                None => libc::open(path.as_ptr(), DIRECTORY_OPEN_FLAGS),
            }
        };
        let errno = if descriptor >= 0 {
            0
        } else {
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO)
        };
        write_status_bytes(opened_fd, &descriptor.to_ne_bytes())?;
        Ok(errno)
    })
}

#[pyfunction]
#[cfg(unix)]
fn _repair_and_open_directory_fd_once(
    opened_fd: &Bound<'_, PyByteArray>,
    path: &[u8],
    dir_fd: i32,
    expected_device: u64,
    expected_inode: u64,
) -> PyResult<i32> {
    ffi_boundary(|| {
        if opened_fd.len() != std::mem::size_of::<i32>()
            || opened_fd.to_vec() != (-1_i32).to_ne_bytes()
        {
            return Err(PyValueError::new_err(
                "Native recovery directory status buffer must contain one negative descriptor",
            ));
        }
        let path = CString::new(path).map_err(|_| {
            PyValueError::new_err("Native recovery directory path contains a null byte")
        })?;
        let (descriptor, errno) =
            repair_and_open_directory_at(&path, dir_fd, expected_device, expected_inode);
        write_status_bytes(opened_fd, &descriptor.to_ne_bytes())?;
        Ok(errno)
    })
}

#[pyfunction]
#[cfg(unix)]
fn _open_private_file_fd_once(
    opened_fd: &Bound<'_, PyByteArray>,
    path: &[u8],
    dir_fd: i32,
) -> PyResult<i32> {
    ffi_boundary(|| {
        if opened_fd.len() != std::mem::size_of::<i32>()
            || opened_fd.to_vec() != (-1_i32).to_ne_bytes()
        {
            return Err(PyValueError::new_err(
                "Native private-file status buffer must contain one negative descriptor",
            ));
        }
        let path = CString::new(path)
            .map_err(|_| PyValueError::new_err("Native private-file path contains a null byte"))?;
        let descriptor = unsafe {
            libc::openat(
                dir_fd,
                path.as_ptr(),
                PRIVATE_FILE_OPEN_FLAGS,
                (libc::S_IRUSR | libc::S_IWUSR) as libc::c_uint,
            )
        };
        let errno = if descriptor >= 0 {
            0
        } else {
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO)
        };
        write_status_bytes(opened_fd, &descriptor.to_ne_bytes())?;
        Ok(errno)
    })
}

#[pyfunction]
#[cfg(unix)]
fn _open_existing_private_file_fd_once(
    opened_fd: &Bound<'_, PyByteArray>,
    path: &[u8],
    dir_fd: i32,
) -> PyResult<i32> {
    ffi_boundary(|| {
        if opened_fd.len() != std::mem::size_of::<i32>()
            || opened_fd.to_vec() != (-1_i32).to_ne_bytes()
        {
            return Err(PyValueError::new_err(
                "Native existing-file status buffer must contain one negative descriptor",
            ));
        }
        let path = CString::new(path)
            .map_err(|_| PyValueError::new_err("Native existing-file path contains a null byte"))?;
        let descriptor =
            unsafe { libc::openat(dir_fd, path.as_ptr(), EXISTING_PRIVATE_FILE_OPEN_FLAGS) };
        let errno = if descriptor >= 0 {
            0
        } else {
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO)
        };
        write_status_bytes(opened_fd, &descriptor.to_ne_bytes())?;
        Ok(errno)
    })
}

#[pyfunction]
#[cfg(not(unix))]
#[pyo3(signature = (_opened_fd, _path, _dir_fd=None))]
fn _open_directory_fd_once(
    _opened_fd: &Bound<'_, PyByteArray>,
    _path: &[u8],
    _dir_fd: Option<i32>,
) -> PyResult<i32> {
    Err(PyOSError::new_err(
        "Native directory transactions require a Unix platform",
    ))
}

#[pyfunction]
#[cfg(not(unix))]
fn _repair_and_open_directory_fd_once(
    _opened_fd: &Bound<'_, PyByteArray>,
    _path: &[u8],
    _dir_fd: i32,
    _expected_device: u64,
    _expected_inode: u64,
) -> PyResult<i32> {
    Err(PyOSError::new_err(
        "Native descriptor transactions require a Unix platform",
    ))
}

#[pyfunction]
#[cfg(not(unix))]
fn _open_private_file_fd_once(
    _opened_fd: &Bound<'_, PyByteArray>,
    _path: &[u8],
    _dir_fd: i32,
) -> PyResult<i32> {
    Err(PyOSError::new_err(
        "Native private-file transactions require a Unix platform",
    ))
}

#[pyfunction]
#[cfg(not(unix))]
fn _open_existing_private_file_fd_once(
    _opened_fd: &Bound<'_, PyByteArray>,
    _path: &[u8],
    _dir_fd: i32,
) -> PyResult<i32> {
    Err(PyOSError::new_err(
        "Native existing-file transactions require a Unix platform",
    ))
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
            metadata.set_item(
                "build_source_sha256",
                env!("NERB_NATIVE_BUILD_SOURCE_SHA256"),
            )?;

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

            let scan_limits = PyDict::new(py);
            scan_limits.set_item("maximum_input_bytes", MAX_SCAN_INPUT_BYTES)?;
            scan_limits.set_item(
                "maximum_concurrent_scans_per_bank",
                MAX_CONCURRENT_SCANS_PER_ENGINE,
            )?;
            metadata.set_item("scan_limits", scan_limits)?;

            if match_mode.as_str() == "entity_independent" {
                let resources = self
                    .inner
                    .regex_resource_profile()
                    .expect("entity-independent mode must expose its regex resource profile");
                let regex_resources = PyDict::new(py);
                regex_resources.set_item("scope", "entity_independent_shards")?;
                regex_resources
                    .set_item("physical_regex_layers", resources.physical_regex_layers)?;
                regex_resources.set_item(
                    "maximum_regex_layers_per_entity",
                    resources.maximum_regex_layers_per_entity,
                )?;
                regex_resources.set_item(
                    "compiled_regex_static_bytes",
                    resources.compiled_regex_static_bytes,
                )?;
                regex_resources.set_item(
                    "eager_cache_bytes_per_scan",
                    resources.eager_cache_bytes_per_scan,
                )?;
                regex_resources.set_item(
                    "pikevm_cache_projection_bytes_per_scan",
                    resources.pikevm_cache_projection_bytes_per_scan,
                )?;
                regex_resources.set_item(
                    "pikevm_stack_growth_allowance_bytes_per_scan",
                    resources.pikevm_stack_growth_allowance_bytes_per_scan,
                )?;
                regex_resources.set_item(
                    "lazy_dfa_growth_allowance_bytes_per_scan",
                    resources.lazy_dfa_growth_allowance_bytes_per_scan,
                )?;
                regex_resources.set_item(
                    "regex_cache_allowance_bytes",
                    resources.regex_cache_allowance_bytes,
                )?;
                regex_resources
                    .set_item("size_limit_bisections", resources.size_limit_bisections)?;
                regex_resources.set_item(
                    "resource_limit_bisections",
                    resources.resource_limit_bisections,
                )?;
                regex_resources.set_item(
                    "accounted_bytes",
                    resources.compiled_regex_static_bytes + resources.regex_cache_allowance_bytes,
                )?;
                regex_resources
                    .set_item("cache_concurrency_budget", MAX_CONCURRENT_SCANS_PER_ENGINE)?;
                regex_resources.set_item(
                    "explicit_regex_cache_slots",
                    MAX_CONCURRENT_SCANS_PER_ENGINE,
                )?;
                regex_resources.set_item("internal_meta_cache_pool_used", false)?;
                regex_resources.set_item(
                    "per_lazy_dfa_cache_capacity_bytes",
                    ENTITY_INDEPENDENT_REGEX_CACHE_CAPACITY,
                )?;
                regex_resources.set_item(
                    "maximum_lazy_dfa_caches_per_regex",
                    MAX_LAZY_DFA_CACHES_PER_META_REGEX,
                )?;
                regex_resources.set_item(
                    "pikevm_stack_nfa_memory_multiplier",
                    PIKEVM_STACK_NFA_MEMORY_MULTIPLIER,
                )?;
                regex_resources.set_item("onepass_enabled", false)?;
                regex_resources.set_item("bounded_backtracker_enabled", false)?;
                regex_resources.set_item(
                    "maximum_layers_per_entity",
                    MAX_ENTITY_INDEPENDENT_REGEX_LAYERS_PER_ENTITY,
                )?;
                regex_resources.set_item(
                    "maximum_patterns_per_regex_layer",
                    MAX_PATTERNS_PER_BOUNDED_REGEX_LAYER,
                )?;
                regex_resources.set_item(
                    "maximum_accounted_bytes",
                    MAX_ENTITY_INDEPENDENT_REGEX_ACCOUNTED_BYTES,
                )?;
                metadata.set_item("regex_resources", regex_resources)?;
            }

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

    fn detector_metadata(&self, detector_index: u32) -> PyResult<(String, String, String)> {
        ffi_boundary(|| {
            let index = usize::try_from(detector_index).map_err(|_| {
                PyIndexError::new_err(format!("detector index {detector_index} out of range"))
            })?;
            let detector = self.inner.detectors().get(index).ok_or_else(|| {
                PyIndexError::new_err(format!("detector index {detector_index} out of range"))
            })?;
            Ok((
                detector.entity.clone(),
                detector.canonical_name.clone(),
                detector.surface_name.clone(),
            ))
        })
    }

    #[pyo3(signature = (haystack, out=None))]
    fn scan_bytes(
        &self,
        py: Python<'_>,
        haystack: &[u8],
        out: Option<Py<PyMatchBuffer>>,
    ) -> PyResult<Py<PyMatchBuffer>> {
        ffi_boundary(|| {
            let size_result = validate_scan_input_size(haystack).map_err(PyErr::from);
            match out {
                Some(out) => {
                    let mut buffer = {
                        let mut borrowed = out.bind(py).borrow_mut();
                        std::mem::take(&mut borrowed.inner)
                    };
                    buffer.clear();
                    let scan_result = size_result.and_then(|()| {
                        py.detach(|| self.inner.scan_bytes_into(haystack, &mut buffer))
                            .map_err(PyErr::from)
                    });
                    out.bind(py).borrow_mut().inner = buffer;
                    scan_result?;
                    Ok(out)
                }
                None => {
                    size_result?;
                    let buffer = py.detach(|| self.inner.scan_bytes(haystack))?;
                    Py::new(py, PyMatchBuffer { inner: buffer })
                }
            }
        })
    }

    fn scan_bytes_bounded(
        &self,
        py: Python<'_>,
        haystack: &[u8],
        max_matches: usize,
    ) -> PyResult<Py<PyMatchBuffer>> {
        ffi_boundary(|| {
            validate_scan_input_size(haystack).map_err(PyErr::from)?;
            let buffer = py.detach(|| self.inner.scan_bytes_bounded(haystack, max_matches))?;
            Py::new(py, PyMatchBuffer { inner: buffer })
        })
    }

    #[pyo3(signature = (haystack, out=None))]
    fn scan_bytes_leftmost_from_all_overlaps(
        &self,
        py: Python<'_>,
        haystack: &[u8],
        out: Option<Py<PyMatchBuffer>>,
    ) -> PyResult<Py<PyMatchBuffer>> {
        ffi_boundary(|| {
            let size_result = validate_scan_input_size(haystack).map_err(PyErr::from);
            match out {
                Some(out) => {
                    let mut buffer = {
                        let mut borrowed = out.bind(py).borrow_mut();
                        std::mem::take(&mut borrowed.inner)
                    };
                    buffer.clear();
                    let scan_result = size_result.and_then(|()| {
                        py.detach(|| {
                            self.inner
                                .scan_bytes_leftmost_from_all_overlaps(haystack, &mut buffer)
                        })
                        .map_err(PyErr::from)
                    });
                    out.bind(py).borrow_mut().inner = buffer;
                    scan_result?;
                    Ok(out)
                }
                None => {
                    size_result?;
                    let mut buffer = NativeMatchBuffer::new();
                    py.detach(|| {
                        self.inner
                            .scan_bytes_leftmost_from_all_overlaps(haystack, &mut buffer)
                    })?;
                    Py::new(py, PyMatchBuffer { inner: buffer })
                }
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
        .map_err(|error| {
            PyOSError::new_err(format!("Could not read document path {path:?}: {error}"))
        })?;
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
    module.add(
        "BUILD_SOURCE_SHA256",
        env!("NERB_NATIVE_BUILD_SOURCE_SHA256"),
    )?;
    module.add_class::<PyBank>()?;
    module.add_class::<PyMatchBuffer>()?;
    module.add_function(wrap_pyfunction!(_is_word_character, module)?)?;
    module.add_function(wrap_pyfunction!(_close_fd_once, module)?)?;
    module.add_function(wrap_pyfunction!(_fsync_fd_commit, module)?)?;
    module.add_function(wrap_pyfunction!(_open_directory_fd_once, module)?)?;
    module.add_function(wrap_pyfunction!(
        _repair_and_open_directory_fd_once,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(_open_private_file_fd_once, module)?)?;
    module.add_function(wrap_pyfunction!(
        _open_existing_private_file_fd_once,
        module
    )?)?;
    Ok(())
}

#[cfg(test)]
mod word_character_tests {
    use super::native_is_word_character;

    #[test]
    fn regex_syntax_word_semantics_cover_non_category_alphabetics() {
        assert!(native_is_word_character('\u{24B6}'));
        assert!(native_is_word_character('\u{0301}'));
        assert!(native_is_word_character('\u{200C}'));
        assert!(native_is_word_character('\u{200D}'));
        assert!(!native_is_word_character('\u{2014}'));
    }
}
