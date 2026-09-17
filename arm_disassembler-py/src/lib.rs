//! Python bindings for arm_disassembler (ARM64 decode + format).

use ::arm_disassembler::{decode_raw, Decoder, Formatter};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;

/// Disassemble ARM64 machine code.
#[pyfunction]
#[pyo3(signature = (data, base_vaddr=0))]
fn disassemble(py: Python<'_>, data: &[u8], base_vaddr: u64) -> PyResult<Vec<PyObject>> {
    let mut dec = Decoder::new(data, base_vaddr);
    let fmt = Formatter::new();
    let mut out = Vec::new();
    while dec.can_decode() {
        let ins = dec.decode();
        let dict = PyDict::new_bound(py);
        dict.set_item("vaddr", ins.vaddr)?;
        dict.set_item("raw", ins.raw)?;
        dict.set_item("length", ins.len)?;
        dict.set_item("mnemonic", ins.mnemonic.as_str())?;
        dict.set_item("text", fmt.format_simple(&ins))?;
        out.push(dict.into_py(py));
    }
    Ok(out)
}

/// Decode a single 32-bit A64 instruction word.
#[pyfunction]
#[pyo3(signature = (raw, vaddr=0))]
fn decode_one(py: Python<'_>, raw: u32, vaddr: u64) -> PyResult<PyObject> {
    let ins = decode_raw(vaddr, raw);
    let fmt = Formatter::new();
    let dict = PyDict::new_bound(py);
    dict.set_item("vaddr", ins.vaddr)?;
    dict.set_item("raw", ins.raw)?;
    dict.set_item("length", ins.len)?;
    dict.set_item("mnemonic", ins.mnemonic.as_str())?;
    dict.set_item("text", fmt.format_simple(&ins))?;
    Ok(dict.into_py(py))
}

/// Convenience: decode one instruction from 4 little-endian bytes.
#[pyfunction]
#[pyo3(signature = (data, vaddr=0))]
fn decode_bytes(py: Python<'_>, data: &[u8], vaddr: u64) -> PyResult<PyObject> {
    if data.len() < 4 {
        return Err(PyValueError::new_err("need at least 4 bytes"));
    }
    let raw = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    decode_one(py, raw, vaddr)
}

#[pymodule]
fn arm_disassembler(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(disassemble, m)?)?;
    m.add_function(wrap_pyfunction!(decode_one, m)?)?;
    m.add_function(wrap_pyfunction!(decode_bytes, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
