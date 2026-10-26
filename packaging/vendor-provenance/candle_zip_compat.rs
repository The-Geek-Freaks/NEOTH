use candle_core::{DType, Device, Error, Tensor, npy::NpzTensors, pickle::PthTensors};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use tempfile::tempdir;
use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};

const FORTRAN_PTH: &[u8] = include_bytes!("../../vendor/candle-core/tests/fortran_tensor_3d.pth");

fn assert_tensor(tensor: &Tensor, expected: Vec<Vec<i64>>) {
    assert_eq!(tensor.dtype(), DType::I64);
    assert_eq!(tensor.dims(), [expected.len(), expected[0].len()]);
    assert_eq!(tensor.to_vec2::<i64>().unwrap(), expected);
}

#[test]
fn npz_roundtrip_preserves_named_tensors_and_unicode() -> anyhow::Result<()> {
    let directory = tempdir()?;
    let path = directory.path().join("roundtrip.npz");
    let first = Tensor::from_vec(vec![11_i64, 12, 13, 21, 22, 23], (2, 3), &Device::Cpu)?;
    let second = Tensor::from_vec(vec![101_i64, 102, 103, 104], (2, 2), &Device::Cpu)?;
    Tensor::write_npz(&[("numbers", &first), ("größen", &second)], &path)?;
    let all: HashMap<_, _> = Tensor::read_npz(&path)?.into_iter().collect();
    assert_eq!(all.len(), 2);
    assert_tensor(&all["numbers"], vec![vec![11, 12, 13], vec![21, 22, 23]]);
    assert_tensor(&all["größen"], vec![vec![101, 102], vec![103, 104]]);
    let selected = Tensor::read_npz_by_name(&path, &["größen", "numbers"])?;
    assert_eq!(selected.len(), 2);
    assert_tensor(&selected[0], vec![vec![101, 102], vec![103, 104]]);
    assert_tensor(&selected[1], vec![vec![11, 12, 13], vec![21, 22, 23]]);
    let lazy = NpzTensors::new(&path)?;
    let (shape, dtype) = lazy.get_shape_and_dtype("größen")?;
    assert_eq!(shape.dims(), [2, 2]);
    assert_eq!(dtype, DType::I64);
    assert_tensor(
        &lazy.get("größen")?.unwrap(),
        vec![vec![101, 102], vec![103, 104]],
    );
    Ok(())
}

#[test]
fn pickle_discovers_metadata_and_reads_nonfirst_tensor_payload() -> anyhow::Result<()> {
    let directory = tempdir()?;
    let path = directory.path().join("with-readme.pth");
    let mut input = ZipArchive::new(std::io::Cursor::new(FORTRAN_PTH))?;
    let names = input
        .file_names()
        .map(|name| name.map(|name| name.into_owned()))
        .collect::<zip::result::ZipResult<Vec<String>>>()?;
    let mut writer = ZipWriter::new(File::create(&path)?);
    writer.start_file("README.txt", SimpleFileOptions::default())?;
    writer.write_all(b"unrelated first entry")?;
    for name in names {
        let mut entry = input.by_name(&name)?;
        let mut body = Vec::new();
        entry.read_to_end(&mut body)?;
        writer.start_file(name, SimpleFileOptions::default())?;
        writer.write_all(&body)?;
    }
    writer.finish()?;
    let tensors = PthTensors::new(&path, None)?;
    let info = &tensors.tensor_infos()["tensor_fortran"];
    let mut archive = ZipArchive::new(File::open(&path)?)?;
    assert!(archive.by_name(&info.path)?.size() > 0);
    let tensor = tensors.get("tensor_fortran")?.unwrap();
    assert_eq!(tensor.dtype(), DType::I64);
    assert_eq!(tensor.dims(), [2, 3, 4]);
    assert_eq!(
        tensor.flatten_all()?.to_vec1::<i64>()?,
        (1..=24).collect::<Vec<i64>>()
    );
    Ok(())
}

fn truncate_directory(path: &Path) -> anyhow::Result<()> {
    let mut bytes = std::fs::read(path)?;
    // Keep real member bytes; remove the central directory and end record.
    let central = bytes
        .windows(4)
        .position(|window| window == b"PK\x01\x02")
        .expect("valid fixture has a central directory");
    bytes.truncate(central);
    assert!(ZipArchive::new(std::io::Cursor::new(&bytes)).is_err());
    std::fs::write(path, bytes)?;
    Ok(())
}

fn assert_zip_error<T>(result: candle_core::Result<T>) {
    match result {
        Err(Error::Zip(_)) => {}
        Err(error) => panic!("expected ZIP error, got {error:?}"),
        Ok(_) => panic!("truncated archive was accepted"),
    }
}

#[test]
fn truncated_archive_errors_propagate_through_npz_and_pickle() -> anyhow::Result<()> {
    let directory = tempdir()?;
    let npz = directory.path().join("truncated.npz");
    let tensor = Tensor::from_vec(vec![1_i64, 2, 3, 4], (2, 2), &Device::Cpu)?;
    Tensor::write_npz(&[("probe", &tensor)], &npz)?;
    assert_tensor(&Tensor::read_npz(&npz)?[0].1, vec![vec![1, 2], vec![3, 4]]);
    assert!(NpzTensors::new(&npz)?.get("probe")?.is_some());
    truncate_directory(&npz)?;
    assert_zip_error(Tensor::read_npz(&npz));
    assert_zip_error(NpzTensors::new(&npz));

    let pth = directory.path().join("truncated.pth");
    std::fs::write(&pth, FORTRAN_PTH)?;
    assert!(PthTensors::new(&pth, None)?.get("tensor_fortran")?.is_some());
    truncate_directory(&pth)?;
    assert_zip_error(PthTensors::new(&pth, None));
    Ok(())
}
