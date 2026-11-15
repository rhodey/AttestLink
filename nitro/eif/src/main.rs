//! Small command-line adapter for Firecracker's released EIF writer.
//! The writer itself is kept byte-for-byte in upstream.rs; see README.md.

#[allow(dead_code)]
mod upstream;

mod utils {
    pub fn u64_to_usize(value: u64) -> usize {
        usize::try_from(value).expect("EIF offset exceeds address space")
    }
}

use std::env;
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::Write;

fn run() -> Result<(), Box<dyn Error>> {
    // This adapter deliberately exposes one qualified launch profile.
    // Changing CPU/memory/feature settings requires updating both image and VMM.
    if !cfg!(target_arch = "aarch64") {
        return Err("this image builder targets ARM64; build and run it on ARM64".into());
    }
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() != 4 {
        return Err("usage: nitro-eif-write KERNEL INITRAMFS CMDLINE OUTPUT".into());
    }
    let [kernel_path, initramfs_path, cmdline, output_path] = args.as_slice() else {
        unreachable!()
    };
    if cmdline.contains('\0') || cmdline.len() > 4095 {
        return Err("kernel command line must be at most 4095 bytes with no NUL".into());
    }
    let kernel = File::open(kernel_path)?;
    let initramfs = File::open(initramfs_path)?;
    if initramfs.metadata()?.len() == 0 {
        return Err("initramfs must not be empty".into());
    }
    let image = upstream::EifImage::new(
        &kernel,
        kernel_path,
        Some((&initramfs, initramfs_path)),
        cmdline.clone(),
        2048 * 1024 * 1024,
        1,
        upstream::EIF_HDR_FLAG_PCIE | upstream::EIF_HDR_FLAG_PCIE_VIRTIO,
    )?;
    // Limit the loaded image to half of our fixed 2 GiB Sandbox's memory.
    if image.size() > 1024 * 1024 * 1024 {
        return Err("EIF exceeds this profile's 1 GiB image-size limit".into());
    }
    let mut bytes = vec![0; image.size()];
    image.write(&mut bytes)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)?;
    output.write_all(&bytes)?;
    output.sync_all()?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("nitro-eif-write: {error}");
        std::process::exit(1);
    }
}
