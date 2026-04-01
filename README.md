# vshadow-rs

Pure Rust parser for the Windows **Volume Shadow Snapshot (VSS)** format.

Enumerates and reads shadow copies from NTFS volumes — works with raw disk images (E01, dd, raw) and live drives.

## Features

- Parse VSS volume header, catalog, and store metadata
- Enumerate all shadow copies with creation time, machine name, GUIDs
- Read block descriptors (copy-on-write block map)
- No C dependencies — pure Rust, no FFI, no libvshadow
- Works with any `Read + Seek` source (files, E01 readers, disk handles)

## Usage

```rust
use vshadow_rs::{read_vss_header, read_catalog, read_block_descriptors};

let mut source = std::fs::File::open(r"\\.\C:").unwrap();

if let Some(header) = read_vss_header(&mut source).unwrap() {
    let shadows = read_catalog(&mut source, &header).unwrap();
    for sc in &shadows {
        println!("{} - created {}", sc.shadow_copy_id, sc.creation_time);
    }
}
```

## Acknowledgments

This is a clean-room Rust implementation based on the **Volume Shadow Snapshot format specification** documented by [Joachim Metz](https://github.com/joachimmetz) as part of the [libvshadow](https://github.com/libyal/libvshadow) project.

The format specification is available at:
https://github.com/libyal/libvshadow/blob/main/documentation/Volume%20Shadow%20Snapshot%20(VSS)%20format.asciidoc

**libvshadow** is copyright (C) 2011-2024 Joachim Metz and is licensed under the LGPL. This Rust implementation is an independent port that does not use or link to any libvshadow code, but would not have been possible without Metz's extensive reverse engineering and documentation of the VSS on-disk format.

## License

MIT — see [LICENSE](LICENSE)
