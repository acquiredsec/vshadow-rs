//! vshadow-rs — Pure Rust parser for Windows Volume Shadow Snapshot (VSS) format.
//!
//! Based on Joachim Metz's format specification:
//! https://github.com/libyal/libvshadow/blob/main/documentation/Volume%20Shadow%20Snapshot%20(VSS)%20format.asciidoc
//!
//! VSS stores persistent shadow copies on NTFS volumes using 16KB copy-on-write blocks.
//! The volume header at offset 0x1e00 points to a catalog which lists all snapshots.
//! Each snapshot has a store containing block descriptors that map changed blocks.

use anyhow::{anyhow, Result};
use std::io::{Read, Seek, SeekFrom};

/// VSS volume header offset within the NTFS volume (0x1e00 = 7680 bytes).
const VSS_HEADER_OFFSET: u64 = 0x1e00;

/// Catalog/store block size (16KB).
const BLOCK_SIZE: u64 = 0x4000;

/// Catalog block header size.
const CATALOG_HEADER_SIZE: u64 = 128;

/// Catalog entry size.
const CATALOG_ENTRY_SIZE: u64 = 128;

/// VSS identifier GUID used to validate VSS structures.
const VSS_GUID: [u8; 16] = [
    0x6B, 0x87, 0x08, 0x38, 0x76, 0xC1, 0x48, 0x4E,
    0xB7, 0xAE, 0x04, 0x04, 0x6E, 0x6C, 0xC7, 0x52,
];

/// Read a little-endian u32 from a byte slice.
fn read_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap())
}

/// Read a little-endian u64 from a byte slice.
fn read_u64(buf: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(buf[offset..offset + 8].try_into().unwrap())
}

/// Read a GUID (16 bytes) from a byte slice and format as string.
fn read_guid(buf: &[u8], offset: usize) -> String {
    let b = &buf[offset..offset + 16];
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes(b[0..4].try_into().unwrap()),
        u16::from_le_bytes(b[4..6].try_into().unwrap()),
        u16::from_le_bytes(b[6..8].try_into().unwrap()),
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

/// Convert FILETIME (100-nanosecond intervals since 1601-01-01) to a human-readable string.
fn filetime_to_string(ft: u64) -> String {
    if ft == 0 { return String::new(); }
    // FILETIME epoch: 1601-01-01 00:00:00 UTC
    // Unix epoch: 1970-01-01 00:00:00 UTC
    // Difference: 11644473600 seconds
    let unix_secs = (ft / 10_000_000).saturating_sub(11_644_473_600);
    let dt = chrono::DateTime::from_timestamp(unix_secs as i64, 0);
    match dt {
        Some(d) => d.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => format!("FILETIME:{}", ft),
    }
}

/// VSS volume header — found at offset 0x1e00 in the NTFS volume.
#[derive(Debug, Clone)]
pub struct VssVolumeHeader {
    pub vss_id: String,
    pub version: u32,
    pub catalog_offset: u64,
    pub max_size: u64,
    pub volume_id: String,
    pub storage_volume_id: String,
}

/// A shadow copy snapshot found in the VSS catalog.
#[derive(Debug, Clone)]
pub struct VssShadowCopy {
    pub store_id: String,
    pub shadow_copy_id: String,
    pub shadow_copy_set_id: String,
    pub creation_time: String,
    pub creation_time_raw: u64,
    pub volume_size: u64,
    pub store_header_offset: u64,
    pub store_block_list_offset: u64,
    pub store_block_range_list_offset: u64,
    pub operating_machine: String,
    pub service_machine: String,
    pub snapshot_context: u32,
    pub attribute_flags: u32,
}

/// A block descriptor — maps an original block to its snapshot data.
#[derive(Debug, Clone)]
pub struct VssBlockDescriptor {
    pub original_offset: u64,
    pub relative_store_offset: u64,
    pub store_data_offset: u64,
    pub flags: u32,
    pub allocation_bitmap: u32,
}

/// Parse VSS volume header from an NTFS volume.
pub fn read_vss_header<R: Read + Seek + ?Sized>(source: &mut R) -> Result<Option<VssVolumeHeader>> {
    source.seek(SeekFrom::Start(VSS_HEADER_OFFSET))?;
    let mut buf = [0u8; 512];
    source.read_exact(&mut buf)?;

    // Verify VSS identifier
    if buf[0..16] != VSS_GUID {
        return Ok(None); // No VSS on this volume
    }

    let version = read_u32(&buf, 16);
    let record_type = read_u32(&buf, 20);
    if record_type != 0x01 {
        return Ok(None); // Not a volume header
    }

    let catalog_offset = read_u64(&buf, 48);
    let max_size = read_u64(&buf, 56);
    let volume_id = read_guid(&buf, 64);
    let storage_volume_id = read_guid(&buf, 80);

    Ok(Some(VssVolumeHeader {
        vss_id: read_guid(&buf, 0),
        version,
        catalog_offset,
        max_size,
        volume_id,
        storage_volume_id,
    }))
}

/// Read all shadow copies from the VSS catalog.
pub fn read_catalog<R: Read + Seek + ?Sized>(source: &mut R, header: &VssVolumeHeader) -> Result<Vec<VssShadowCopy>> {
    if header.catalog_offset == 0 {
        return Ok(Vec::new()); // No catalog = no snapshots
    }

    let mut shadows = Vec::new();
    let mut catalog_offset = header.catalog_offset;

    // Temporary storage for type 0x02 entries (keyed by store_id)
    let mut type02_entries: std::collections::HashMap<String, Type02Entry> = std::collections::HashMap::new();
    // Temporary storage for type 0x03 entries
    let mut type03_entries: Vec<Type03Entry> = Vec::new();

    loop {
        // Read catalog block
        source.seek(SeekFrom::Start(catalog_offset))?;
        let mut block = vec![0u8; BLOCK_SIZE as usize];
        source.read_exact(&mut block)?;

        // Verify catalog block header
        if block[0..16] != VSS_GUID {
            break; // Invalid block
        }
        let record_type = read_u32(&block, 20);
        if record_type != 0x02 {
            break; // Not a catalog block
        }

        let next_offset = read_u64(&block, 40);

        // Parse catalog entries (after 128-byte header)
        let entries_per_block = (BLOCK_SIZE - CATALOG_HEADER_SIZE) / CATALOG_ENTRY_SIZE;
        for i in 0..entries_per_block {
            let offset = (CATALOG_HEADER_SIZE + i * CATALOG_ENTRY_SIZE) as usize;
            let entry_type = read_u64(&block, offset);

            match entry_type {
                0x02 => {
                    let volume_size = read_u64(&block, offset + 8);
                    let store_id = read_guid(&block, offset + 16);
                    let creation_time_raw = read_u64(&block, offset + 48);
                    let creation_time = filetime_to_string(creation_time_raw);

                    type02_entries.insert(store_id.clone(), Type02Entry {
                        store_id,
                        volume_size,
                        creation_time,
                        creation_time_raw,
                    });
                }
                0x03 => {
                    let store_block_list_offset = read_u64(&block, offset + 8);
                    let store_id = read_guid(&block, offset + 16);
                    let store_header_offset = read_u64(&block, offset + 32);
                    let store_block_range_list_offset = read_u64(&block, offset + 40);

                    type03_entries.push(Type03Entry {
                        store_id,
                        store_block_list_offset,
                        store_header_offset,
                        store_block_range_list_offset,
                    });
                }
                0x01 | 0x00 => {} // Unused entry, skip
                _ => {} // Unknown, skip
            }
        }

        if next_offset == 0 {
            break; // Last catalog block
        }
        catalog_offset = next_offset;
    }

    // Match type 0x02 and type 0x03 entries by store_id
    for t03 in &type03_entries {
        if let Some(t02) = type02_entries.get(&t03.store_id) {
            // Read store information to get shadow copy details
            let store_info = read_store_info(source, t03.store_header_offset)?;

            shadows.push(VssShadowCopy {
                store_id: t02.store_id.clone(),
                shadow_copy_id: store_info.shadow_copy_id,
                shadow_copy_set_id: store_info.shadow_copy_set_id,
                creation_time: t02.creation_time.clone(),
                creation_time_raw: t02.creation_time_raw,
                volume_size: t02.volume_size,
                store_header_offset: t03.store_header_offset,
                store_block_list_offset: t03.store_block_list_offset,
                store_block_range_list_offset: t03.store_block_range_list_offset,
                operating_machine: store_info.operating_machine,
                service_machine: store_info.service_machine,
                snapshot_context: store_info.snapshot_context,
                attribute_flags: store_info.attribute_flags,
            });
        }
    }

    // Sort by creation time (newest first)
    shadows.sort_by(|a, b| b.creation_time_raw.cmp(&a.creation_time_raw));

    Ok(shadows)
}

/// Read block descriptors from a store's block list.
/// These map original volume offsets to their snapshot data locations.
pub fn read_block_descriptors<R: Read + Seek + ?Sized>(
    source: &mut R,
    block_list_offset: u64,
) -> Result<Vec<VssBlockDescriptor>> {
    let mut descriptors = Vec::new();
    let mut current_offset = block_list_offset;

    loop {
        source.seek(SeekFrom::Start(current_offset))?;
        let mut block = vec![0u8; BLOCK_SIZE as usize];
        source.read_exact(&mut block)?;

        // Verify block header
        if block[0..16] != VSS_GUID {
            break;
        }
        let record_type = read_u32(&block, 20);
        if record_type != 0x03 {
            break; // Not a block descriptor list
        }

        let next_offset = read_u64(&block, 40);

        // Parse block descriptors (after 128-byte header, each is 32 bytes)
        let entries_per_block = (BLOCK_SIZE - 128) / 32;
        for i in 0..entries_per_block {
            let offset = (128 + i * 32) as usize;
            let original_offset = read_u64(&block, offset);
            let relative_store_offset = read_u64(&block, offset + 8);
            let store_data_offset = read_u64(&block, offset + 16);
            let flags = read_u32(&block, offset + 24);
            let allocation_bitmap = read_u32(&block, offset + 28);

            // Skip empty entries
            if original_offset == 0 && store_data_offset == 0 {
                continue;
            }
            // Skip "not used" flagged entries
            if flags & 0x04 != 0 {
                continue;
            }

            descriptors.push(VssBlockDescriptor {
                original_offset,
                relative_store_offset,
                store_data_offset,
                flags,
                allocation_bitmap,
            });
        }

        if next_offset == 0 {
            break;
        }
        current_offset = next_offset;
    }

    Ok(descriptors)
}

// --- Internal types ---

struct Type02Entry {
    store_id: String,
    volume_size: u64,
    creation_time: String,
    creation_time_raw: u64,
}

struct Type03Entry {
    store_id: String,
    store_block_list_offset: u64,
    store_header_offset: u64,
    store_block_range_list_offset: u64,
}

struct StoreInfo {
    shadow_copy_id: String,
    shadow_copy_set_id: String,
    snapshot_context: u32,
    attribute_flags: u32,
    operating_machine: String,
    service_machine: String,
}

fn read_store_info<R: Read + Seek + ?Sized>(source: &mut R, store_header_offset: u64) -> Result<StoreInfo> {
    // Read store block header + store information
    source.seek(SeekFrom::Start(store_header_offset))?;
    let mut block = vec![0u8; BLOCK_SIZE as usize];
    source.read_exact(&mut block)?;

    // Verify
    if block[0..16] != VSS_GUID {
        return Err(anyhow!("Invalid store header at offset {}", store_header_offset));
    }

    // Store info starts after the 128-byte block header
    let info_offset = 128;
    // Skip unknown GUID at offset 0
    let shadow_copy_id = read_guid(&block, info_offset + 16);
    let shadow_copy_set_id = read_guid(&block, info_offset + 32);
    let snapshot_context = read_u32(&block, info_offset + 48);
    let attribute_flags = read_u32(&block, info_offset + 56);

    // Read operating machine string
    let os_str_size = u16::from_le_bytes(
        block[info_offset + 64..info_offset + 66].try_into().unwrap()
    ) as usize;
    let operating_machine = if os_str_size > 0 && info_offset + 66 + os_str_size <= block.len() {
        let utf16: Vec<u16> = block[info_offset + 66..info_offset + 66 + os_str_size]
            .chunks(2)
            .filter_map(|c| c.try_into().ok().map(u16::from_le_bytes))
            .collect();
        String::from_utf16_lossy(&utf16).trim_end_matches('\0').to_string()
    } else {
        String::new()
    };

    // Read service machine string (after operating machine)
    let svc_offset = info_offset + 66 + os_str_size;
    let service_machine = if svc_offset + 2 <= block.len() {
        let svc_str_size = u16::from_le_bytes(
            block[svc_offset..svc_offset + 2].try_into().unwrap()
        ) as usize;
        if svc_str_size > 0 && svc_offset + 2 + svc_str_size <= block.len() {
            let utf16: Vec<u16> = block[svc_offset + 2..svc_offset + 2 + svc_str_size]
                .chunks(2)
                .filter_map(|c| c.try_into().ok().map(u16::from_le_bytes))
                .collect();
            String::from_utf16_lossy(&utf16).trim_end_matches('\0').to_string()
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    Ok(StoreInfo {
        shadow_copy_id,
        shadow_copy_set_id,
        snapshot_context,
        attribute_flags,
        operating_machine,
        service_machine,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guid_format() {
        let bytes = [
            0x6B, 0x87, 0x08, 0x38, 0x76, 0xC1, 0x48, 0x4E,
            0xB7, 0xAE, 0x04, 0x04, 0x6E, 0x6C, 0xC7, 0x52,
        ];
        let guid = read_guid(&bytes, 0);
        assert_eq!(guid, "3808876b-c176-4e48-b7ae-04046e6cc752");
    }

    #[test]
    fn test_filetime_to_string() {
        // 2019-03-22 04:35:32 UTC
        let ft = 132003741320000000u64;
        let s = filetime_to_string(ft);
        assert!(s.contains("2019"), "Expected 2019, got: {}", s);
    }
}
