// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

//! Implementation of a tool that generates a simple IGVM file that is used
//! to generate test data for the C API unit tests.

use std::fs::File;
use std::io::Write;
use std::io::Read;
use std::error::Error;
use clap::{Parser, ValueEnum};

use igvm::Arch;
use igvm::IgvmDirectiveHeader;
use igvm::IgvmFile;
use igvm::IgvmInitializationHeader;
use igvm::IgvmPlatformHeader;
use igvm::IgvmRevision;
use igvm_defs::IgvmPageDataFlags;
use igvm_defs::IgvmPageDataType;
use igvm_defs::IgvmPlatformType;
use igvm_defs::IGVM_VHS_PARAMETER;
use igvm_defs::IGVM_VHS_PARAMETER_INSERT;
use igvm_defs::IGVM_VHS_SUPPORTED_PLATFORM;
use igvm_defs::PAGE_SIZE_4K;

fn new_platform(compatibility_mask: u32, platform_type: IgvmPlatformType) -> IgvmPlatformHeader {
    IgvmPlatformHeader::SupportedPlatform(IGVM_VHS_SUPPORTED_PLATFORM {
        compatibility_mask,
        highest_vtl: 0,
        platform_type,
        platform_version: 1,
        shared_gpa_boundary: 0,
    })
}

fn new_guest_policy(policy: u64, compatibility_mask: u32) -> IgvmInitializationHeader {
    IgvmInitializationHeader::GuestPolicy {
        policy,
        compatibility_mask,
    }
}

fn new_page_data(page: u64, compatibility_mask: u32, data: &[u8]) -> IgvmDirectiveHeader {
    IgvmDirectiveHeader::PageData {
        gpa: page * PAGE_SIZE_4K,
        compatibility_mask,
        flags: IgvmPageDataFlags::new(),
        data_type: IgvmPageDataType::NORMAL,
        data: data.to_vec(),
    }
}

fn new_parameter_area(index: u32) -> IgvmDirectiveHeader {
    IgvmDirectiveHeader::ParameterArea {
        number_of_bytes: 4096,
        parameter_area_index: index,
        initial_data: vec![],
    }
}

fn new_parameter_usage(index: u32) -> IgvmDirectiveHeader {
    IgvmDirectiveHeader::VpCount(IGVM_VHS_PARAMETER {
        parameter_area_index: index,
        byte_offset: 0,
    })
}

fn new_parameter_insert(page: u64, index: u32, mask: u32) -> IgvmDirectiveHeader {
    IgvmDirectiveHeader::ParameterInsert(IGVM_VHS_PARAMETER_INSERT {
        gpa: page * PAGE_SIZE_4K,
        parameter_area_index: index,
        compatibility_mask: mask,
    })
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum Platform {
    /// Virtual Secure Mode based isolation
    VSM,
    /// ARM64 CCA based isolation
    CCA,
}

#[derive(Parser, Debug)]
pub struct CmdOptions {
    #[arg(long, value_enum, default_value = "vsm")]
    pub platform: Option<Platform>,

    #[arg(long, value_parser = parse_pagefile, help = "<PAGE_FILE> = file:gpa")]
    pub page_file: Option<Vec<PageFile>>,

    #[arg(long, value_parser = parse_u64)]
    pub page_size: Option<u64>,

    /// Output filename for the generated IGVM file
    pub output: String,
}

#[derive(Debug, Clone)]
pub struct PageFile {
    name: String,
    gpa: u64,
}

fn parse_u64(s: &str) -> Result<u64, String> {
    if s.starts_with("0x") || s.starts_with("0X") {
        // Hexadecimal
        u64::from_str_radix(&s[2..], 16).map_err(|e| {
            format!("Failed to parse hex '{}': {}", s, e)
        })
    } else {
        // Decimal
        s.parse::<u64>().map_err(|e| {
            format!("Failed to parse decimal '{}': {}", s, e)
        })
    }
}

fn parse_pagefile(s: &str) -> Result<PageFile, String> {
    let parts: Vec<_> = s.split(':').collect();

    if parts.len() != 2 {
        return Err("Format must be file_name:gpa".into());
    }

    let gpa = parse_u64(parts[1])?;

    Ok(PageFile{name: parts[0].into(), gpa})
}

fn main() -> Result<(), Box<dyn Error>> {
    let options = CmdOptions::parse();
    let compatibility_mask = 0x1;
    let compatibility_mask2 = 0x2;
    let filename = options.output;
    let page_size = match options.page_size {
        Some(s) => s,
        None => 4096,
    };
    let mut revision = IgvmRevision::V1;
    let mut initialization_headers: Vec<IgvmInitializationHeader> = Vec::new();
    let mut directive_headers: Vec<IgvmDirectiveHeader> = Vec::new();
    let platform_type = match options.platform {
        Some(Platform::VSM) => IgvmPlatformType::VSM_ISOLATION,
        Some(Platform::CCA) => {
            revision = IgvmRevision::V2 {
                arch: Arch::AArch64,
                page_size: page_size as u32,
            };
            initialization_headers = vec![new_guest_policy(0, compatibility_mask)];
            IgvmPlatformType::CCA
        }
        // Should never get here as platform defaults to VSM
        None => return Err("Platform argument is missing".into()),
    };
    if let Some(page_file) = options.page_file {
        for file in &page_file {
            let mut fd = File::open(&file.name).map_err(|e| {
                eprintln!("Failed to open page data file {}", file.name);
                e
            })?;

            let len = fd.metadata()?.len() as usize;
            if len > 0x100000000usize {
                return Err("page data file is too large (> 4G)".into());
            }
            let mut data = Vec::with_capacity(len);
            if fd.read_to_end(&mut data)? != len {
                return Err("Failed to read page data file".into());
            }

            let mut gpa = file.gpa;
            for page in data.chunks(page_size as usize) {
                directive_headers.push(IgvmDirectiveHeader::PageData {
                    gpa,
                    compatibility_mask,
                    flags: IgvmPageDataFlags::new(),
                    data_type: IgvmPageDataType::NORMAL,
                    data: page.to_vec(),
                });
                gpa += page_size;
            }
        }
    } else {
        let data1 = vec![1; PAGE_SIZE_4K as usize];
        let data2 = vec![2; PAGE_SIZE_4K as usize];
        let data3 = vec![3; PAGE_SIZE_4K as usize];
        let data4 = vec![4; PAGE_SIZE_4K as usize];
        directive_headers = vec![
            new_page_data(0, compatibility_mask, &data1),
            new_page_data(1, compatibility_mask, &data2),
            new_page_data(2, compatibility_mask, &data3),
            new_page_data(4, compatibility_mask, &data4),
            new_page_data(10, compatibility_mask, &data1),
            new_page_data(11, compatibility_mask, &data2),
            new_page_data(12, compatibility_mask, &data3),
            new_page_data(14, compatibility_mask, &data4),
            new_parameter_area(0),
            new_parameter_usage(0),
            new_parameter_insert(20, 0, 1),
        ];

        initialization_headers = vec![
            new_guest_policy(0x30000, compatibility_mask),
            new_guest_policy(0x30000, compatibility_mask2)
        ];
    }
    let file = IgvmFile::new(
        revision,
        vec![new_platform(compatibility_mask, platform_type)],
        initialization_headers,
        directive_headers,
    )
    .expect("Failed to create file");
    let mut binary_file = Vec::new();
    file.serialize(&mut binary_file).unwrap();

    let mut file = File::create(filename).expect("Could not open file");
    file.write_all(binary_file.as_slice())
        .expect("Failed to write file");

    Ok(())
}
