use std::io;

pub struct Winmd {}

impl Winmd {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = vec![];
        result.extend(&DOS_HEADER);
        result.extend(&DOS_HEADER_SUFFIX);
        result.extend(&E_LFANEW);
        result.extend(&STUB_PROGRAM_PREFIX);
        result.extend(DOS_MESSAGE);
        result.extend(&DOS_MESSAGE_SUFFIX);
        result.extend(&STUB_PROGRAM_SUFFIX);
        result.extend(&PE_HEADER);

        let coff = COFFHeader::new(2, 0x5E9_DCF09);
        result.extend(&coff.to_bytes());
        let mut data_directory: [DataDirectory; 16] = Default::default();
        // imports
        data_directory[1] = DataDirectory {
            virtual_address: 0x0000_2154,
            size: 0x0000_0057,
        };
        // base relocation
        data_directory[5] = DataDirectory {
            virtual_address: 0x0000_4000,
            size: 0x0000_000C,
        };
        // import address
        data_directory[12] = DataDirectory {
            virtual_address: 0x0000_2000,
            size: 0x0000_0008,
        };
        // COM descriptor
        data_directory[14] = DataDirectory {
            virtual_address: 0x0000_2008,
            size: 0x0000_0048,
        };
        let header = PEOptHeader {
            // IMAGE_NT_OPTIONAL_HDR32_MAGIC
            signature: 0x010B,
            linker_version: 0x000B,
            size_code: 0x0000_0200,
            size_initialized_data: 0x0000_0200,

            entry_point: 0x0000_21AE,
            base_code: 0x0000_2000,
            base_data: 0x0000_4000,
            image_base: 0x0040_0000,
            section_alignment: 0x0000_2000,
            file_alignment: 0x0000_0200,
            os_version: 0x0000_0004,
            subsystem_version: 0x0000_0004,
            size_image: 0x0000_6000,
            size_headers: 0x0000_0200,
            subsystem: 0x0003,
            dll_characteristics: 0x8540,
            size_stack_reserve: 0x0010_0000,
            size_stack_commit: 0x0000_1000,
            size_heap_reserve: 0x0010_0000,
            size_heap_commit: 0x0000_1000,
            number_rva_sizes: 0x0000_0010,

            data_directory,
            ..Default::default()
        };
        result.extend(&header.to_bytes()[..]);
        let header = ImageSectionHeader {
            name: *b".text\0\0\0",
            physical_address_or_virtual_size: 0x0000_01B4,
            virtual_address: 0x0000_2000,
            size_raw_data: 0x0000_0200,
            pointer_raw_data: 0x0000_0200,
            // IMAGE_SCN_CNT_CODE
            // IMAGE_SCN_MEM_WRITE
            // IMAGE_SCN_MEM_READ
            characteristics: 0b1100000_00000000_00000000_00100000,
            ..Default::default()
        };
        result.extend(&header.to_bytes()[..]);
        let header = ImageSectionHeader {
            name: *b".reloc\0\0",
            physical_address_or_virtual_size: 0x0000_000C,
            virtual_address: 0x0000_4000,
            size_raw_data: 0x0000_0200,
            pointer_raw_data: 0x0000_0400,
            // IMAGE_SCN_CNT_INITIALIZED_DATA
            // IMAGE_SCN_MEM_READ
            // IMAGE_SCN_MEM_DISCARDABLE
            characteristics: 0b01000010_00000000_00000000_01000000,
            ..Default::default()
        };
        result.extend(&header.to_bytes()[..]);
        // 40 import table
        result.extend(&[0; 56][..]);
        let cli_header = CLIHeader {
            cb: std::mem::size_of::<CLIHeader>() as u32,
            ..Default::default()
        };
        result.extend(&cli_header.to_bytes()[..]);
        result
    }
}
// pub fn write(definition: Winmd) -> io::Result<()> {
//     todo!()
// }

#[derive(Default)]
#[repr(C)]
struct COFFHeader {
    machine: u16,
    num_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_symbols: u32,
    size_opt_header: u16,
    characteristics: u16,
}

const IMAGE_FILE_32BIT_MACHINE: u16 = 0x0100;
const IMAGE_FILE_DLL: u16 = 0x2000;
const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
impl COFFHeader {
    fn new(num_sections: u16, time_date_stamp: u32) -> Self {
        Self {
            machine: 0x014C,
            num_sections,
            time_date_stamp,
            size_opt_header: std::mem::size_of::<PEOptHeader>() as u16,
            // The following must be 1:
            // IMAGE_FILE_EXECUTABLE_IMAGE
            // IMAGE_FILE_DLL
            //
            // IMAGE_FILE_32BIT_MACHINE should only be set if
            // COMIMAGE_FLAGS_32BITREQUIRED is set in set in the
            // CLI Header.
            // TODO: make this configurable
            characteristics: IMAGE_FILE_32BIT_MACHINE
                | IMAGE_FILE_DLL
                | IMAGE_FILE_EXECUTABLE_IMAGE,
            ..Default::default()
        }
    }

    fn to_bytes(&self) -> [u8; std::mem::size_of::<COFFHeader>()] {
        // This is safe because `Self` is `#[repr(C)]` and only contains
        // primitive types
        unsafe { std::mem::transmute_copy(self) }
    }
}

// const fn u16_as_le(n: u16) -> [u8; 2] {
//     [(n & 0xFF) as u8, ((n & 0xFF00) >> 8) as u8]
// }
const fn u32_as_le(n: u32) -> [u8; 4] {
    [
        (n & 0xFF) as u8,
        ((n & 0xFF00) >> 8) as u8,
        ((n & 0xFF_0000) >> 16) as u8,
        ((n & 0xFF00_0000) >> 24) as u8,
    ]
}

const DOS_HEADER: [u8; 28] = [
    b'M', b'Z', 0x90, 0x00, 0x03, 0x0, 0x0, 0x0, 0x4, 0x0, 0x0, 0x0, 0xFF, 0xFF, 0x0, 0x0, 0xB8,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x40, 0x0, 0x0, 0x0,
];
const DOS_HEADER_SUFFIX: [u8; 32] = [0x0; 32];
const E_LFANEW: [u8; 4] = u32_as_le(0x80);

const STUB_PROGRAM_PREFIX: [u8; 14] = [
    0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21,
];
const DOS_MESSAGE: &[u8] = b"This program cannot be run in DOS mode";
const DOS_MESSAGE_SUFFIX: [u8; 5] = [0x2E, 0x0D, 0x0D, 0x0A, b'$'];
const STUB_PROGRAM_SUFFIX: [u8; 7] = [0x0; 7];
const PE_HEADER: [u8; 4] = [b'P', b'E', 0, 0];

#[derive(Default)]
#[repr(C)]
struct PEOptHeader {
    signature: u16,
    linker_version: u16,
    size_code: u32,
    size_initialized_data: u32,
    size_uninitialized_data: u32,
    //The RVA of the code entry point
    entry_point: u32,
    base_code: u32,
    base_data: u32,
    // The next 21 fields are an extension to the COFF optional header format
    image_base: u32,
    section_alignment: u32,
    file_alignment: u32,
    os_version: u32,
    image_version: u32,
    subsystem_version: u32,
    win32_version_value: u32,
    size_image: u32,
    size_headers: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_stack_reserve: u32,
    size_stack_commit: u32,
    size_heap_reserve: u32,
    size_heap_commit: u32,
    loader_flags: u32,
    number_rva_sizes: u32,
    data_directory: [DataDirectory; 16],
}

impl PEOptHeader {
    fn to_bytes(&self) -> [u8; std::mem::size_of::<Self>()] {
        // This is safe because `Self` is `#[repr(C)]` and only contains
        // primitive types
        unsafe { std::mem::transmute_copy(self) }
    }
}

#[derive(Default)]
#[repr(C)]
struct DataDirectory {
    virtual_address: u32,
    size: u32,
}

#[derive(Default)]
#[repr(C)]
struct ImageSectionHeader {
    name: [u8; 8],
    physical_address_or_virtual_size: u32,
    virtual_address: u32,
    size_raw_data: u32,
    pointer_raw_data: u32,
    pointer_relocations: u32,
    pointer_line_numbers: u32,
    num_relocations: u16,
    num_line_numbers: u16,
    characteristics: u32,
}
impl ImageSectionHeader {
    fn to_bytes(&self) -> [u8; std::mem::size_of::<Self>()] {
        // This is safe because `Self` is `#[repr(C)]` and only contains
        // primitive types
        unsafe { std::mem::transmute_copy(self) }
    }
}

#[repr(C)]
#[derive(Default)]
struct CLIHeader {
    cb: u32,
    runtime_version: u32,
    metadata: u64,
    flags: u32,
    entry_point_taken: u32,
    resources: u64,
    strong_name_signature: u64,
    code_manager_table: u64,
    vtable_fixups: u64,
    export_address_table_jumps: u64,
    managed_native_header: u64,
}
impl CLIHeader {
    fn to_bytes(&self) -> [u8; std::mem::size_of::<Self>()] {
        // This is safe because `Self` is `#[repr(C)]` and only contains
        // primitive types
        unsafe { std::mem::transmute_copy(self) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn creates_bytes() {
        let winmd = Winmd {};
        let expected = std::fs::read("sample.winmd").unwrap();
        let bytes = winmd.to_bytes();
        let start = DOS_HEADER.len()
            + DOS_HEADER_SUFFIX.len()
            + E_LFANEW.len()
            + STUB_PROGRAM_PREFIX.len()
            + DOS_MESSAGE.len()
            + DOS_MESSAGE_SUFFIX.len()
            + STUB_PROGRAM_SUFFIX.len()
            + PE_HEADER.len()
            + std::mem::size_of::<COFFHeader>()
            + std::mem::size_of::<PEOptHeader>()
            + (std::mem::size_of::<ImageSectionHeader>() * 2)
            + 56;

        let end = start + std::mem::size_of::<CLIHeader>();

        println!("0x{:x} to 0x{:x}", start, end);
        println!("Bytes left: {}", expected[end..].len());
        assert_eq!(&bytes[..start], &expected[..start]);
    }

    #[test]
    fn little_endian() {
        assert_eq!(u32_as_le(0xAB10DC20), [0x20, 0xDC, 0x10, 0xAB]);
    }
}
