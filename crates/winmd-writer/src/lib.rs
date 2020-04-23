use std::io;
use std::mem::size_of;
const DOS_HEADER: &[u8; 0x84] = include_bytes!("./dos_header");
pub struct Winmd {}

impl Winmd {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(
            DOS_HEADER.len() + size_of::<COFFHeader>() + size_of::<PEOptHeader>(),
        );
        result.extend(&DOS_HEADER[..]);

        // TODO: do not hard code num_sections or time_date_stamp
        let coff_header = COFFHeader::new(2, 0x5E9_DCF09);
        result.extend(&coff_header.to_bytes());

        let opt_header = PEOptHeader::new(
            0x0000_0200,
            0x0000_0200,
            0x0000_21AE,
            0x0000_2000,
            0x0000_4000,
            0x0040_0000,
            0x0000_6000,
            0x0000_0200,
        );

        result.extend(&opt_header.to_bytes()[..]);
        let header = ImageSectionHeader::new(
            *b".text\0\0\0",
            0x0000_01B4,
            0x0000_2000,
            0x0000_0200,
            0x0000_0200,
            // IMAGE_SCN_CNT_CODE
            // IMAGE_SCN_MEM_WRITE
            // IMAGE_SCN_MEM_READ
            0b1100000_00000000_00000000_00100000,
        );
        result.extend(&header.to_bytes()[..]);
        let header = ImageSectionHeader::new(
            *b".reloc\0\0",
            0x0000_000C,
            0x0000_4000,
            0x0000_0200,
            0x0000_0400,
            // IMAGE_SCN_CNT_INITIALIZED_DATA
            // IMAGE_SCN_MEM_READ
            // IMAGE_SCN_MEM_DISCARDABLE
            0b01000010_00000000_00000000_01000000,
        );
        result.extend(&header.to_bytes()[..]);
        // padding
        result.extend(&[0; 56][..]);
        let import_address_table = ImportAddressTable::new(0x0000_2190);
        result.extend(&import_address_table.to_bytes());
        let cli_header = CLIHeader {
            cb: std::mem::size_of::<CLIHeader>() as u32,
            runtime_version: 0x0005_0002,
            metadata: DataDirectory {
                // CLI Data located at file offset x254
                // This is the 0x2054 (the virtual_address below) - 0x2000 (the RVA of the .text section) +
                // 0x200 (the pointer to raw data of the .text section)
                virtual_address: 0x00002054,
                size: 0x00000100,
            },
            flags: 0b00000000_00000000_00000000_00000001,
            ..Default::default()
        };

        result.extend(&cli_header.to_bytes()[..]);
        result.extend(&[0; 56][..]);

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
    fn new(
        size_code: u32,
        size_initialized_data: u32,
        entry_point: u32,
        base_code: u32,
        base_data: u32,
        image_base: u32,
        size_image: u32,
        size_headers: u32,
    ) -> Self {
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

        PEOptHeader {
            // Always IMAGE_NT_OPTIONAL_HDR32_MAGIC
            signature: 0x010B,
            linker_version: 0x000B,
            size_code,
            size_initialized_data,
            // TODO allow uninitialized data
            entry_point,
            base_code,
            base_data,
            image_base,
            section_alignment: 0x0000_2000,
            file_alignment: 0x0000_0200,
            os_version: 0x0000_0004,
            subsystem_version: 0x0000_0004,
            size_image,
            size_headers,
            subsystem: 0x0003,
            dll_characteristics: 0x8540,
            size_stack_reserve: 0x0010_0000,
            size_stack_commit: 0x0000_1000,
            size_heap_reserve: 0x0010_0000,
            size_heap_commit: 0x0000_1000,
            number_rva_sizes: 0x0000_0010,

            data_directory,
            ..Default::default()
        }
    }
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
    virtual_size: u32,
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
    fn new(
        name: [u8; 8],
        virtual_size: u32,
        virtual_address: u32,
        size_raw_data: u32,
        pointer_raw_data: u32,
        characteristics: u32,
    ) -> Self {
        Self {
            name,
            virtual_size,
            virtual_address,
            size_raw_data,
            pointer_raw_data,
            characteristics,
            ..Default::default()
        }
    }
    fn to_bytes(&self) -> [u8; std::mem::size_of::<Self>()] {
        // This is safe because `Self` is `#[repr(C)]` and only contains
        // primitive types
        unsafe { std::mem::transmute_copy(self) }
    }
}

#[repr(C)]
#[derive(Default)]
struct ImportAddressTable {
    hint_name_table_rva: u32,
    zeroed: u32,
}

impl ImportAddressTable {
    fn new(hint_name_table_rva: u32) -> Self {
        Self {
            hint_name_table_rva,
            zeroed: 0,
        }
    }

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
    metadata: DataDirectory,
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
        let expected = std::fs::read("./examples/example.winmd").unwrap();
        let bytes = winmd.to_bytes();
        let start = DOS_HEADER.len()
            + std::mem::size_of::<COFFHeader>()
            + std::mem::size_of::<PEOptHeader>()
            + (std::mem::size_of::<ImageSectionHeader>() * 2)
            + 56
            + std::mem::size_of::<ImportAddressTable>()
            + size_of::<CLIHeader>();

        let end = start + 4;

        println!("0x{:x} to 0x{:x}", start, end);
        println!("Bytes left: {}", expected[end..].len());
        assert_eq!(&bytes[start..end], &expected[start..end]);
    }
}
