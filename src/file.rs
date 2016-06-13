use std::io;
use std::io::{Read, Write};
use std::fs::File;

#[derive(Clone)]
pub struct FlupFs;

impl FlupFs {
    pub fn new() -> FlupFs {
        FlupFs
    }

    pub fn get_file(&self, file_id: String) -> io::Result<Vec<u8>> {
        let mut f = try!(File::open(format!("files/{}", file_id)));

        let mut data = Vec::new();
        try!(f.read_to_end(&mut data));

        Ok(data)
    }

    pub fn write_file(&self, file_id: String, data: Vec<u8>) -> io::Result<()> {
        let mut file = try!(File::create(format!("files/{}", file_id)));

        try!(file.write_all(&data));

        Ok(())
    }
}
