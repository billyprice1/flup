#![feature(custom_derive, plugin)]
#![plugin(tojson_macros)]

#[macro_use] extern crate guard;
extern crate rustc_serialize;
extern crate toml;
extern crate crypto;

use rustc_serialize::Decodable;

use std::io::{self, Read};
use std::fs::File;
use std::path::Path;

use crypto::md5::Md5;
use crypto::sha1::Sha1;
use crypto::digest::Digest;

mod file;
mod db;
mod handler;

use file::FlupFs;
use db::FlupDb;
use handler::FlupHandler;

/// Gets a 4 character long `String` from file data/bytes.
/// # Examples
///
/// ```
/// assert_eq!(hash_file(&[119, 101, 119, 108, 97, 100]), "775e");
/// ```
pub fn hash_file(file: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.input(file);

    hasher.result_str()[..4].to_string()
}

/// Generates an MD5 hash of a `String`, used for hashing IPs
/// # Examples
///
/// ```
/// assert_eq!(hash_ip("127.0.0.1:55100"), "c3c38aa42f2c6581a7ff2e8065f345b5");
/// ```
pub fn hash_ip(salt: String, ip: String) -> String {
    let mut hasher = Md5::new();
    hasher.input(ip.as_bytes());
    hasher.input(salt.as_bytes());

    hasher.result_str()
}

/// Processes filenames, shortening both the name, and if exists, the extension.
/// # Examples
///
/// ```
/// assert_eq!(handle_filename("fuckmyshitup.png"), "fuckmyshitup.png");
/// assert_eq!(handle_filename("whatthefuckdidyoujustfuckingsayaboutmeyoulittlebitchillhaveyouknowigraduatedtopofmyclassinthenavysealsandivebeeninvolvedinnumeroussecretraidsonalquaedaandihaveover300confirmedkills.png"), "whatthefuckdidyoujustfuckingsayaboutmeyoulitt.png");
/// assert_eq!(handle_filename("gen2isacuck.imprettyfuckingsurethisisnotafileextension"), "gen2isacuck.imprettyfu");
/// ```
pub fn handle_filename(filename: String) -> String {
    let path = Path::new(filename.as_str());

    let base_str = path.file_stem().unwrap().to_str().unwrap();
    let short_base: String = base_str.chars().take(45).collect();

    match path.extension() {
        Some(ext) => {
            let ext_str = ext.to_str().unwrap();
            let short_ext: String = ext_str.chars().take(10).collect();

            format!("{}.{}", short_base, short_ext)
        },
        None => short_base,
    }
}

/// Handles an X-Forwarded-For string and selects the appropriate index
/// # Examples
///
/// ```
/// assert_eq!(handle_xforwarded("totally not injected, 8.8.8.8", 1), "8.8.8.8");
/// assert_eq!(handle_xforwarded("8.8.8.8", 1), "8.8.8.8");
/// assert_eq!(handle_xforwarded("totally not injected, 8.8.8.8, 127.0.0.1", 2), "8.8.8.8");
/// ```
pub fn handle_xforwarded(ips_string: String, i: usize) -> String {
    let mut ips: Vec<&str> = ips_string.split(", ").collect();
    ips.reverse();

    ips.get(i).unwrap().to_string()
}

/// Configuration for Flup.
#[derive(Debug, Clone, RustcDecodable)]
pub struct FlupConfig {
    /// The host to run the webserver on.
    pub host: String,
    /// The URL which the instance is running on.
    pub url: String,

    /// The salt used for hashing IPs.
    pub salt: String,

    /// Whether or not to use X-Forwarded-For at all
    pub xforwarded: bool,
    /// If using X-Forwarded-For, which header to trust.
    pub xforwarded_index: usize,
}

/// File struct containing all stored file information minus the data.
#[derive(Debug, Clone, ToJson, RustcEncodable, RustcDecodable)]
pub struct FileInfo {
    /// The original filename of the file.
    pub name: String,

    /// The file's description.
    pub desc: String,

    /// The file's ID.
    pub file_id: String,

    /// The file's SHA1 hash.
    pub hash: String,

    /// The size of the file.
    pub size: u64,

    /// The file's uploader.
    pub uploader: String,
}

/// Flup struct, containing the config, and internal db and fs structs.
#[derive(Clone)]
pub struct Flup {
    pub config: FlupConfig,
    db: FlupDb,
    fs: FlupFs,
}

/// Possible Flup startup errors.
#[derive(Debug)]
pub enum StartError {
    Redis(db::RedisError),
    Io(io::Error),
}

/// POST params used in `UploadRequest`.
pub struct UploadRequestParams {
    /// List of files submitted for upload
    pub files: Vec<(Option<File>, Option<String>)>,

    /// Show on public list or not
    pub public: bool,
    /// Optional description
    pub desc: Option<String>,
}

/// Upload request struct, contstructed by request handlers.
pub struct UploadRequest {
    /// X-Forwarded-For header.
    pub xforwarded: Option<String>,

    /// POST params.
    pub params: Option<UploadRequestParams>,

    /// Uploader IP.
    pub ip: String,
}

/// File ID request struct, contstructed by request handlers.
pub struct IdGetRequest {
    /// File ID
    pub file_id: String,
}

/// File request struct, contstructed by request handlers.
pub struct GetRequest {
    /// File ID
    pub file_id: String,
}

/// Possible upload errors
#[derive(Debug)]
pub enum UploadError {
    SetIp,
    NoPostParams,
    InvalidFileData,
    FileEmpty,
    FileTooBig,
    OpenUploadFile,
    GetMetadata,
    ReadData,
    WriteFile,
    DescTooLong,
    AddFile,
}

/// Possible get errors
#[derive(Debug)]
pub enum GetError {
    NotFound,
    FileNotFound
}

/// Possible ID get errors
#[derive(Debug)]
pub enum IdGetError {
    NotFound,
}

impl Flup {
    /// Constructs a new `Flup` from a `FlupConfig`.
    pub fn new(config: FlupConfig) -> Result<Flup, StartError> {
        let db = try!(FlupDb::new());
        let fs = FlupFs::new();

        Ok(Flup {
            config: config,
            db: db,
            fs: fs,
        })
    }

    /// Uploads a file with data from an `UploadRequest`.
    pub fn upload(&self, req: UploadRequest) -> Result<Vec<FileInfo>, UploadError> {
        guard!(let Some(params) = req.params else {
            return Err(UploadError::NoPostParams);
        });

        let ip = match req.xforwarded {
            Some(ref ips_string) if self.config.xforwarded == true => {
                handle_xforwarded(ips_string.clone(), self.config.xforwarded_index)
            },
            _ => req.ip,
        };

        let uploader = hash_ip(self.config.salt.clone(), ip.clone());
        if let Err(_) = self.db.set_ip(uploader.clone(), ip) {
            return Err(UploadError::SetIp);
        }

        let desc = match params.desc {
            Some(ref desc) if desc.len() > 100 => {
                return Err(UploadError::DescTooLong);
            },
            Some(desc) => desc,
            _ => "(none)".to_string(),
        };

        let mut files = vec![];

        for (file, filename) in params.files {
            guard!(let Some(mut file) = file else {
                return Err(UploadError::OpenUploadFile);
            });

            let file_size = match file.metadata() {
                Ok(file_metadata) => file_metadata.len(),
                _ => return Err(UploadError::GetMetadata),
            };

            if file_size == 0 {
                return Err(UploadError::FileEmpty);
            } else if file_size > 8388608 {
                return Err(UploadError::FileTooBig);
            }

            let mut file_data = vec![];
            if let Err(_) = file.read_to_end(&mut file_data) {
                return Err(UploadError::ReadData);
            }

            let file_id = hash_file(&file_data);

            let file_info = if let Ok(file_info) = self.db.get_file(file_id.to_string()) {
                file_info
            } else {
                if let Err(_) = self.fs.write_file(file_id.clone(), file_data.clone()) {
                    return Err(UploadError::WriteFile);
                }

                let filename = match filename  {
                    Some(ref filename) if filename.len() != 0 => handle_filename(filename.clone()),
                    _ => "file".to_string(),
                };

                let hash = {
                    let mut hasher = Sha1::new();
                    hasher.input(&file_data[..]);

                    hasher.result_str()
                };

                let file_info = FileInfo {
                    name: filename,
                    desc: desc.clone(),
                    file_id: file_id.clone(),
                    hash: hash,
                    size: file_size,
                    uploader: uploader.clone(),
                };

                if let Err(_) = self.db.add_file(file_id, file_info.clone(), params.public) {
                    return Err(UploadError::AddFile);
                }

                file_info
            };

            files.push(file_info);
        }

        Ok(files)
    }

    /// Gets a `FileInfo` by a file ID
    pub fn file_by_id(&self, req: IdGetRequest) -> Result<(String, FileInfo), IdGetError> {
        guard!(let Ok(file_info) = self.db.get_file(req.file_id.clone()) else {
            return Err(IdGetError::NotFound);
        });

        Ok((req.file_id, file_info))
    }

    /// Gets a `FileInfo` and file data by a file ID
    pub fn file(&self, req: GetRequest) -> Result<(FileInfo, Vec<u8>), GetError> {
        guard!(let Ok(file_info) = self.db.get_file(req.file_id.clone()) else {
            return Err(GetError::NotFound);
        });

        guard!(let Ok(file_data) = self.fs.get_file(req.file_id.clone()) else {
            return Err(GetError::FileNotFound);
        });

        Ok((file_info, file_data))
    }
}

/// Opens and parses `config.toml`.
fn get_config() -> FlupConfig {
    let mut f = File::open("config.toml").unwrap();
    let mut data = String::new();
    f.read_to_string(&mut data).unwrap();

    let v = toml::Parser::new(&data).parse().unwrap();
    let mut d = toml::Decoder::new(toml::Value::Table(v));
    FlupConfig::decode(&mut d).unwrap()
}

fn main() {
    let config = get_config();
    let flup = Flup::new(config.clone()).unwrap();

    FlupHandler::start(flup);
}
