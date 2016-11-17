#![feature(custom_derive, plugin, proc_macro)]
#![plugin(tojson_macros)]

#[macro_use] extern crate guard;
extern crate rustc_serialize;
#[macro_use] extern crate tojson_macros;
extern crate toml;
extern crate crypto;

use rustc_serialize::Decodable;

use std::io::{Read, Write};
use std::fs::File;
use std::path::Path;

use crypto::sha1::Sha1;
use crypto::digest::Digest;

mod db;
mod handler;

use db::{FlupDb, FlupDbConfig};
use handler::{FlupHandler, FlupHandlerConfig};

static ID_CHARS: &'static [char] = &['2','3','4','5','6','7','8','9','A','B','C','D','E','F','G','H','J','K','L','M','N','P','Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f','g','h','i','j','k','m','n','p','q','r','s','t','u','v','w','x','y','z'];

#[derive(Debug, Clone, RustcDecodable)]
pub struct FlupConfig {
    pub salt: String,

    pub no_access_extensions: Vec<String>,
    pub no_upload_extensions: Vec<String>,

    pub max_size: u64,
}

#[derive(Debug, Clone, ToJson, RustcEncodable, RustcDecodable)]
pub struct FileInfo {
    pub name: String,
    pub desc: String,

    pub file_id: String,

    pub hash: String,
    pub size: u64,

    pub uploader: String,
}

#[derive(Debug, Clone, ToJson, RustcEncodable, RustcDecodable)]
pub struct DeletedFile {
    pub file: FileInfo,
    pub reason: String,
}

#[derive(Clone)]
pub struct Flup {
    config: FlupConfig,
    db: FlupDb,
}

#[derive(Debug)]
pub enum StartError {
    Db(db::StartError),
}

#[derive(Debug)]
pub struct UploadRequestParams {
    pub files: Vec<(Result<File, std::io::Error>, Option<String>)>,

    pub is_private: bool,
    pub no_filename: bool,
    pub desc: Option<String>,
}

#[derive(Debug)]
pub struct UploadRequest {
    pub ip: String,
    pub params: Option<UploadRequestParams>,
}

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
    CreateFile,
    WriteFile,
    BlockedExtension,
    DescTooLong,
    AddFile,
}

#[derive(Debug)]
pub struct GetRequest {
    file_id: String,
    ip: String,
}

#[derive(Debug)]
pub enum GetError {
    BlockedExtension,
    NotFound,
}

#[derive(Debug)]
pub enum IdGetError {
    NotFound,
}

#[derive(Debug, Clone, RustcDecodable)]
struct Config {
    flup: FlupConfig,
    flup_handler: FlupHandlerConfig,
    flup_db: FlupDbConfig,
}

fn hash_ip(salt: &String, ip: &String) -> String {
    let mut hasher = Sha1::new();
    hasher.input(ip.as_bytes());
    hasher.input(salt.as_bytes());

    hasher.result_str()
}

fn hash_file_data(file_data: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.input(file_data);

    hasher.result_str()
}

fn handle_filename(filename: String, remove_filename: bool) -> String {
    let path = Path::new(filename.as_str());

    let short_base = match remove_filename {
        true => "file".to_string(),
        false => {
            let base_str = path.file_stem().unwrap().to_str().unwrap();
            base_str.chars().take(45).collect::<String>()
        },
    };

    match path.extension() {
        Some(ext) => {
            let ext_str = ext.to_str().unwrap();
            let short_ext: String = ext_str.chars().take(10).collect();

            format!("{}.{}", short_base, short_ext)
        },
        None => short_base,
    }
}

fn blocked_extension(blocked: &[String], filename: &String) -> bool {
    if let Some(extension) = Path::new(&filename.to_lowercase()).extension() {
        let extension_string = extension.to_str().unwrap().to_string();

        blocked.contains(&extension_string)
    } else {
        false
    }
}

impl Flup {
    pub fn new(config: FlupConfig, db_config: FlupDbConfig) -> Result<Flup, StartError> {
        let db = match FlupDb::new(db_config) {
            Err(error) => return Err(StartError::Db(error)),
            Ok(db) => db,
        };

        Ok(Flup {
            config: config,
            db: db,
        })
    }

    fn new_file_id(&self) -> String {
        let mut i = self.db.new_id_seed() as usize + 1;
        let mut id = String::new();

        while i > 0 {
            i -= 1;
            id.push(ID_CHARS[i % ID_CHARS.len()]);
            i = i / ID_CHARS.len();
        }

        id = id.chars().rev().collect();

        match self.db.get_file_by_id(&id) {
            Some(_) => self.new_file_id(),
            None => id,
        }
    }

    pub fn upload(&self, req: &UploadRequest) -> Result<Vec<FileInfo>, UploadError> {
        guard!(let Some(ref params) = req.params else {
            return Err(UploadError::NoPostParams);
        });

        let uploader = hash_ip(&self.config.salt, &req.ip);

        let desc = match params.desc {
            Some(ref desc) if desc.len() > 100 => {
                return Err(UploadError::DescTooLong);
            },
            Some(ref desc) => desc,
            _ => "",
        };

        let mut files = vec![];

        for &(ref attempted_file_open, ref filename) in &params.files {
            let mut file = match attempted_file_open {
                &Ok(ref file) => file,
                _ => return Err(UploadError::OpenUploadFile),
            };

            let file_size = match file.metadata() {
                Ok(file_metadata) => file_metadata.len(),
                _ => return Err(UploadError::GetMetadata),
            };

            if file_size == 0 {
                return Err(UploadError::FileEmpty);
            } else if file_size > self.config.max_size {
                return Err(UploadError::FileTooBig);
            }

            let mut file_data = vec![];
            if let Err(_) = file.read_to_end(&mut file_data) {
                return Err(UploadError::ReadData);
            }

            let hash = hash_file_data(&file_data);

            if let Some(file_id) = self.db.get_file_id_by_hash(&hash) {
                files.push(self.db.get_file_by_id(&file_id).expect("File with identical hash missing"));
                continue;
            }

            let file_id = match params.is_private {
                true => hash.chars().take(10).collect(),
                false => self.new_file_id(),
            };

            match File::create(format!("files/{}", file_id)) {
                Ok(mut file) => {
                    if file.write_all(&file_data).is_err() {
                        return Err(UploadError::WriteFile)
                    }
                },
                Err(_) => return Err(UploadError::CreateFile),
            }

            let filename = match filename.as_ref().map(|filename| filename.trim())  {
                Some(ref filename) if filename.len() > 0 => {
                    handle_filename(filename.to_string(), params.no_filename)
                },
                _ => "file".to_string(),
            };

            if blocked_extension(&self.config.no_upload_extensions, &filename) {
                return Err(UploadError::BlockedExtension);
            }

            let file_info = FileInfo {
                name: filename,
                desc: desc.to_string(),
                file_id: file_id.clone(),
                hash: hash,
                size: file_size,
                uploader: uploader.clone(),
            };

            self.db.add_file(&file_info.file_id, &file_info, !params.is_private);
            files.push(file_info);
        }

        Ok(files)
    }

    pub fn file_by_id(&self, file_id: &String) -> Result<FileInfo, IdGetError> {
        match self.db.get_file_by_id(&file_id) {
            Some(file_info) => Ok(file_info),
            None => return Err(IdGetError::NotFound),
        }
    }

    pub fn file(&self, file_id: &String, filename: &String) -> Result<FileInfo, GetError> {
        if blocked_extension(&self.config.no_access_extensions, &filename) {
            return Err(GetError::BlockedExtension);
        }

        match self.db.get_file_by_id(&file_id) {
            Some(file_info) => Ok(file_info),
            None => return Err(GetError::NotFound),
        }
    }

    pub fn uploads_count(&self) -> (isize, isize) {
        let uploads_count = self.db.get_uploads_count();
        let public_uploads_count = self.db.get_public_uploads_count();

        (uploads_count, public_uploads_count)
    }

    pub fn public_uploads(&self) -> Vec<FileInfo> {
        self.db.get_public_uploads().into_iter().take(50).map(|file_id| {
            self.db.get_file_by_id(&file_id)
                .expect(&format!("Error fetching file from public files list (ID: {})", file_id))
        }).collect()
    }

    pub fn deletion_log(&self) -> Vec<DeletedFile> {
        self.db.get_deleted_files()
    }
}

fn get_config() -> Config {
    let mut f = File::open("config.toml").expect("Config file missing");
    let mut data = String::new();
    f.read_to_string(&mut data).expect("Unable to read config file");

    let v = toml::Parser::new(&data).parse().expect("Error parsing config");
    let mut d = toml::Decoder::new(toml::Value::Table(v));
    Config::decode(&mut d).expect("Error creating Config from config")
}

fn main() {
    let config = get_config();

    let flup = match Flup::new(config.flup, config.flup_db) {
        Err(error) => panic!("Error starting: {:?}", error),
        Ok(flup) => flup,
    };

    FlupHandler::start(flup, config.flup_handler);
}
