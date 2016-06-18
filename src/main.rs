#![feature(custom_derive, plugin)]
#![plugin(tojson_macros)]

#[macro_use] extern crate guard;
extern crate rustc_serialize;
extern crate iron;
extern crate router;
extern crate mount;
extern crate params;
extern crate handlebars_iron as hbs;
extern crate staticfile;
extern crate toml;
extern crate crypto;

use rustc_serialize::Decodable;

use iron::prelude::*;
use mount::Mount;
use router::Router;

use hbs::{HandlebarsEngine, DirectorySource};
use staticfile::Static;

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

fn hash_file(file: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.input(file);

    hasher.result_str()[..4].to_string()
}

fn hash_ip(salt: String, ip: String) -> String {
    let mut hasher = Md5::new();
    hasher.input(ip.as_bytes());
    hasher.input(salt.as_bytes());

    hasher.result_str()
}

#[derive(Debug, Clone, RustcDecodable)]
pub struct FlupConfig {
    host: String,
    url: String,

    salt: String,

    xforwarded: bool,
    xforwarded_index: usize,
}

#[derive(Debug, Clone, ToJson, RustcEncodable, RustcDecodable)]
pub struct FileInfo {
    name: String,
    desc: String,
    file_id: String,
    hash: String,
    size: u64,
    uploader: String,
}

#[derive(Clone)]
pub struct Flup {
    pub config: FlupConfig,
    db: FlupDb,
    fs: FlupFs,
}

#[derive(Debug)]
pub enum StartError {
    Redis(db::RedisError),
    Io(io::Error),
}

pub struct UploadRequestParams {
    files: Vec<params::File>,

    public: bool,
    desc: Option<String>,
}

pub struct UploadRequest {
    xforwarded: Option<String>,

    params: Option<UploadRequestParams>,

    ip: String,
}

pub struct IdGetRequest {
    file_id: String,
}

pub struct GetRequest {
    file_id: String,
}

#[derive(Debug)]
pub enum UploadError {
    SetIp,
    NoPostParams,
    InvalidFileData,
    FileEmpty,
    FileTooBig,
    OpenUploadFile,
    ReadData,
    WriteFile,
    DescTooLong,
    AddFile,
}

#[derive(Debug)]
pub enum GetError {
    NotFound,
    FileNotFound
}

#[derive(Debug)]
pub enum IdGetError {
    NotFound,
}

impl Flup {
    pub fn new(config: FlupConfig) -> Result<Flup, StartError> {
        let db = try!(FlupDb::new());
        let fs = FlupFs::new();

        Ok(Flup {
            config: config,
            db: db,
            fs: fs,
        })
    }

    pub fn upload(&self, req: UploadRequest) -> Result<Vec<FileInfo>, UploadError> {
        guard!(let Some(params) = req.params else {
            return Err(UploadError::NoPostParams);
        });

        let ip = match req.xforwarded {
            Some(ref ips_string) if self.config.xforwarded == true => {
                let mut ips: Vec<&str> = ips_string.split(", ").collect();
                ips.reverse();

                ips.get(self.config.xforwarded_index).unwrap().to_string()
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

        for file in params.files {
            if file.size() == 0 {
                return Err(UploadError::FileEmpty);
            } else if file.size() > 8388608 {
                return Err(UploadError::FileTooBig);
            }

            let file_data = if let Ok(mut handle) = file.open() {
                let mut buf = vec![];

                if let Err(_) = handle.read_to_end(&mut buf) {
                    return Err(UploadError::ReadData);
                }

                buf
            } else {
                return Err(UploadError::OpenUploadFile);
            };

            let file_id = hash_file(&file_data);

            let file_info = if let Ok(file_info) = self.db.get_file(file_id.to_string()) {
                file_info
            } else {
                if let Err(_) = self.fs.write_file(file_id.clone(), file_data.clone()) {
                    return Err(UploadError::WriteFile);
                }

                let filename = match file.filename()  {
                    Some(filename) if filename.len() != 0 => {
                        let path = Path::new(filename);

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
                    },
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
                    size: file.size(),
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

    pub fn file_by_id(&self, req: IdGetRequest) -> Result<(String, FileInfo), IdGetError> {
        guard!(let Ok(file_info) = self.db.get_file(req.file_id.clone()) else {
            return Err(IdGetError::NotFound);
        });

        Ok((req.file_id, file_info))
    }

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

fn get_config() -> FlupConfig {
    let mut f = File::open("config.toml").unwrap();
    let mut data = String::new();
    f.read_to_string(&mut data).unwrap();

    let v = toml::Parser::new(&data).parse().unwrap();
    let mut d = toml::Decoder::new(toml::Value::Table(v));
    FlupConfig::decode(&mut d).unwrap()
}

fn new_flup_router(flup_handler: FlupHandler) -> Router {
    let mut router = Router::new();

    let flup_handler_clone = flup_handler.clone();
    router.post("/", move |req: &mut Request| {
        flup_handler_clone.handle_upload(req)
    });

    let flup_handler_clone = flup_handler.clone();
    router.get("/:id", move |req: &mut Request| {
        flup_handler_clone.handle_file_by_id(req)
    });

    let flup_handler_clone = flup_handler.clone();
    router.get("/:id/*", move |req: &mut Request| {
        flup_handler_clone.handle_file(req)
    });

    let flup_handler_clone = flup_handler.clone();
    router.get("/uploads", move |req: &mut Request| {
        flup_handler_clone.handle_uploads(req)
    });

    let flup_handler_clone = flup_handler.clone();
    router.get("/about", move |req: &mut Request| {
        flup_handler_clone.handle_about(req)
    });

    let flup_handler_clone = flup_handler.clone();
    router.get("/", move |req: &mut Request| {
        flup_handler_clone.handle_home(req)
    });

    router
}

fn main() {
    let config = get_config();

    let mut hbse = HandlebarsEngine::new();
    hbse.add(Box::new(DirectorySource::new("./views/", ".hbs")));
    hbse.reload().unwrap();

    let flup = Flup::new(config.clone()).unwrap();
    let flup_handler = FlupHandler::new(flup);

    let mut mount = Mount::new();
    mount.mount("/", new_flup_router(flup_handler));
    mount.mount("/static/", Static::new(Path::new("static")));

    let mut chain = Chain::new(mount);
    chain.link_after(hbse);

    Iron::new(chain).http(config.host.as_str()).unwrap();
}
