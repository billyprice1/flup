use super::{
    Flup,
    FileInfo,
    DeletedFile,
    UploadRequest,
    UploadRequestParams,
    UploadError,
    GetError,
};

extern crate mime_guess;
extern crate handlebars_iron as hbs;

extern crate iron;
extern crate router;
extern crate mount;
extern crate params;
extern crate staticfile;

use rustc_serialize::json;

use self::params::{Params, Value};

use self::iron::prelude::*;
use self::iron::status::Status;
use self::iron::modifiers::Header;
use self::iron::headers;

use self::staticfile::Static;
use self::router::Router;
use self::mount::Mount;

use self::hbs::{Template, HandlebarsEngine, DirectorySource};

use std::path::{Path, PathBuf};

enum UploadErrorType {
    ServerError,
    UserError,
    Denied,
}

enum GetErrorType {
    Denied,
    NotFound,
}

#[derive(RustcEncodable)]
struct JsonFile {
    name: String,
    url: String,
    hash: String,
    size: u64,
}

#[derive(RustcEncodable)]
struct SuccessJsonResponse {
    success: bool, // Always true
    files: Vec<JsonFile>,
}

#[derive(RustcEncodable)]
struct ErrorJsonResponse<'a> {
    success: bool, // Always false
    errorcode: usize,
    description: &'a str,
}

#[derive(ToJson)]
struct HomePageData {
    uploads_count: isize,
    public_uploads_count: isize,
}

#[derive(ToJson)]
struct UploadedPageData {
    uploaded: Vec<String>,
}

#[derive(ToJson)]
struct UploadsPageData {
    uploads: Vec<FileInfo>,
}

#[derive(ToJson)]
struct DeletedFilesData {
    deleted_files: Vec<DeletedFile>,
}

#[derive(ToJson)]
struct ErrorPageData {
    error: String,
}

#[derive(Debug, Clone, RustcDecodable)]
pub struct FlupHandlerConfig {
    url: String,
    host: String,

    xforwarded: bool,
    xforwarded_index: usize,
}

#[derive(Clone)]
pub struct FlupHandler {
    flup: Flup,
    config: FlupHandlerConfig,
}

fn error_info_from_upload_error(error: &UploadError) -> (UploadErrorType, &str) {
    match error {
        &UploadError::SetIp => (UploadErrorType::ServerError, "Error adding IP to temp DB"),
        &UploadError::NoPostParams => (UploadErrorType::UserError, "No POST params found"),
        &UploadError::InvalidFileData => (UploadErrorType::UserError, "Invalid file data found"),
        &UploadError::FileEmpty => (UploadErrorType::UserError, "Specified file is empty"),
        &UploadError::FileTooBig => (UploadErrorType::UserError, "File exceeds our limit"),
        &UploadError::OpenUploadFile => (UploadErrorType::ServerError, "Error opening uploaded file"),
        &UploadError::GetMetadata => (UploadErrorType::ServerError, "Unable to get file metadata"),
        &UploadError::ReadData => (UploadErrorType::ServerError, "Error reading file data"),
        &UploadError::CreateFile => (UploadErrorType::ServerError, "Error creating file"),
        &UploadError::WriteFile => (UploadErrorType::ServerError, "Error writing to file"),
        &UploadError::BlockedExtension => (UploadErrorType::Denied, "Uploading files with this extension is not allowed."),
        &UploadError::DescTooLong => (UploadErrorType::UserError, "Description too long"),
        &UploadError::AddFile => (UploadErrorType::ServerError, "Error adding file to DB"),
    }
}

fn error_info_from_get_error(error: &GetError) -> (GetErrorType, &str) {
    match error {
        &GetError::NotFound => (GetErrorType::NotFound, "File not found"),
        &GetError::BlockedExtension => (GetErrorType::Denied, "Fetching this extension is not allowed, try changing the filename in the url :^)"),
    }
}

fn handle_xforwarded(ips_string: &str, i: usize) -> Option<String> {
    let mut ips: Vec<&str> = ips_string.split(", ").collect();
    ips.reverse();

    ips.get(i).map(|ip| ip.to_string())
}

impl FlupHandler {
    pub fn start(flup: Flup, config: FlupHandlerConfig) {
        let mut router = Router::new();

        let flup_handler = FlupHandler {
            config: config.clone(),
            flup: flup,
        };

        let flup_handler_clone = flup_handler.clone();
        router.post("/", move |req: &mut Request| {
            flup_handler_clone.handle_upload(req)
        }, "upload");

        let flup_handler_clone = flup_handler.clone();
        router.post("/upload.php", move |req: &mut Request| { // legacy
            flup_handler_clone.handle_upload(req)
        }, "legacy_upload");

        let flup_handler_clone = flup_handler.clone();
        router.get("/:id", move |req: &mut Request| {
            flup_handler_clone.handle_file_by_id(req)
        }, "id_request");

        let flup_handler_clone = flup_handler.clone();
        router.get("/:id/:name", move |req: &mut Request| {
            flup_handler_clone.handle_file(req)
        }, "file_request");

        let flup_handler_clone = flup_handler.clone();
        router.get("/uploads", move |req: &mut Request| {
            flup_handler_clone.handle_public_uploads_get(req)
        }, "public_uploads_page_request");

        let flup_handler_clone = flup_handler.clone();
        router.get("/about", move |req: &mut Request| {
            flup_handler_clone.handle_about(req)
        }, "about_page_request");

        let flup_handler_clone = flup_handler.clone();
        router.get("/deletion_log", move |req: &mut Request| {
            flup_handler_clone.handle_deletion_log(req)
        }, "deletion_log_page_request");

        let flup_handler_clone = flup_handler.clone();
        router.get("/", move |req: &mut Request| {
            flup_handler_clone.handle_home(req)
        }, "home_page_request");

        let mut hbse = HandlebarsEngine::new();
        hbse.add(Box::new(DirectorySource::new("./views/", ".hbs")));
        hbse.reload().expect("Error reloading handlebars engine");

        let mut mount = Mount::new();
        mount.mount("/", router);
        mount.mount("/static/", Static::new(Path::new("static")));

        let mut chain = Chain::new(mount);
        chain.link_after(hbse);

        Iron::new(chain).http(config.host.as_str()).expect("Unable to start webserver");
    }

    fn error_page(&self, status: Status, text: &str) -> IronResult<Response> {
        let data = ErrorPageData {
            error: text.to_string(),
        };

        let mut resp = Response::new();
        resp.set_mut(Template::new("error", data)).set_mut(status);
        Ok(resp)
    }

    fn json_error(&self, error_code: usize, text: &str) -> IronResult<Response> {
        let response = ErrorJsonResponse {
            success: false,
            errorcode: error_code,
            description: text,
        };
        
        let json = json::encode(&response).expect("Error creating JSON from error struct");

        Ok(Response::with((Status::Ok, json)))
    }

    fn process_upload_request(&self, req: &mut Request) -> UploadRequest {
        let xforwarded = match req.headers.get_raw("X-Forwarded-For") {
            Some(data) if data.len() == 1 => {
                Some(String::from_utf8(data[0].clone()).unwrap())
            },
            _ => None,
        };

        let params = match req.get_ref::<Params>() {
            Ok(params) => {
               let files = match params.get("files") {
                    Some(&Value::Array(ref file_values)) => {
                        file_values.into_iter().filter_map(|value| {
                            match value {
                                &Value::File(ref file) => Some((file.open(), file.filename.clone())),
                                _ => None,
                            }
                        }).collect()
                    },
                    _ => vec![],
                };

                let desc = match params.get("desc") {
                    Some(&Value::String(ref desc)) => Some(desc.clone()),
                    _ => None,
                };

                let no_filename = match params.get("nofilename") {
                    Some(&Value::String(ref toggle)) if toggle == "on" => true,
                    _ => false,
                };

                let is_private = match params.get("private") {
                    Some(&Value::String(ref toggle)) if toggle == "on" => true,
                    _ => false,
                };

                Some(UploadRequestParams {
                    files: files,

                    is_private: is_private,
                    no_filename: no_filename,
                    desc: desc,
                })
            },
            _ => None,
        };

        let ip = match xforwarded {
            Some(ref ips_string) if self.config.xforwarded == true => {
                handle_xforwarded(ips_string, self.config.xforwarded_index)
                    .expect("Invalid xforwarded index, change your config?")
            },
            _ => req.remote_addr.to_string(),
        };

        UploadRequest {
            ip: ip,
            params: params,
        }
    }

    pub fn handle_upload_html(&self, req: &mut Request) -> IronResult<Response> {
        let flup_req = self.process_upload_request(req);

        match self.flup.upload(&flup_req) {
            Ok(files) => {
                let uploaded = files.into_iter().map(|file_info| {
                    format!("{}/{}", self.config.url, file_info.file_id)
                }).collect();

                let data = UploadedPageData {
                    uploaded: uploaded,
                };

                let mut resp = Response::new();
                resp.set_mut(Template::new("uploaded", data)).set_mut(Status::Ok);
                Ok(resp)
            },
            Err(error) => {
                let (error_type, error_text) = error_info_from_upload_error(&error);

                let status = match error_type {
                    UploadErrorType::ServerError => Status::InternalServerError,
                    UploadErrorType::UserError => Status::BadRequest,
                    UploadErrorType::Denied => Status::Forbidden,
                };

                self.error_page(status, error_text)
            },
        }
    }

    pub fn handle_upload_text(&self, trailing: bool, req: &mut Request) -> IronResult<Response> {
        let flup_req = self.process_upload_request(req);

        match self.flup.upload(&flup_req) {
            Ok(files) => {
                let urls = files.into_iter().map(|file_info| {
                    format!("{}/{}", self.config.url, file_info.file_id)
                }).collect::<Vec<String>>();

                let urls_string = match trailing {
                    true => format!("{}\n", urls.join("\n")),
                    false => urls.join("\n"),
                };

                Ok(Response::with((Status::Ok, urls_string)))
            },
            Err(error) => {
                let (error_type, error_text) = error_info_from_upload_error(&error);

                let status = match error_type {
                    UploadErrorType::ServerError => Status::InternalServerError,
                    UploadErrorType::UserError => Status::BadRequest,
                    UploadErrorType::Denied => Status::Forbidden,
                };

                Ok(Response::with((status, error_text)))
            },
        }
    }

    pub fn handle_upload_json(&self, req: &mut Request) -> IronResult<Response> {
        let flup_req = self.process_upload_request(req);

        match self.flup.upload(&flup_req) {
            Ok(files) => {
                let mut json_files = vec![];

                for file_info in files {
                    json_files.push(JsonFile {
                        name: file_info.name,
                        url: format!("{}/{}", self.config.url, file_info.file_id),
                        hash: file_info.hash,
                        size: file_info.size,
                    })
                }

                let response = SuccessJsonResponse {
                    success: true,
                    files: json_files,
                };

                let json = json::encode(&response).unwrap();

                Ok(Response::with((Status::Ok, json)))
            },
            Err(error) => {
                let (error_type, error_text) = error_info_from_upload_error(&error);

                let code = match error_type {
                    UploadErrorType::ServerError => 500,
                    UploadErrorType::UserError => 400,
                    UploadErrorType::Denied => 403,
                };

                self.json_error(code, error_text)
            },
        }
    }

    pub fn handle_upload(&self, req: &mut Request) -> IronResult<Response> {
        let output_type = match req.get_ref::<Params>() {
            Ok(params) => {
                match params.get("output") {
                    Some(&Value::String(ref output_type)) => Some(output_type.clone()),
                    _ => None,
                }
            }
            _ => None,
        };

        match output_type.as_ref().map(String::as_ref) {
            Some("text") => self.handle_upload_text(true, req),
            Some("gyazo") => self.handle_upload_text(false, req),
            Some("html") => self.handle_upload_html(req),
            _ => self.handle_upload_json(req),
        }
    }

    pub fn handle_file_by_id(&self, req: &mut Request) -> IronResult<Response> {
        let router = req.extensions.get::<Router>().unwrap();
        let file_id = router.find("id").unwrap().to_string();

        match self.flup.file(&file_id) {
            Ok(file_info) => {
                let url = format!("/{}/{}", file_id, file_info.name);
                let redirect = Header(headers::Location(url));

                Ok(Response::with((Status::SeeOther, redirect)))
            },
            Err(error) => {
                let (error_type, error_text) = error_info_from_get_error(&error);

                let status = match error_type {
                    GetErrorType::NotFound => Status::NotFound,
                    GetErrorType::Denied => Status::Forbidden,
                };

                self.error_page(status, error_text)
            },
        }
    }

    pub fn handle_file(&self, req: &mut Request) -> IronResult<Response> {
        let router = req.extensions.get::<Router>().unwrap();
        let file_id = router.find("id").unwrap().to_string();

        match self.flup.file(&file_id) {
            Ok(file_info) => {
                let file_path = PathBuf::from(format!("files/{}", &file_id));

                let name_path = PathBuf::from(file_info.name);
                let mime = mime_guess::guess_mime_type(name_path);

                Ok(Response::with((Status::Ok, mime, file_path)))
            },
            Err(error) => {
                let (error_type, error_text) = error_info_from_get_error(&error);

                let status = match error_type {
                    GetErrorType::NotFound => Status::NotFound,
                    GetErrorType::Denied => Status::Forbidden,
                };

                self.error_page(status, error_text)
            },
        }
    }

    pub fn handle_home(&self, _: &mut Request) -> IronResult<Response> {
        let (uploads_count, public_uploads_count) = self.flup.uploads_count();

        let data = HomePageData {
            uploads_count: uploads_count,
            public_uploads_count: public_uploads_count,
        };

        let mut resp = Response::new();
        resp.set_mut(Template::new("index", data)).set_mut(Status::Ok);
        Ok(resp)
    }

    pub fn handle_public_uploads_get(&self, _: &mut Request) -> IronResult<Response> {
        let uploads = self.flup.public_uploads();

        let data = UploadsPageData {
            uploads: uploads,
        };

        let mut resp = Response::new();
        resp.set_mut(Template::new("uploads", data)).set_mut(Status::Ok);
        Ok(resp)
    }

    pub fn handle_about(&self, _: &mut Request) -> IronResult<Response> {
        let mut resp = Response::new();
        resp.set_mut(Template::new("about", ())).set_mut(Status::Ok);
        Ok(resp)
    }

    pub fn handle_deletion_log(&self, _: &mut Request) -> IronResult<Response> {
        let deleted_files = self.flup.deletion_log();

        let data = DeletedFilesData {
            deleted_files: deleted_files,
        };

        let mut resp = Response::new();
        resp.set_mut(Template::new("deletedfiles", data)).set_mut(Status::Ok);
        Ok(resp)
    }
}
