use super::*;

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
use self::iron::Url;
use self::iron::status::Status;
use self::iron::modifiers::Redirect;

use self::staticfile::Static;
use self::router::Router;
use self::mount::Mount;

use self::hbs::{Template, HandlebarsEngine, DirectorySource};

use std::path::Path;

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
struct ErrorPageData {
    error: String,
}

#[derive(Clone)]
pub struct FlupHandler {
    flup: Flup,
}

impl FlupHandler {
    pub fn start(flup: Flup) {
        let mut router = Router::new();

        let flup_handler = FlupHandler {
            flup: flup.clone(),
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
        router.get("/", move |req: &mut Request| {
            flup_handler_clone.handle_home(req)
        }, "home_page_request");

        let mut hbse = HandlebarsEngine::new();
        hbse.add(Box::new(DirectorySource::new("./views/", ".hbs")));
        hbse.reload().unwrap();

        let mut mount = Mount::new();
        mount.mount("/", router);
        mount.mount("/static/", Static::new(Path::new("static")));

        let mut chain = Chain::new(mount);

        chain.link_after(hbse);

        Iron::new(chain).http(flup.config.host.as_str()).unwrap();
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
        let json = json::encode(&ErrorJsonResponse {
            success: false,
            errorcode: error_code,
            description: text,
        }).unwrap();

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
                let mut files = vec![];

                match params.get("files") {
                    Some(&Value::Array(ref file_values)) => {
                        for value in file_values {
                            if let &Value::File(ref file) = value {
                                let filename = file.filename.clone();
                                files.push((file.open().ok(), filename))
                            }
                        }
                    },
                    _ => {  },
                }

                let secure_id = match params.get("secureid") {
                    Some(&Value::String(ref toggle)) if toggle == "on" => true,
                    _ => false,
                };

                let desc = match params.get("desc") {
                    Some(&Value::String(ref desc)) => Some(desc.clone()),
                    _ => None,
                };

                let no_filename = match params.get("nofilename") {
                    Some(&Value::String(ref toggle)) if toggle == "on" => true,
                    _ => false,
                };

                let is_public = match params.get("public") {
                    Some(&Value::String(ref toggle)) if toggle == "on" => true,
                    _ => false,
                };

                Some(UploadRequestParams {
                    files: files,

                    secure_id: secure_id,
                    is_public: is_public,
                    no_filename: no_filename,
                    desc: desc,
                })
            },
            _ => None,
        };

        UploadRequest {
            xforwarded: xforwarded,

            params: params,

            ip: req.remote_addr.to_string(),
        }
    }

    pub fn handle_upload_html(&self, req: &mut Request) -> IronResult<Response> {
        let flup_req = self.process_upload_request(req);

        match self.flup.upload(flup_req) {
            Ok(files) => {
                let uploaded = files.into_iter().map(|file_info| {
                    format!("{}/{}", self.flup.config.url, file_info.file_id)
                }).collect();

                let data = UploadedPageData {
                    uploaded: uploaded,
                };

                let mut resp = Response::new();
                resp.set_mut(Template::new("uploaded", data)).set_mut(Status::Ok);
                Ok(resp)
            },
            Err(error) => {
                match error {
                    UploadError::SetIp => {
                        self.error_page(Status::InternalServerError, "Error adding IP to temp DB")
                    },
                    UploadError::NoPostParams => {
                        self.error_page(Status::BadRequest, "No POST params found")
                    },
                    UploadError::InvalidFileData => {
                        self.error_page(Status::BadRequest, "Invalid file data found")
                    },
                    UploadError::FileEmpty => {
                        self.error_page(Status::BadRequest, "Specified file is empty")
                    },
                    UploadError::FileTooBig => {
                        self.error_page(Status::BadRequest, "File exceeds our limit")
                    },
                    UploadError::OpenUploadFile => {
                        self.error_page(Status::InternalServerError, "Error opening uploaded file")
                    },
                    UploadError::GetMetadata => {
                        self.error_page(Status::InternalServerError, "Unable to get file metadata")
                    },
                    UploadError::ReadData => {
                        self.error_page(Status::InternalServerError, "Error reading file data")
                    },
                    UploadError::WriteFile => {
                        self.error_page(Status::InternalServerError, "Error writing to file")
                    },
                    UploadError::BlockedExtension => {
                        self.error_page(Status::BadRequest, "Uploading files with this extension is not allowed.")
                    },
                    UploadError::DescTooLong => {
                        self.error_page(Status::BadRequest, "Description too long")
                    },
                    UploadError::AddFile => {
                        self.error_page(Status::InternalServerError, "Error adding file to DB")
                    },
                }
            },
        }
    }

    pub fn handle_upload_text(&self, trailing: bool, req: &mut Request) -> IronResult<Response> {
        let flup_req = self.process_upload_request(req);

        match self.flup.upload(flup_req) {
            Ok(files) => {
                let urls = files.into_iter().map(|file_info| {
                    format!("{}/{}", self.flup.config.url, file_info.file_id)
                }).collect::<Vec<String>>();

                let urls_string = match trailing {
                    true => format!("{}\n", urls.join("\n")),
                    false => urls.join("\n"),
                };

                Ok(Response::with((Status::Ok, urls_string)))
            },
            Err(error) => {
                match error {
                    UploadError::SetIp => {
                        Ok(Response::with((Status::InternalServerError, "Error adding IP to temp DB")))
                    },
                    UploadError::NoPostParams => {
                        Ok(Response::with((Status::BadRequest, "No POST params found")))
                    },
                    UploadError::InvalidFileData => {
                        Ok(Response::with((Status::BadRequest, "Invalid file data found")))
                    },
                    UploadError::FileEmpty => {
                        Ok(Response::with((Status::BadRequest, "Specified file is empty")))
                    },
                    UploadError::FileTooBig => {
                        Ok(Response::with((Status::BadRequest, "File exceeds our limit")))
                    },
                    UploadError::OpenUploadFile => {
                        Ok(Response::with((Status::InternalServerError, "Error opening uploaded file")))
                    },
                    UploadError::GetMetadata => {
                        Ok(Response::with((Status::InternalServerError, "Unable to get file metadata")))
                    },
                    UploadError::ReadData => {
                        Ok(Response::with((Status::InternalServerError, "Error reading file data")))
                    },
                    UploadError::WriteFile => {
                        Ok(Response::with((Status::InternalServerError, "Error writing to file")))
                    },
                    UploadError::BlockedExtension => {
                        Ok(Response::with((Status::BadRequest, "Uploading files with this extension is not allowed.")))
                    },
                    UploadError::DescTooLong => {
                        Ok(Response::with((Status::BadRequest, "Description too long")))
                    },
                    UploadError::AddFile => {
                        Ok(Response::with((Status::InternalServerError, "Error adding file to DB")))
                    },
                }
            },
        }
    }

    pub fn handle_upload_json(&self, req: &mut Request) -> IronResult<Response> {
        let flup_req = self.process_upload_request(req);

        match self.flup.upload(flup_req) {
            Ok(files) => {
                let mut json_files = vec![];

                for file_info in files {
                    json_files.push(JsonFile {
                        name: file_info.name,
                        url: format!("{}/{}", self.flup.config.url, file_info.file_id),
                        hash: file_info.hash,
                        size: file_info.size,
                    })
                }

                let response = SuccessJsonResponse {
                    success: true,
                    files: json_files,
                };

                Ok(Response::with((Status::Ok, json::encode(&response).unwrap())))
            },
            Err(error) => {
                match error {
                    UploadError::SetIp => {
                        self.json_error(500, "Error adding IP to temp DB")
                    },
                    UploadError::NoPostParams => {
                        self.json_error(400, "No POST params found")
                    },
                    UploadError::InvalidFileData => {
                        self.json_error(400, "Invalid file data found")
                    },
                    UploadError::FileEmpty => {
                        self.json_error(400, "Specified file is empty")
                    },
                    UploadError::FileTooBig => {
                        self.json_error(400, "File exceeds our limit")
                    },
                    UploadError::OpenUploadFile => {
                        self.json_error(500, "Error opening uploaded file")
                    },
                    UploadError::GetMetadata => {
                        self.json_error(500, "Unable to get file metadata")
                    },
                    UploadError::ReadData => {
                        self.json_error(500, "Error reading file data")
                    },
                    UploadError::WriteFile => {
                        self.json_error(500, "Error writing to file")
                    },
                    UploadError::BlockedExtension => {
                        self.json_error(403, "Uploading files with this extension is not allowed.")
                    },
                    UploadError::DescTooLong => {
                        self.json_error(400, "Description too long")
                    },
                    UploadError::AddFile => {
                        self.json_error(500, "Error adding file to DB")
                    },
                }
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

        match output_type.unwrap_or(String::new()).as_str() {
            "text" => self.handle_upload_text(true, req),
            "gyazo" => self.handle_upload_text(false, req),
            "json" => self.handle_upload_json(req),
            _ => self.handle_upload_html(req),
        }
    }

    fn process_file_by_id_request(&self, req: &mut Request) -> IdGetRequest {
        let router = req.extensions.get::<Router>().unwrap();
        let file_id = router.find("id").unwrap().to_string();

        IdGetRequest {
            file_id: file_id,
        }
    }

    pub fn handle_file_by_id(&self, req: &mut Request) -> IronResult<Response> {
        let flup_req = self.process_file_by_id_request(req);

        match self.flup.file_by_id(flup_req) {
            Ok((file_id, file_info)) => {
                let url = format!("{}/{}/{}", self.flup.config.url, file_id, file_info.name);
                Ok(Response::with((Status::SeeOther, Redirect(Url::parse(url.as_str()).unwrap()))))
            },
            Err(error) => {
                match error {
                    IdGetError::NotFound => {
                        self.error_page(Status::NotFound, "File not found")
                    }
                }
            },
        }
    }

    fn process_file_request(&self, req: &mut Request) -> GetRequest {
        let router = req.extensions.get::<Router>().unwrap();
        let file_id = router.find("id").unwrap().to_string();
        let filename = router.find("name").unwrap().to_string();

        GetRequest {
            file_id: file_id,
            filename: filename,
        }
    }

    pub fn handle_file(&self, req: &mut Request) -> IronResult<Response> {
        let flup_req = self.process_file_request(req);

        match self.flup.file(flup_req) {
            Ok((file_info, file_data)) => {
                let mime = mime_guess::guess_mime_type(Path::new(file_info.name.as_str()));
                Ok(Response::with((Status::Ok, mime, file_data)))
            },
            Err(error) => {
                match error {
                    GetError::NotFound => {
                        self.error_page(Status::NotFound, "File not found")
                    },
                    GetError::BlockedExtension => {
                        self.error_page(Status::Unauthorized, "Fetching this extension is not allowed, try changing the filename in the url :^)")
                    },
                    GetError::FileNotFound => {
                        self.error_page(Status::NotFound, "File not found (on disk (oh fuck))")
                    },
                }
            },
        }
    }

    pub fn handle_home(&self, _: &mut Request) -> IronResult<Response> {
        let uploads_count = self.flup.db.get_uploads_count().unwrap_or(0);
        let public_uploads_count = self.flup.db.get_public_uploads_count().unwrap_or(0);

        let data = HomePageData {
            uploads_count: uploads_count,
            public_uploads_count: public_uploads_count,
        };

        let mut resp = Response::new();
        resp.set_mut(Template::new("index", data)).set_mut(Status::Ok);
        Ok(resp)
    }

    pub fn handle_public_uploads_get(&self, _: &mut Request) -> IronResult<Response> {
        let uploads = self.flup.db.get_public_uploads().unwrap_or(vec![]);

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
}
