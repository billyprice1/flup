use super::*;

extern crate mime_guess;

use rustc_serialize::json;

use params::{Params, Value};

use iron::prelude::*;
use iron::Url;
use iron::status::Status;
use iron::modifiers::Redirect;

use router::Router;

use std::path::Path;

use hbs::Template;

#[derive(RustcEncodable)]
struct JsonFile {
    name: String,
    url: String,
    hash: String,
    size: usize,
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
    pub fn new(flup: Flup) -> FlupHandler {
        FlupHandler {
            flup: flup,
        }
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
                let files = match params.get("files") {
                    Some(&Value::Array(ref file_values)) => {
                        let mut files = vec![];

                        for value in file_values {
                            if let &Value::File(ref file) = value {
                                files.push(file.clone())
                            }
                        }

                        files
                    },
                    Some(&Value::File(ref file)) => vec![file.clone()],
                    _ => vec![],
                };

                let desc = match params.get("desc") {
                    Some(&Value::String(ref desc)) => Some(desc.clone()),
                    _ => None,
                };

                let is_public = match params.get("public") {
                    Some(&Value::String(ref toggle)) if toggle == "on" => true,
                    _ => false,
                };

                Some(UploadRequestParams {
                    files: files,

                    public: is_public,
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
                    UploadError::ReadData => {
                        self.error_page(Status::InternalServerError, "Error reading file data")
                    },
                    UploadError::WriteFile => {
                        self.error_page(Status::InternalServerError, "Error writing to file")
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
                        size: 69,
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
                    UploadError::ReadData => {
                        self.json_error(500, "Error reading file data")
                    },
                    UploadError::WriteFile => {
                        self.json_error(500, "Error writing to file")
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
        let query_string = req.url.query.clone().unwrap_or("".to_string());

        for q in query_string.split("&").collect::<Vec<&str>>() {
            if let Some(i) = q.find("=") {
                let (key, value) = q.split_at(i);

                let value = &value[1..];

                if key == "output" {
                    match value {
                        "json" => return self.handle_upload_json(req),
                        _ => return Ok(Response::with((Status::BadRequest, "Bad output type"))),
                    }
                }
            }
        }

        self.handle_upload_html(req)
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

        GetRequest {
            file_id: file_id,
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

    pub fn handle_uploads(&self, _: &mut Request) -> IronResult<Response> {
        let uploads = self.flup.db.get_uploads().unwrap_or(vec![]);

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
