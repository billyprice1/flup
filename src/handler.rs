use super::*;

extern crate mime_guess;

use params::{Params, Value};

use iron::prelude::*;
use iron::Url;
use iron::status::Status;
use iron::modifiers::Redirect;

use router::Router;

use std::path::Path;

use hbs::Template;

#[derive(ToJson)]
struct HomePageData {
    uploads_count: isize,
    public_uploads_count: isize,
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

    pub fn handle_upload(&self, req: &mut Request) -> IronResult<Response> {
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

        let flup_req = UploadRequest {
            xforwarded: xforwarded,

            params: params,

            ip: req.remote_addr.to_string(),
        };

        match self.flup.upload(flup_req) {
            Ok(file_ids) => {
                let url = format!("{}/{}", self.flup.config.url, file_ids.join(" "));
                Ok(Response::with((Status::Ok, format!("{}", url))))
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

    pub fn handle_file_by_id(&self, req: &mut Request) -> IronResult<Response> {
        let router = req.extensions.get::<Router>().unwrap();
        let file_id = router.find("id").unwrap().to_string();

        let flup_req = IdGetRequest {
            file_id: file_id,
        };

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

    pub fn handle_file(&self, req: &mut Request) -> IronResult<Response> {
        let router = req.extensions.get::<Router>().unwrap();
        let file_id = router.find("id").unwrap().to_string();

        let flup_req = GetRequest {
            file_id: file_id,
        };

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
