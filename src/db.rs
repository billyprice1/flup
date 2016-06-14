extern crate r2d2;
extern crate r2d2_redis;
extern crate redis;

use super::{StartError, FileInfo};

use rustc_serialize::json;

use self::redis::{Commands, ToRedisArgs, FromRedisValue};
pub use self::redis::RedisError;

use self::r2d2_redis::RedisConnectionManager;

use std::default::Default;

#[derive(Clone)]
pub struct FlupDb {
    redis: r2d2::Pool<RedisConnectionManager>,
}

impl ToRedisArgs for FileInfo {
    fn to_redis_args(&self) -> Vec<Vec<u8>> {
        json::encode(self).unwrap().to_redis_args()
    }
}

impl FromRedisValue for FileInfo {
    fn from_redis_value(v: &redis::Value) -> redis::RedisResult<Self> {
        Ok(json::decode(try!(String::from_redis_value(v)).as_str()).unwrap())
    }
}

impl FlupDb {
    pub fn new() -> Result<FlupDb, StartError> {
        let manager = match RedisConnectionManager::new("redis://127.0.0.1/") {
            Err(error) => return Err(StartError::Redis(error)),
            Ok(manager) => manager,
        };

        let config = Default::default();

        let pool = r2d2::Pool::new(config, manager).unwrap();

        Ok(FlupDb {
            redis: pool,
        })
    }

    pub fn add_file(&self, file_id: String, file: FileInfo, public: bool) -> redis::RedisResult<()> {
        let redis = self.redis.get().unwrap();

        try!(redis.hset("flup::files", file_id.clone(), file));

        if public == true {
            try!(redis.lpush("flup::publicfiles", file_id));
        }

        Ok(())
    }

    pub fn get_file(&self, file_id: String) -> redis::RedisResult<FileInfo> {
        let redis = self.redis.get().unwrap();

        match redis.hget("flup::files", file_id) {
            Ok(files) => Ok(files),
            Err(error) => Err(error),
        }
    }

    pub fn set_ip(&self, hash: String, ip: String) -> redis::RedisResult<()> {
        let redis = self.redis.get().unwrap();

        try!(redis.hset("flup::ips", hash, ip));

        Ok(())
    }

    pub fn get_ip(&self, hash: String) -> redis::RedisResult<String> {
        let redis = self.redis.get().unwrap();

        match redis.hget("flup::ips", hash) {
            Ok(ip) => Ok(ip),
            Err(error) => Err(error),
        }
    }

    pub fn get_uploads(&self) -> redis::RedisResult<Vec<FileInfo>> {
        let redis = self.redis.get().unwrap();

        let public_ids: Vec<String> = try!(redis.lrange("flup::publicfiles", 0, 20));

        Ok(public_ids.into_iter().map(|key: String| {
            self.get_file(key).unwrap()
        }).collect())
    }

    pub fn get_uploads_count(&self) -> redis::RedisResult<isize> {
        let redis = self.redis.get().unwrap();

        Ok(try!(redis.hlen("flup::files")))
    }

    pub fn get_public_uploads_count(&self) -> redis::RedisResult<isize> {
        let redis = self.redis.get().unwrap();

        Ok(try!(redis.llen("flup::publicfiles")))
    }
}
