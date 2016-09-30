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
    key_prefix: String,
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
    pub fn new(key_prefix: String) -> Result<FlupDb, StartError> {
        let manager = match RedisConnectionManager::new("redis://127.0.0.1/") {
            Err(error) => return Err(StartError::Redis(error)),
            Ok(manager) => manager,
        };

        let config = Default::default();

        let pool = r2d2::Pool::new(config, manager).unwrap();

        Ok(FlupDb {
            redis: pool,
            key_prefix: key_prefix,
        })
    }

    pub fn new_id_seed(&self) -> redis::RedisResult<usize> {
        let redis = self.redis.get().unwrap();

        Ok(try!(redis.incr(self.key_prefix.clone() + "::idseed", 1)))
    }

    pub fn add_file(&self, file_id: String, file: FileInfo, public: bool) -> redis::RedisResult<()> {
        let redis = self.redis.get().unwrap();

        try!(redis.hset(self.key_prefix.clone() + "::hashes", file.hash.clone(), file_id.clone()));
        try!(redis.hset(self.key_prefix.clone() + "::files", file_id.clone(), file));

        if public == true {
            try!(redis.lpush(self.key_prefix.clone() + "::publicfiles", file_id));
        }

        Ok(())
    }

    pub fn get_file_id_by_hash(&self, hash: String) -> redis::RedisResult<String> {
        let redis = self.redis.get().unwrap();

        Ok(try!(redis.hget(self.key_prefix.clone() + "::hashes", hash)))
    }

    pub fn get_file_by_id(&self, file_id: String) -> redis::RedisResult<FileInfo> {
        let redis = self.redis.get().unwrap();

        Ok(try!(redis.hget(self.key_prefix.clone() + "::files", file_id)))
    }

    pub fn get_public_uploads(&self) -> redis::RedisResult<Vec<FileInfo>> {
        let redis = self.redis.get().unwrap();

        let public_ids: Vec<String> = try!(redis.lrange(self.key_prefix.clone() + "::publicfiles", 0, 20));

        Ok(public_ids.into_iter().map(|key: String| {
            self.get_file_by_id(key).unwrap()
        }).collect())
    }

    pub fn get_uploads_count(&self) -> redis::RedisResult<isize> {
        let redis = self.redis.get().unwrap();

        Ok(try!(redis.hlen(self.key_prefix.clone() + "::files")))
    }

    pub fn get_public_uploads_count(&self) -> redis::RedisResult<isize> {
        let redis = self.redis.get().unwrap();

        Ok(try!(redis.llen(self.key_prefix.clone() + "::publicfiles")))
    }
}
