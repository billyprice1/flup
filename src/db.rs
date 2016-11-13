extern crate r2d2;
extern crate r2d2_redis;
extern crate redis;

use super::{FileInfo, DeletedFile};

use rustc_serialize::json;

use self::redis::{Commands, ToRedisArgs, FromRedisValue};
use self::r2d2_redis::RedisConnectionManager;

use std::default::Default;

#[derive(Debug)]
pub enum StartError {
    RedisError(redis::RedisError),
    Pool(r2d2::InitializationError),
}

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

impl ToRedisArgs for DeletedFile {
    fn to_redis_args(&self) -> Vec<Vec<u8>> {
        json::encode(self).unwrap().to_redis_args()
    }
}

impl FromRedisValue for DeletedFile {
    fn from_redis_value(v: &redis::Value) -> redis::RedisResult<Self> {
        Ok(json::decode(try!(String::from_redis_value(v)).as_str()).unwrap())
    }
}

impl FlupDb {
    pub fn new(key_prefix: String) -> Result<FlupDb, StartError> {
        let manager = match RedisConnectionManager::new("redis://127.0.0.1/") {
            Err(error) => return Err(StartError::RedisError(error)),
            Ok(manager) => manager,
        };

        let config = Default::default();

        let pool = match r2d2::Pool::new(config, manager) {
            Err(error) => return Err(StartError::Pool(error)),
            Ok(pool) => pool,
        };

        Ok(FlupDb {
            redis: pool,
            key_prefix: key_prefix,
        })
    }

    fn get_redis(&self) -> r2d2::PooledConnection<RedisConnectionManager> {
        self.redis.get().expect("Unable to get redis conn from pool")
    }

    pub fn new_id_seed(&self) -> redis::RedisResult<usize> {
        let redis = self.get_redis();

        Ok(try!(redis.incr(self.key_prefix.clone() + "::idseed", 1)))
    }

    pub fn add_file(&self, file_id: String, file: FileInfo, public: bool) -> redis::RedisResult<()> {
        let redis = self.get_redis();

        try!(redis.hset(self.key_prefix.clone() + "::hashes", file.hash.clone(), file_id.clone()));
        try!(redis.hset(self.key_prefix.clone() + "::files", file_id.clone(), file));

        if public == true {
            try!(redis.lpush(self.key_prefix.clone() + "::publicfiles", file_id));
        }

        Ok(())
    }

    pub fn get_file_id_by_hash(&self, hash: String) -> redis::RedisResult<String> {
        let redis = self.get_redis();

        Ok(try!(redis.hget(self.key_prefix.clone() + "::hashes", hash)))
    }

    pub fn get_file_by_id(&self, file_id: String) -> redis::RedisResult<FileInfo> {
        let redis = self.get_redis();

        Ok(try!(redis.hget(self.key_prefix.clone() + "::files", file_id)))
    }

    pub fn get_public_uploads(&self) -> redis::RedisResult<Vec<FileInfo>> {
        let redis = self.get_redis();

        let public_ids: Vec<String> = try!(redis.lrange(self.key_prefix.clone() + "::publicfiles", 0, 20));

        Ok(public_ids.into_iter().map(|key: String| {
            self.get_file_by_id(key).expect("File in publicfiles missing") // TODO: handle this error
        }).collect())
    }

    pub fn get_uploads_count(&self) -> redis::RedisResult<isize> {
        let redis = self.get_redis();

        Ok(try!(redis.hlen(self.key_prefix.clone() + "::files")))
    }

    pub fn get_public_uploads_count(&self) -> redis::RedisResult<isize> {
        let redis = self.get_redis();

        Ok(try!(redis.llen(self.key_prefix.clone() + "::publicfiles")))
    }

    pub fn get_deleted_files(&self) -> redis::RedisResult<Vec<DeletedFile>> {
        let redis = self.get_redis();

        Ok(try!(redis.lrange(self.key_prefix.clone() + "::deletionlog", 0, -1)))
    }
}
