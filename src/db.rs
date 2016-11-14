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

#[derive(Debug, Clone, RustcDecodable)]
pub struct FlupDbConfig {
    prefix: String,
}

#[derive(Clone)]
pub struct FlupDb {
    redis: r2d2::Pool<RedisConnectionManager>,
    config: FlupDbConfig,
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
    pub fn new(config: FlupDbConfig) -> Result<FlupDb, StartError> {
        let manager = match RedisConnectionManager::new("redis://127.0.0.1/") {
            Err(error) => return Err(StartError::RedisError(error)),
            Ok(manager) => manager,
        };

        let r2d2_config = Default::default();

        let pool = match r2d2::Pool::new(r2d2_config, manager) {
            Err(error) => return Err(StartError::Pool(error)),
            Ok(pool) => pool,
        };

        Ok(FlupDb {
            redis: pool,
            config: config,
        })
    }

    fn get_redis(&self) -> r2d2::PooledConnection<RedisConnectionManager> {
        self.redis.get()
            .expect("DB Error: Unable to get Redis conn from pool")
    }

    pub fn new_id_seed(&self) -> isize {
        let redis = self.get_redis();

        redis.incr(format!("{}::idseed", &self.config.prefix), 1)
            .expect("DB Error: Unable to get ID seed")
    }

    pub fn add_file(&self, file_id: &String, file: &FileInfo, public: bool) {
        let redis = self.get_redis();

        let () = redis.hset(format!("{}::hashes", &self.config.prefix), file.hash.clone(), file_id.clone())
            .expect(&format!("DB Error: Error adding file hash to file hashes map (ID: {})", file_id));
        let () = redis.hset(format!("{}::files", &self.config.prefix), file_id.clone(), file.clone())
            .expect(&format!("Error adding file info to files DB (ID: {})", file_id));

        if public == true {
            redis.lpush(format!("{}::publicfiles", &self.config.prefix), file_id)
                .expect(&format!("DB Error: Error adding file ID to public files list (ID: {})", file_id))
        }
    }

    pub fn get_file_id_by_hash(&self, hash: &str) -> Option<String> {
        let redis = self.get_redis();

        redis.hget(format!("{}::hashes", &self.config.prefix), hash)
            .expect(&format!("DB Error: Error getting file ID from file hashes map (hash: {})", hash))
    }

    pub fn get_file_by_id(&self, file_id: &str) -> Option<FileInfo> {
        let redis = self.get_redis();

        redis.hget(format!("{}::files", &self.config.prefix), file_id)
            .expect(&format!("DB Error: Error getting file info from file map (ID: {})", file_id))
    }

    pub fn get_public_uploads(&self) -> Vec<String> {
        let redis = self.get_redis();

        redis.lrange(format!("{}::publicfiles", &self.config.prefix), 0, -1)
            .expect("DB Error: Error getting public uploads list")
    }

    pub fn get_uploads_count(&self) -> isize {
        let redis = self.get_redis();

        redis.hlen(format!("{}::files", &self.config.prefix))
            .expect("DB Error: Error getting public upload count")
    }

    pub fn get_public_uploads_count(&self) -> isize {
        let redis = self.get_redis();

        redis.llen(format!("{}::publicfiles", &self.config.prefix))
            .expect("DB Error: Error getting public upload count")
    }

    pub fn get_deleted_files(&self) -> Vec<DeletedFile> {
        let redis = self.get_redis();

        redis.lrange(format!("{}::deletionlog", &self.config.prefix), 0, -1)
            .expect("DB Error: Error getting deleted files list")
    }
}
