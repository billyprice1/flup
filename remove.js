let redis = require("redis")
let fs = require("fs")

let toml = require("toml")

{
	let config = toml.parse("config.toml")

	let fileId = process.argv[2]
	let redisPrefix = config["redis_prefix"]

	fs.unlink(`files/${fileId}`, (err) => {
		console.log("Error deleting", err)
	})

	let redisClient = redis.createClient()

	redisClient.on("error", (err) => {
		console.error("Redis error", err)
	})

	redisClient.hdel(`${redisPrefix}::files`, fileId, (err) => {
		if (err) {
			console.error(err)
		}
	})
}