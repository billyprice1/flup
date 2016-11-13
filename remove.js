"use strict"

let redis = require("redis")
let fs = require("fs")

let toml = require("toml")

{
	fs.readFile("config.toml", "utf8", (err, data) => {
		let config = toml.parse(data)

		let fileId = process.argv[2]
		let reason = process.argv[3]

		let redisPrefix = config["redis_prefix"]
		let url = config["url"]

		let redisClient = redis.createClient()

		redisClient.on("error", (err) => {
			console.error("Redis error", err)
		})

		redisClient.hget(`${redisPrefix}::files`, fileId, (err, reply) => {
			if (err) {
				console.error("Error checking if file exists", err)
				return
			}

			if (!reply) {
				redisClient.quit()
				console.error("File does not exist")
				return
			}

			console.log("File found!")

			fs.unlink(`files/${fileId}`, (err) => {
				if (err) {
					console.error("Error deleting file from fs", err)
				}

				console.log("Deleted file from fs...")
			})

			let fileInfo = {}

			try {
				fileInfo = JSON.parse(reply)
			} catch (err) {
				redisClient.quit()
				console.error("Error parsing fileInfo JSON", err)
			}

			let hash = fileInfo["hash"]

			redisClient.lrem(`${redisPrefix}::publicfiles`, 1, fileId, (err) => {
				if (err) {
					redisClient.quit()
					console.error("Error removing from publicfiles", err)
					return
				}

				console.log("Removed from publicfiles...")

				redisClient.hdel(`${redisPrefix}::hashes`, hash, (err) => {
					if (err) {
						redisClient.quit()
						console.error("Error removing from HASH->ID map", err)
						return
					}

					console.log("Removed from HASH->ID map...")

					redisClient.hdel(`${redisPrefix}::files`, fileId, (err) => {
						if (err) {
							redisClient.quit()
							console.error("Error removing from fileInfo map", err)
							return
						}

						console.log("Removed from fileInfo map...")

						if (reason != undefined) {
							let deletedFile = {
								reason: reason,
								file: fileInfo,
							}

							redisClient.rpush(`${redisPrefix}::deletionlog`, JSON.stringify(deletedFile), (err) => {
								if (err) {
									redisClient.quit()
									console.error("Error pushing to deletion log", err)
									return
								}

								console.log("Pushed to deletion log")

								redisClient.quit()
								console.log("All done :3")
							})
						} else {
							redisClient.quit()
							console.log("All done :3")
						}
					})
				})
			})
		})
	})
}