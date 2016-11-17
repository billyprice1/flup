"use strict"

let redis = require("redis")
let fs = require("fs")

let toml = require("toml")

let asyncAll = (fns, after) => {
	let done = 0

	fns.forEach((fn) => {
		fn(() => {
			done++

			if (done == fns.length) {
				after()
			}
		})
	})
}

{
	fs.readFile("config.toml", "utf8", (err, data) => {
		let config = toml.parse(data)

		let fileId = process.argv[2]
		let reason = process.argv[3]

		let redisPrefix = config["flup_db"]["prefix"]
		let url = config["flup_handler"]["url"]

		let redisClient = redis.createClient()

		redisClient.on("error", (err) => {
			console.error("Redis error", err)
			redisClient.quit()
		})

		redisClient.hget(`${redisPrefix}::files`, fileId, (err, reply) => {
			if (err) {
				console.error("Error checking if file exists", err)
				redisClient.quit()
				return
			}

			if (reply == null) {
				console.error("File does not exist")
				redisClient.quit()
				return
			}

			console.log("File found!")

			let fileInfo = null

			try {
				fileInfo = JSON.parse(reply)
			} catch (err) {
				console.error("Error parsing fileInfo JSON", err)
				return
			}

			let hash = fileInfo["hash"]

			asyncAll([
				(done) => {
					redisClient.hdel(`${redisPrefix}::hashes`, hash, (err) => {
						if (err) {
							console.error("Error removing from HASH->ID map", err)
							return
						}

						console.log("Removed from HASH->ID map...")
						done()
					})
				},
				(done) => {
					redisClient.lrem(`${redisPrefix}::publicfiles`, 1, fileId, (err) => {
						if (err) {
							console.error("Error removing from publicfiles", err)
							return
						}

						console.log("Removed from publicfiles...")
						done()
					})
				},
				(done) => {
					redisClient.hdel(`${redisPrefix}::files`, fileId, (err) => {
						if (err) {
							console.error("Error removing from fileInfo map", err)
							return
						}

						console.log("Removed from fileInfo map...")
						done()
					})
				},
				(done) => {
					if (reason != undefined) {
						let deletedFile = {
							reason: reason,
							file: fileInfo,
						}

						redisClient.rpush(`${redisPrefix}::deletionlog`, JSON.stringify(deletedFile), (err) => {
							if (err) {
								console.error("Error pushing to deletion log", err)
								return
							}

							console.log("Pushed to deletion log")
							done()
						})
					} else {
						done()
					}
				},
			], () => {
				redisClient.quit()
				console.log("All done :3")
			})

			fs.unlink(`files/${fileId}`, (err) => {
				if (err) {
					console.error("Error deleting file from fs", err)
					return
				}

				console.log("Deleted file from fs...")
			})
		})
	})
}