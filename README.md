# Flup
The program powering https://lainfile.pw

A fairly simple pomf clone written from scratch in rust using Iron as a framework, and Redis as a database.

Currently is compliant to the Pomf API standard, minus CSV, who the fuck uses CSV? And especially for fucking file uploading, what the fuck?

## Principles
- If it requires JS, don't.
- If reading the code doesn't make you depressed you need to learn Rust properly.
- If you have any idea what you are doing, don't contribute.
- Keep things abstract, especially the request handler, because I might dump Iron.
- Kill yourself.

## Configuration

It's toml, learn how to use toml, why should I have to tell you how to use shit? What is this a fucking README file? Fuck you. You don't even need to, just edit the default you eejit.

### URL
key: `url`

The URL which the instance is running on, used to generate file URLs.
#### Examples
>"https://lainfile.pw"

>"http://localhost:8080"

### Host
key: `host`

The IP and port for the webserver to bind to.
#### Examples
>"0.0.0.0:80"

>"127.0.0.1:8080"

### IP hashing salt
key: `salt`

#### Examples
>"SsPud3Qo"

>"I hate people of a jewish decent"

### X-Forwarded-For toggle
key: `xforwarded`

What are you fucking stupid? Enable this if you are behind any number of proxies above 0.

##### Examples
>true

>false

>please kill me

### X-Forwarded-For index
key: `xforwarded_index`

If using X-Forwarded-For, which header to trust.

#### Examples
>If using a single proxy: `0`

>If using a proxy and Cloudflare: `1`

>If using 99 proxies (jesus fuck): `98`

## License
Copyright © `>current year` Installgen2

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

## Hexafluoride
Please kill yourself, you are a fucking waste of life.

## Lexoi
You too.
