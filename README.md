A simple, customizable SSH & Telnet honeypot server, with an API for viewing user interactions.

The API is written in Go, and the honeypot server leverages [Cowrie](https://github.com/cowrie/cowrie), which you can find in [`honeypot/`](./honeypot).

## Setup

To setup the honeypot server itself, you first need to configure what the filesystem and credentials will be:

```bash
# configure valid credentials
$ vim honeypot/userdb.txt

# the filesystem is built by taking the debian:bullseye image
# and copying over everything in honeypot/honeyfs/ into it.
# so, you can customize this directory to your liking:
$ ls honeypot/honeyfs/
```

Now build the filesystem:

```bash
# update the cowrie submodule
$ git submodule update --init --recursive
# use docker to build the filesystem
$ make build-honeyfs
# due to permission issues, you may need to run the following command
$ sudo make update-perms
```

For the API, you need to set some environment variables:
```bash
$ cat .env
HONEYPOT_API_PORT=8000     # web server port for API
HONEYPOT_SSH_PORT=2222     # where to accept SSH connections
HONEYPOT_TELNET_PORT=2223  # where to accept Telnet connections
AUTH_TOKEN=your_auth_token # token for accessing the API
SLACK_WEBHOOK=<url>        # optional, if you want to send alerts to Slack
```

Now, build it up:
```bash
docker compose build
```

## Usage

```bash
$ docker compose up
```

#### Accessing the Honeypot
```bash
$ ssh -p 2222 bliss@localhost # pw: bliss
$ telnet localhost 2223
```

#### Accessing the API
To view interaction data, you can access a Swagger UI at `http://localhost:8000/api`.

Here's an example of how to get all sessions:
```bash
curl -X 'GET' \
  'http://localhost:8000/api/sessions?limit=10&offset=0&include_failed_logins=false' \
  -H 'accept: application/json' \
  -H 'Authorization: your_auth_token' | jq
```

Keep in mind that sometimes the first valid login to the server might not be recorded; try logging in a second time.

#### Reports

A report of all interaction data is generated every 10 minutes, and once a report is generated you can access it at the endpoint shown below.

To manually generate and view a report, you can run:
```bash
$ curl -X 'POST' \
  'http://localhost:8000/api/report' \
  -H 'accept: application/json' \
  -H 'Authorization: your_auth_token' \

$ curl 'http://localhost:8000/api/report?token=your_auth_token'
# this will be html, just go open it in a browser
```

This report is generated using a Python script, with an embedded interpreter! Check it out in [`report/`](report/report.go).
