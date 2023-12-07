# WebACL

WebACL provides a simple web UI for managing ACL access permissions on a linux system.

**Disclaimer:** This app has been built some time ago for a very specific usecase. You might want to audit security and usability before using it for your own projects. Also note that all text is in German.

## Prerequisites

- A linux system managing a filesystem with ACL access management (e.g. for `samba`) using `setfacl`/`getfacl`
  - Test this by navigating into the managed structure and running `getfacl <some folder>`, the command should return sensible data
- A webserver environment like `nginx` or `apache` and a certificate that can be checked[^certfix]
- Local group management, e.g. via `winbind` (AD) or linux groups
- A `keycloak` or other OIDC SSO system for login management

## Setup

### Installation

1. Install the current version of `python3`
2. Clone this repository via `git clone https://github.com/xorwow/webacl`
3. Navigate into the new `webacl` directory 
4. Run `pip3 install -r requirements.txt` to install the required packages
6. Configure your app and flask settings as shown in the next section

### Configuration

#### App config

Copy the file `templates/config.py.template` to `./config.py` and fill out the missing fields. It should look like this:

```python
import os, logging

# Minimum log level to write, DEBUG includes extensive tracing, INFO just important events
# This will affect sysout logging as well as file logging
MIN_LOG_LEVEL = logging.INFO

# Create a random app secret key and put it here. Do not share.
#SECRET_KEY = os.getenv(WEBACL_SECRET_KEY).encode('utf-8')
SECRET_KEY = b'<something very random>'

# Base path of ACL folder scope. Requests for files outside this scope will be blocked.
SAFE_BASE_PATH = '<root path of the managed file structure that should be exposed>'
BASE_REALPATH = os.path.join(os.path.realpath(SAFE_BASE_PATH), '')

# A user that has any of ADMIN_GROUPS or is included in ADMIN_USERS will be treated as an administrator.
ADMIN_GROUPS = [ '<a linux/winbind group that is only assigned to admins>' ]
ADMIN_USERS = [ '<a specific admin user>' ]

# Only allow users within these groups to log in and use the service
# Additionally, the ADMIN_GROUPS and ADMIN_USERS will be checked
ALLOWED_LOGIN_GROUPS = [ '<a group that is only assigned to users which may use this service>' ]

# Protected group and user permission entries that will not be listed to non-admin users.
PROTECTED_GROUPS = [ '<a group that will not be shown to or be modifiable by normal users>' ]
PROTECTED_USERS = [ '<a user that will not be shown to or be modifiable by normal users>' ]

# Maximum search depth for the admin view global search
# Increasing this will significantly lenghten the search process
# 0 for infinite
MAX_SEARCH_DEPTH = 4

# Config for flask-oidc (see https://flask-oidc.readthedocs.io/en/latest/)
OIDC_CONFIG = {
    'SECRET_KEY': SECRET_KEY,
    'OIDC_CLIENT_SECRETS': 'client_secrets.json',
    'OIDC_ID_TOKEN_COOKIE_SECURE': False,
    'OIDC_REQUIRE_VERIFIED_EMAIL': False,
    'OIDC_USER_INFO_ENABLED': True,
    'OIDC_OPENID_REALM': '<your realm id>',
    'OIDC_SCOPES': ['openid', 'email'],
    'OIDC_INTROSPECTION_AUTH_METHOD': 'client_secret_post'
}
```

Copy the file `templates/client_secrets.json.template` to `./client_secrets.json` and fill out the missing fields regarding your OIDC system. It should look like this:

```json
{
    "web": {
        "client_id": "<...>",
        "client_secret": "<...>",
        "auth_uri": "<...>",
        "token_uri": "<...>",
        "userinfo_uri": "<...>",
        "issuer": "<...>",
        "redirect_uris": [ "https://127.0.0.1/oidc_callback" ]
    }
}
```

More information on setting up a `keycloak` client is found below.

#### Flask config

*This section describes a production environment. See [Development](#-development) for running a development/testing environment.*

The official [flask documentation](https://flask.palletsprojects.com/en/2.1.x/deploying/) gives pointers on how to run your app through a specific webserver.  
For `nginx`/`uwsgi`, use `/=app:app` for the redirect operations, since the location is (usually) `/` and the app name is `app`.

After installing the uwsgi-python3 plugin, a full command (run from the `webacl` dir) could look like this:

`uwsgi -s /run/webacl.sock --manage-script-name --mount /=app:app --plugin python3 --chmod-socket=666`

The corresponding nginx section would be:

```
server {

        listen 443 ssl;
        server_name localhost;

        ssl_certificate cert.pem;
        ssl_certificate_key cert.key;
        ssl_protocols TLSv1.2;
        ssl_session_cache shared:SSL:1m;
        ssl_session_timeout 5m;
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers on;

        location / { try_files $uri @webacl; }
        location @webacl {
            include uwsgi_params;
            uwsgi_pass unix:///run/webacl.sock;
        }
    }
```

Don't forget to include a cert.pem/cert.key in the location specified in this config.

#### Keycloak config

When using `keycloak`, enter your administration console and create a new client:

- Select a client ID, e.g. `webacl`
- Set the client protocol to `openid-connect`
- Set the access type to `confidential`
- Enable `Standard Flow`
- Add the following authorized redirect URIs
  - `https://127.0.0.1/oidc_callback`
  - `https://<your external server IP or FQDN>/oidc_callback`

You can then add the client id and generated client secret to your `client_secrets.json`.

## Usage

When your app is up and running, navigate to the server in your browser (typically `https://<your FQDN or IP>/`). You will be redirected to your OIDC login page.
After logging in, you can access the folder overview endpoint if your user is in the allowed login (or admin) groups defined in `config.py`.
On the overview, the first level of subfolders of your fileroot will be listed, but only for folders the logged in user can access with write privileges.
When clicking on a folder, you can navigate to its subfolders or view/change its ACL permission set.
Note that when adding a permission to a folder, all parent folders up to the fileroot will receive readonly permissions for this user to allow for folder traversal.

### Administration

When the logged in user is in the configured admin groups/users, you will additionally be shown a link to the admin portal on the folder overview page.
You will also have no restrictions on viewing folders, even if you do not have write privileges for them.
The admin portal contains options for clearing the internal caches and for listing all folders a user has access to.

#### Cache management

You can clear the entity cache as well as the folder cache.
This is needed if you find that the information the service has does not reflect the actual state of the system.
The can happen if you manually change the groups of a user, re-sync your AD to the local system or manually change folder permissions.

#### Global search

When you enter the name of a user into the global search, the service will scan all folders (up to a depth defined in `config.py`) in the fileroot for
ones the user has access to (read-only or writeable). These can then be removed individually or as a whole.
Note that the first time this runs, it will take a significant amount of time, depending on the amount of folders to scan.
This is a consequence of the permission query taking some time on an average system. On subsequent searches, folders should mostly be cached so it will run much faster.

## Logging

As configured in `config.py`, information from a certain logging level upwards (typically `INFO` or `DEBUG`) will be printed to `sysout` and written to `session.log`.
The session log will be replaced every time you (re)start the server.

Additionally, `action.log` will contain all ACL permission updates performed through the system in a parseable format for emergency recovery.
It will never be wiped/replaced, but includes a timestamp with every logged action for filtering.

## Development

### Running a development server

You can run a flask development server instead of a full webserver environment during testing.
Beware that this must still run on a system that fulfills the requirements listed above.

To start this server, export the following environment variables:  
`FLASK_APP='app'`  
`FLASK_ENV='development'`

Then start your server using `flask run --host=0.0.0.0 --port=443 --cert=adhoc`. It will automatically restart when a file changes and show python errors in the web UI.  
`--cert=adhoc` is used to generate a SSL certificate on-the-fly every time you start the server. You can also use a self-generated cert/key pair with `--cert=<cert>.pem --key=<key>.pem`.
If you get an SSL error informing you that the local issuer certificate cannot be validated, check this footnote[^certfix].

### An overview of the codebase

First, it helps to make yourself familiar with [basic flask coding](https://flask.palletsprojects.com/en/2.1.x/quickstart/).  
All of the "views" (URL endpoints) are contained in `app.py`. All interaction with the filesystem and user/group management are contained in `fstools.py`.

#### app.py

This file contains all flask-related code: URL endpoints ("views") and routines for updating folder information and performing administrative actions.
It also exposes the flask app object used for running a server. It is the root of the project.

#### fstools.py

This file is used to interact with the filesystem and local user/group management. It allows you to fetch folder permissions, walk the FS, fetch user groups and more.
It also containes some important classes used throughout the app, which are cached for speed:

##### Entity (with children `User` and `Group`)

This object denotes a user or group. It will always include the name (id) of the entity and some useful attributes like `is_admin`, `is_protected`, etc.
User objects also include the user's group memberships and if the user is allowed to use the service.

Get a validated entity by using `fstools.get_entity(name, check_name=True, is_group=None)`.
If `check_name` is `False`, it will not be validated that this entity really exists, as long as you also supply the `is_group` status.
This is useful if you have already validated this data through other means and would like to save time.

##### Folder

A folder object denotes a folder on the filesystem. It has helpers for getting the folder's permisisons and relative path to the configured fileroot.

Get a validated entity by using `fstools.get_entity(path, name=None, check_path=True)`.
The `name` attribute supplies the folder's name as shown in the web UI. If omitted, it will be extracted from the `path`.
If `check_path` is `False`, it will not be validated that this path really exists and is within safe bounds of the fileroot.
This is useful if you have already validated this data through other means and would like to save time.

##### Permission

A permission object denotes a specific permission on a folder (although it is not bound to a specific folder and can therefore be re-used).

It includes information on the permission being read-only or inheritable (`default` in ACL terms), and which entity it belongs to.

##### templates/

This directory contains the HTML-Jinja2 templates used to render the webpages. It also contains configuration templates used for setting up the project.

##### static/

This directory contains the main CSS file for the webpage.

[^certfix]:
    If your local issuer certificate cannot be validated on a SSO redirect, try the following:
    First, download your issuer certificate, e.g. with `wget https://letsencrypt.org/certs/lets-encrypt-r3.pem`.
    Then, install `python3-certifi` run the following snippet in a python shell:
    ```python
    import certifi
    cafile = certifi.where()
    with open('lets-encrypt-r3.pem', 'rb') as infile:
        customca = infile.read()
    with open(cafile, 'ab') as outfile:
        outfile.write(customca)
    ```
    This will insert the issuer certificate into the local cert store used by flask.
