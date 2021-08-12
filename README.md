# redact-client
[![License: GPL-3.0](https://badgen.net/github/license/pauwels-labs/redact-client?color=blue)](https://opensource.org/licenses/GPL-3.0) [![crates.io](https://badgen.net/crates/v/redact-client?color=blue)](https://crates.io/crates/redact-client) [![docs.rs](https://img.shields.io/docsrs/redact-client?style=flat)](https://docs.rs/redact-client) [![Coverage Status](https://badgen.net/coveralls/c/github/pauwels-labs/redact-client/main)](https://coveralls.io/github/pauwels-labs/redact-client?branch=main)

redact-client is a binary that runs locally on a user's device and responds to requests for encrypted data from third-party websites.

It achieves this by listening for HTTP requests on port 8080. When a website places a reference to private data on their webpage, what it's truly doing is pointing an iframe to localhost with a request path corresponding to the requested data, something like `GET /data/.profile.firstName`. The client also provides some convenient query parameters listed below for various functionality.

## Encryption

Behind the scenes, the client performs several operations to get the data secured and on the page. It first fetches the appropriate data from storage, which may come to it as another reference, an encrypted set of bytes, or an unencrypted set of bytes. If the bytes come encrypted, the decryption key may itself be retrieved as a reference, an encrypted set of bytes, or an unencrypted set of bytes. The client will resolve the entire chain of references/encryption to get the final decrypted value, deserialize it into its final type, and serve it up in a secure iframe. The bulk of the retrieval and resolution work is performed by [redact-crypto](https://github.com/pauwels-labs/redact-crypto), which contains all of the abstractions that power Redact's encrypted type system.

## Opaque Data Display

The last core component of redact-client is iframe security. It must ensure that data is only served within a secure context, that is, within a webpage it controls, in order to block any other domain from being able to request it. It achieves this by splitting the request process into two requests: an unsecure one and a secure one. 

The unsecure URL is the one placed in the third-party website's iframe, it requires no tokens or authentication and simply requests that a piece of data be placed at that location. During this phase, the client generates a token and sets it in its session store. It then responds to the request with an HTML page containing another iframe pointing to the same URL with the token appended as a path parameter. It also sets a cookie at localhost with the session ID of the previously created session. During the secure route phase, the query parameter token and session token are compared for equality before data is served in the returned HTML. A third-party website could not simultaneously provide both a valid query parameter and valid cookie if it attempted to make the request itself.

## Run
1. `git clone https://github.com/pauwels-labs/redact-client`
2. Set your storage URL in config/config.yaml. You can go to [redact-store](https://github.com/pauwels-labs/redact-store) to set up your own storage.
3. `cargo r`

## Usage
- Unsecure fetch data route. This URL requires no tokens and would be provided to an iframe. It returns a page with another iframe to an internal route.
	- `GET /data/<path>?css=<string>&edit=<bool>&data_type=<string>&relay_url=<string>`
	- `<path>` is a jsonpath-style string prepended and appended by a period, e.g. `.profile.firstName.`
	- `css` is a URL-encoded CSS block meant to style the displayed data. The generated HTML can be seen [here](https://github.com/pauwels-labs/redact-client/tree/main/static/secure.handlebars).
	- `edit` should be `true` or `false` depending on if the value should be displayed in an editable input field.
	- `data_type` specifies the type of data to expect; this is particularly useful when creating new data that does not yet have a type. The value can be one of:
		- `Bool`
		- `U64`
		- `I64`
		- `F64`
		- `String`
		- `Media`
			- A binary file which will be rendered in the browser upon retrieval. Currently supported file types are:
				- `image/jpeg`
	- `relay_url` provides a handle to contact with feedback on stored user input. This would typically be a URL controlled by the host of the Redact-enabled website and used for internal bookkeeping.
	
- Secure fetch data route. This route is a CSRF protection process to ensure the client and only the client can possibly be requesting this data.
	- `GET /data/<path>/<token>?css=<string>&edit=<bool>&data_type=<string>&relay_url=<string>`
	- `<path>` is a jsonpath-style string prepended and appended by a period, e.g. `.profile.firstName.`
	- `<token>` is the secure token returned by the unsecure request
	- `css` is a URL-encoded CSS block meant to style the displayed data. The generated HTML can be seen [here](https://github.com/pauwels-labs/redact-client/tree/main/static/secure.handlebars).
	- `edit` should be `true` or `false` depending on if the value should be displayed in an editable input field.
	- `data_type` specifies the type of data to expect; this is particularly useful when creating new data that does not yet have a type. The value can be one of:
		- `Bool`
		- `U64`
		- `I64`
		- `F64`
		- `String`
		- `Media`
	- `relay_url` provides a handle to contact with feedback on stored user input. This would typically be a URL controlled by the host of the Redact-enabled website and used for internal bookkeeping.
	- There's also a `Cookie` header implied here which must contain a session ID for the session containing the same token as the one in the query parameters.
	
- Secure submit data route. This is identical to the previous to the secure fetch route but as a POST in order to submit a modification to the data store. This will also only be called internally.
	- `POST /data/<token>?css=<string>&edit=<bool>`
	- `<token>` is the secure token returned by the unsecure request
	- `css` is a URL-encoded CSS block meant to style the displayed data. The generated HTML can be seen [here](https://github.com/pauwels-labs/redact-client/tree/main/static/secure.handlebars).
	- `edit` should be `true` or `false` depending on if the value should be displayed in an editable input field.

## Test
To run unit tests:
1. `cargo t`

To run unit tests+code coverage output (does not work on macos or windows):
1. `cargo install tarpaulin`
2. `cargo tarpaulin -o html`

## Docs & Support
Docs are available at [docs.redact.ws](https://docs.redact.ws).

Join us in our Keybase channel! You can download the keybase client [here](https://keybase.io/download).

Once there, click on Teams, select Join a team, and our team name is pauwelslabs.

Once you're in, Redact discussion happens in the #redact channel.

Discussions in the Keybase team should be respectful, focused on Redact, and free of profanity.
