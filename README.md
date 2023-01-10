# whoarethey

A program to determine what SSH keys a server accepts.  See
https://www.agwa.name/blog/post/whoarethey for background.
Inspired by [whoami.filippo.io](https://words.filippo.io/dispatches/whoami-updated/).

## Install

If you have the latest version of Go installed, you can run:

```
go install src.agwa.name/whoarethey@latest
```

## Usage

Specify the host/port of the SSH server, the username to try logging
in as, and one or more keys, which can specified as the name of an
`authorized_keys`-formatted file, or a GitHub username prefixed with
`github:`:

```
whoarethey HOST:PORT USERNAME KEYSFILE|github:USERNAME...
```

The program outputs a list of the keys which were accepted by the server.

## Example

To determine if @AGWA or @FiloSottile can log in as root on 192.0.2.4:

```
$ whoarethey 192.0.2.4:22 root github:AGWA github:FiloSottile
github:AGWA
```
