jose-fmt(1) -- Converts JSON between serialization formats
==========================================================

## SYNOPSIS

`jose fmt` [OPTIONS]

## OVERVIEW

This `jose fmt` command provides a mechanism for building and parsing JSON
objects from the command line. It operates as a simple stack machine. All
commands operate on the TOP item of the stack and, occasionally, the PREV item
of the stack. Commands that require a specific type of value will indicate it
in parentheses. For example: "TOP (arr.)".

This program returns 0 on success or the index of the option which failed.

## OPTIONS

* `-X`, `--not` :
  Invert the following assertion

* `-O`, `--object` :
  Assert TOP to be an object

* `-A`, `--array` :
  Assert TOP to be an array

* `-S`, `--string` :
  Assert TOP to be a string

* `-I`, `--integer` :
  Assert TOP to be an integer

* `-R`, `--real` :
  Assert TOP to be a real

* `-N`, `--number` :
  Assert TOP to be a number

* `-T`, `--true` :
  Assert TOP to be true

* `-F`, `--false` :
  Assert TOP to be false

* `-B`, `--boolean` :
  Assert TOP to be a boolean

* `-0`, `--null` :
  Assert TOP to be null

* `-E`, `--equal` :
  Assert TOP to be equal to PREV

* `-Q`, `--query` :
  Query the stack by deep copying and pushing onto TOP

* `-M` #, `--move`=# :
  Move TOP back # places on the stack

* `-U`, `--unwind` :
  Discard TOP from the stack

* `-j` _JSON_, `--json`=_JSON_ :
  Parse JSON constant, push onto TOP

* `-j` _FILE_, `--json`=_FILE_ :
  Read from FILE, push onto TOP

* `-j` -, `--json`=- :
  Read from STDIN, push onto TOP

* `-c`, `--copy` :
  Deep copy TOP, push onto TOP

* `-q` _STR_, `--quote`=_STR_ :
  Convert STR to a string, push onto TOP

* `-o` _FILE_, `--output`=_FILE_ :
  Write TOP to FILE

* `-o` -, `--output`=- :
  Write TOP to STDOUT

* `-f` _FILE_, `--foreach`=_FILE_ :
  Write TOP (obj./arr.) to FILE, one line/item

* `-f` -, `--foreach`=- :
  Write TOP (obj./arr.) to STDOUT, one line/item

* `-u` _FILE_, `--unquote`=_FILE_ :
  Write TOP (str.) to FILE without quotes

* `-u` -, `--unquote`=- :
  Write TOP (str.) to STDOUT without quotes

* `-t` #, `--truncate`=# :
  Shrink TOP (arr.) to length #

* `-t` -#, `--truncate`=-# :
  Discard last # items from TOP (arr.)

* `-i` #, `--insert`=# :
  Insert TOP into PREV (arr.) at #

* `-a`, `--append` :
  Append TOP to the end of PREV (arr.)

* `-a`, `--append` :
  Set missing values from TOP (obj.) into PREV (obj.)

* `-x`, `--extend` :
  Append items from TOP to the end of PREV (arr.)

* `-x`, `--extend` :
  Set all values from TOP (obj.) into PREV (obj.)

* `-d` _NAME_, `--delete`=_NAME_ :
  Delete NAME from TOP (obj.)

* `-d` #, `--delete`=# :
  Delete # from TOP (arr.)

* `-d` -#, `--delete`=-# :
  Delete # from the end of TOP (arr.)

* `-l`, `--length` :
  Push length of TOP (arr./str./obj.) to TOP

* `-e`, `--empty` :
  Erase all items from TOP (arr./obj.)

* `-g` _NAME_, `--get`=_NAME_ :
  Get item with NAME from TOP (obj.), push to TOP

* `-g` #, `--get`=# :
  Get # item from TOP (arr.), push to TOP

* `-g` -#, `--get`=-# :
  Get # item from the end of TOP (arr.), push to TOP

* `-s` _NAME_, `--set`=_NAME_ :
  Sets TOP into PREV (obj.) with NAME

* `-s` #, `--set`=# :
  Sets TOP into PREV (obj.) at #

* `-s` -#, `--set`=-# :
  Sets TOP into PREV (obj.) at # from the end

* `-y`, `--b64load` :
  URL-safe Base64 decode TOP (str.), push onto TOP

* `-Y`, `--b64dump` :
  URL-safe Base64 encode TOP, push onto TOP

## EXAMPLES

Extract the `alg` parameter from a JWE Protected Header:

    $ jose fmt -j "$jwe" -Og protected -yOg alg -Su-
    A128KW

List all JWKs in a JWKSet (one per line):

    $ echo "$jwkset" | jose fmt -j- -Og keys -Af-
    {"kty":"oct",...}
    {"kty":"EC",...}

Change the algorithm in a JWK:

    $ echo "$jwk" | jose fmt -j- -j '"A128GCM"' -s alg -Uo-
    {"kty":"oct","alg":"A128GCM",...}

Build a JWE template:

    $ jose fmt -j '{}' -cs unprotected -q A128KW -s alg -UUo-
    {"unprotected":{"alg":"A128KW"}}

## AUTHOR

Nathaniel McCallum &lt;npmccallum@redhat.com&gt;
