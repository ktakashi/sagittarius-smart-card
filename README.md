# Sagittarius PCSC

Binding of PC/SC or winscard for Sagittarius Scheme.

## Features

  * Interactive oriented design.
  * Flexible to extend user defined commands.
  * Both Scheme or command oriented uses.

## For Scheme scripts

Use `(pcsc)` library.

TODO: API document will be here.

## For Interactive use

Run following script with Sagittarius:

    `(import (pcsc shell)) (pcsc-repl)`

Then prompt will be shown. `(help)` command will show all the defined commands.

## Loading DSL script file.

See `load.scm` file. And `samples` directory contains sample scripts.

## Requirements

Sagittarius version 0.4.2 or later.


## TODO

  * Documentation
  * More pre-defined commands
     * INSTALL, DELETE, LOAD or so.
  * Test with pcsc-lite library
