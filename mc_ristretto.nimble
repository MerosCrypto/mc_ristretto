version     = "0.2.1"
author      = "Luke Parker"
description = "A Nim Wrapper for dalek's Ristretto functionality as needed by Meros."
license     = "MIT"

installFiles = @[
  "mc_ristretto.nim"
]

installDirs = @[
  "src",
  "target"
]

requires "nim > 1.2.10"

before install:
  let cargoExe: string = system.findExe("cargo")
  if cargoExe == "":
    echo "Failed to find executable `cargo`."
    quit(1)

  exec cargoExe & " build --release"
