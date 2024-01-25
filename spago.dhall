{ name = "node-crypto"
, dependencies =
  [ "effect"
  , "either"
  , "exceptions"
  , "maybe"
  , "node-buffer"
  , "node-streams"
  , "nullable"
  , "prelude"
  , "unsafe-coerce"
  ]
, packages = ./packages.dhall
, sources = [ "src/**/*.purs" ]
}
