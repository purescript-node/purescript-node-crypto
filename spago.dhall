{ name = "node-crypto"
, dependencies =
  [ "effect"
  , "either"
  , "exceptions"
  , "foreign"
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
