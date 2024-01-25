let config = ./spago.dhall
in 
{ name = "node-crypto-test"
, dependencies = [ "console", "effect", "node-buffer", "prelude" ] # config.dependencies
, packages = ./packages.dhall
, sources = [ "test/**/*.purs" ] # config.sources
}
