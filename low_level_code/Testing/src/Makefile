all: sync async
.PHONY: all

config:
	npm install aws-sdk async
	stack install monad-parallel
.PHONY: config

sync: config
	luna run --target luna_sync.luna
	stack runghc haskell_sync.hs
	node node_sync.js
.PHONY: sync

async: config 
	luna run --target luna_async.luna
	stack runghc haskell_async.hs
	node node_async.js
.PHONY: async
