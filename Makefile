.DEFAULT_GOAL := help 

gen-keys: ## generate keys 
	./scripts/gen_key.sh

gen-token: ## generate token
	go run main.go

test: ## run tests 
	go test ./...

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
