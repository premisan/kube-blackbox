.PHONY: all test build run install-crd deploy-samples clean

all: test build

test:
	go test -v ./...

build:
	go build -o bin/kube-pinger main.go

run:
	go run main.go

install-crd:
	kubectl apply -f config/crd/bases/observer.io_podrestarthistories.yaml

deploy-samples:
	kubectl apply -f samples/01-oomkilled.yaml
	kubectl apply -f samples/02-liveness-probe-failure.yaml
	kubectl apply -f samples/03-app-panic.yaml

delete-samples:
	kubectl delete -f samples/01-oomkilled.yaml --ignore-not-found
	kubectl delete -f samples/02-liveness-probe-failure.yaml --ignore-not-found
	kubectl delete -f samples/03-app-panic.yaml --ignore-not-found
