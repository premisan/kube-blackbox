.PHONY: all test build run docker-build deploy undeploy install-crd deploy-samples delete-samples clean

IMAGE ?= premisan0/kube-pinger:latest

all: test build

test:
	go test -v ./...

build:
	go build -o bin/kube-pinger main.go

run:
	go run main.go

docker-build:
	docker build -t $(IMAGE) .

deploy: install-crd
	kubectl apply -f config/deploy/deploy.yaml

undeploy:
	kubectl delete -f config/deploy/deploy.yaml --ignore-not-found

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
