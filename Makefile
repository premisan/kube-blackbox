.PHONY: all test build run docker-build deploy undeploy install-crd deploy-samples delete-samples clean

IMAGE ?= premisan0/kube-blackbox:latest

all: test build

test:
	go test -v ./...

build:
	go build -o bin/kube-blackbox main.go

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
	kubectl apply -R -f samples/

delete-samples:
	kubectl delete -R -f samples/ --ignore-not-found
