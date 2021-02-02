all: jwtex-build
.PHONY: jwtex-build
jwtex-build:
	@docker build . -t jwtex-app
