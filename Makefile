prepare:
	rm -rf pip-auth
ifeq ($(GITHUB_ACTIONS),true)
	echo "Running in GitHub Actions CI environment."
	echo 'git+https://github.com/kryptance/openslides-auth-service.git@main#egg=authlib&subdirectory=libraries/pip-auth' > requirements_authlib.txt
else
	echo '-e /pip-auth' > requirements_authlib.txt
	cp -r ../openslides-auth-service/libraries/pip-auth pip-auth
endif

clean:
	rm -rf pip-auth
	rm -f requirements_authlib.txt

build-dev:
	$(MAKE) prepare
	docker build . -f Dockerfile.dev --tag openslides-media-dev
	$(MAKE) clean

build-tests:
	$(MAKE) prepare
	docker build . -f Dockerfile.tests --tag openslides-media-tests
	$(MAKE) clean

build-dummy-autoupdate:
	docker build . -f tests/dummy_autoupdate/Dockerfile.dummy_autoupdate --tag openslides-media-dummy-autoupdate

start-test-setup: | build-dev build-tests build-dummy-autoupdate
	docker compose -f docker-compose.test.yml up -d
	docker compose -f docker-compose.test.yml exec -T tests wait-for-it "media:9006"

run-tests: | start-test-setup
	docker compose -f docker-compose.test.yml exec -T tests pytest

run-dev run-bash: | start-test-setup
	docker compose -f docker-compose.test.yml exec tests bash

check-black:
	docker compose -f docker-compose.test.yml exec -T tests black --check --diff src/ tests/

check-isort:
	docker compose -f docker-compose.test.yml exec -T tests isort --check-only --diff src/ tests/

flake8:
	docker compose -f docker-compose.test.yml exec -T tests flake8 src/ tests/

stop-tests:
	docker compose -f docker-compose.test.yml down

run-cleanup: | build-dev
	docker run -ti --entrypoint="" -v `pwd`/src:/app/src -v `pwd`/tests:/app/tests openslides-media-dev bash -c "./execute-cleanup.sh"
