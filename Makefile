autobahn-docker:
	cd tests/autobahn/ && bash start_server.sh

dev-install:
	cmake --preset gcc_dev_install
	cmake --build --preset gcc_dev_install
	cmake --install build/gcc/dev_install --config Release

test-close:
	. .venv/bin/activate && \
	cd tests/close && \
	bash run_test_close.sh
