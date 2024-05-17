.PHONY: default
default: demo

.PHONY: run_auth run_mixnet run_webserver demo
run_auth:
	source env/bin/activate && \
		gunicorn auth.frejaeid.app:app -b 127.0.0.1:8001

run_mixnet:
	source env/bin/activate && \
		python scripts/local_demo.py --post http://127.0.0.1:8000

run_webserver:
	source env/bin/activate && \
		env AUTH_SERVER_URL=http://127.0.0.1:8001 gunicorn webdemo.app:app

clean:
	rm -rf demoElection/* data.txt signatures.txt

demo:
	env PS1="> " tmux \
		new-session -s "demo_unverif" \
			"make clean; make run_mixnet" \; \
		split-window "make run_webserver" \; \
		split-window "make run_auth" \; \
		set-option status off

