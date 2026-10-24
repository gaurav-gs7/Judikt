.PHONY: test skill-acceptance skill-package demo demo-recording eval attackbench-smoke performance-smoke failure-test interop-community dashboard real-mcp trace docker-build observability-up observability-down helm-template aws-build-push aws-deploy aws-delete terraform-deploy terraform-destroy terraform-fmt serverless-package serverless-deploy serverless-destroy serverless-fmt

test:
	./scripts/run_release_tests.sh

skill-acceptance:
	./scripts/run_skill_acceptance.sh

skill-package:
	./scripts/python.sh scripts/build_skill_release.py --output-dir dist

demo:
	./scripts/run_demo.sh --audit-db /tmp/judikt-demo.db

demo-recording:
	PYTHONPATH=src ./scripts/python.sh scripts/record_demo.py

eval:
	./scripts/run_evals.sh

attackbench-smoke:
	./scripts/run_attackbench.sh tests/fixtures/attackbench_smoke.jsonl build/attackbench-smoke.json

performance-smoke:
	./scripts/run_performance_benchmark.sh build/performance-smoke.json --iterations 25 --warmup 5 --max-p99-ms 100 --min-throughput 10

failure-test:
	./scripts/run_failure_tests.sh

interop-community:
	./scripts/run_community_interop.sh --output build/community-interop.json

dashboard:
	./scripts/run_dashboard.sh

real-mcp:
	./scripts/run_real_mcp_http.sh

trace:
	JUDIKT_TELEMETRY=console ./scripts/run_demo.sh --audit-db /tmp/judikt-trace.db

docker-build:
	docker build -t judikt:local .

observability-up:
	docker compose -f deploy/observability/docker-compose.yml up --build

observability-down:
	docker compose -f deploy/observability/docker-compose.yml down

helm-template:
	helm template judikt charts/judikt \
		--set-string auth.bearerToken=local-render-token \
		--set-string auth.resourceUri=http://127.0.0.1:8080/mcp \
		--set-string approvalSecret=local-render-approval-secret-at-least-32-bytes \
		--set-string audit.hmacSecret=local-render-independent-audit-secret

aws-build-push:
	./scripts/aws/build_push_ecr.sh

aws-deploy:
	@if [ -z "$$IMAGE_URI" ]; then echo "usage: make aws-deploy IMAGE_URI=<ecr-image-uri>"; exit 2; fi
	./scripts/aws/deploy_ec2.sh "$$IMAGE_URI"

aws-delete:
	./scripts/aws/delete_stack.sh

terraform-deploy:
	./scripts/aws/deploy_terraform.sh

terraform-destroy:
	./scripts/aws/destroy_terraform.sh

terraform-fmt:
	terraform fmt -recursive infra/aws/terraform

serverless-package:
	./scripts/aws/package_serverless.sh

serverless-deploy:
	./scripts/aws/deploy_serverless.sh

serverless-destroy:
	./scripts/aws/destroy_serverless.sh

serverless-fmt:
	terraform fmt -recursive infra/aws/serverless
