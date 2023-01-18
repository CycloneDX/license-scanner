# SPDX-License-Identifier: Apache-2.0

SHELL:=/bin/bash -o pipefail

MK_TEMP=$(shell mktemp)
SET_OUTPUT=$(eval OUTPUT=$(MK_TEMP))

.PHONY: build
build: ## Build
	@echo =============================
	@echo ==== Running Build =====
	@echo =============================
	go build ./...

.PHONY: test
test: ## Run all the tests.
	@echo =============================
	@echo ==== Running Unit Tests =====
	@echo =============================
	go test ./... -tags=unit -count=1

.PHONY: test-verbose
test-verbose: ## Run all the tests.
	@echo =====================================
	@echo ==== Running Unit Tests Verbose =====
	@echo =====================================
	$(SET_OUTPUT)
	@echo "...FAILURES..." > ${OUTPUT}
	go test -v ./... -tags=unit -count=1 | tee -a ${OUTPUT} || (err=$$?; grep "FAIL" ${OUTPUT} || true; rm ${OUTPUT} && exit $$err)
	@rm ${OUTPUT}

.PHONY: prechecks
prechecks: ## Update the precheck files
	@echo ================================================
	@echo ==== Running Precheck Test with -args -fix =====
	@echo ================================================
	go test ./... -tags=prechecks -count=1 -args -fix

.PHONY: cover
cover: ## Run the code coverage
	@echo ================================
	@echo ==== Running Code Coverage =====
	@echo ================================
	go test ./... -tags=unit -cover

.PHONY: cover-report
cover-report: ## Generate the code coverage HTML report
	@echo ==========================================
	@echo ==== Generating Code Coverage Report =====
	@echo ==========================================
	go test ./... -tags=unit -coverprofile=coverage.out # coverage.out is the output filename
	go tool cover -html=coverage.out
