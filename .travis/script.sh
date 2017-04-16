#!/usr/bin/env bash

set -e

go get -t ./...
if [ ${TESTMODE} == "unit" ]; then
  ginkgo -v -r --cover --randomizeAllSpecs --randomizeSuites --trace --progress --skipPackage integrationtests --skipMeasurements
fi

if [ ${TESTMODE} == "integration" ]; then
  ginkgo -v --randomizeAllSpecs --randomizeSuites --trace --progress -focus "Benchmark"
  ginkgo -v -r --randomizeAllSpecs --randomizeSuites --trace --progress integrationtests
fi
