#!/usr/bin/bash
set -o nounset -o errexit -o xtrace

python qp_test_pythonbuild.py && LD_PRELOAD=/usr/lib/libjemalloc.so.2 pytest  qp_test.py  --hypothesis-show-statistics -k TestTrees
