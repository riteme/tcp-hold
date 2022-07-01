#!/bin/bash

# limit=32MiB
nl-qdisc-add --dev=inner0 --parent=root plug --limit=33554432
