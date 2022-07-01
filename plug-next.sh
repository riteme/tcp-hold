#!/bin/bash

nl-qdisc-add --dev=inner0 --parent=root --update plug --buffer
nl-qdisc-add --dev=inner0 --parent=root --update plug --release-one
