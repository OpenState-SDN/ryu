#!/bin/bash
watch -n1 --color dpctl tcp:127.0.0.1:6634 stats-state table=all tcp_dst=2000 -c
