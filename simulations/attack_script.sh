#!/bin/bash
# Simulating Brute-Force Authentication Attempt (T1)
for i in {1..5}; do
  curl -X POST "http://localhost:8080/login?user_id=attacker1&success=false"
done
