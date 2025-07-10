#!/usr/bin/env bash
cd ./node_modules/@railgun-reloaded/cryptography \
  && npm install \
  && npx patch-package \
  && npm run build \
  && cd ../../.. \
  && cd ./node_modules/@railgun-reloaded/0zk-addresses \
  && npm install \
  && npm run build
