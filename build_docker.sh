#!/bin/bash
docker build --tag=web_hyperlooped .
docker run -p 1337:1337 --rm --name=web_hyperlooped web_hyperlooped