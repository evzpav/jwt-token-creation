#!/bin/bash

ssh-keygen -b 2048 -t rsa -f key
openssl rsa -in key -pubout -out key.pub.pem