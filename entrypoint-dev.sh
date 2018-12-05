#!/bin/bash

chmod +x /app/wait-for-it.sh
npm install
/bin/bash /app/wait-for-it.sh mysql-db:3306 -t 300 -- bash startup.sh