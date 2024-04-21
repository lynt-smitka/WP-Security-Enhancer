# WP-Security-Enhancer

Readme in progress... 😀

More details: https://smitka.me/2024/04/05/13-extra-things-we-do-for-better-wordpress-security/

This repository contains 2 mu plugins.

## lynt-security-enhancer.php
- contains functions for hashing passwords using bcrypt
- filtering sensitive data from rest api
- automatic logout if a user connects from another IP
- more careful verification that requests for admistration functions really come from the user

## lynt-audit-logger.php ==
- simple audit logging system which sends events into your php error log

