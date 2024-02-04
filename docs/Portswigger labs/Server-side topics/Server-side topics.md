---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 1
---

## SQL injection
  - SQL injection vulnerability in WHERE clause allowing retrieval of hidden data
  - SQL injection vulnerability allowing login bypass
  - SQL injection attack, querying the database type and version on Oracle
  - SQL injection attack, querying the database type and version on MySQL and Microsoft
  - SQL injection attack, listing the database contents on non-Oracle databases
  - SQL injection attack, listing the database contents on Oracle
  - SQL injection UNION attack, determining the number of columns returned by the query
  - SQL injection UNION attack, finding a column containing text
  - SQL injection UNION attack, retrieving data from other tables
  - SQL injection UNION attack, retrieving multiple values in a single column
    
## Business logic vulnerabilities
  - Excessive trust in client-side controls
  - High-level logic vulnerability
  - Inconsistent security controls
  - Flawed enforcement of business rules

## Authentication vulnerabilities
  - Username enumeration via different responses
  - 2FA simple bypass
  - Password reset broken logic
  - Username enumeration via subtly different responses

## Command Injection
  - OS command injection, simple case
  - Blind OS command injection with time delays
  - Blind OS command injection with output redirection

## Path Traversal
  - File path traversal, simple case
  - File path traversal, traversal sequences blocked with absolute path bypass
  - File path traversal, traversal sequences stripped non-recursively
  - File path traversal, traversal sequences stripped with superfluous URL-decode
  - File path traversal, validation of start of path
  - File path traversal, validation of file extension with null byte bypass

## Server-side request forgery
  - Basic SSRF against the local server
  - Basic SSRF against another back-end system
  - SSRF with blacklist-based input filter
  - Information disclosure
  - Information disclosure in error messages
  - Information disclosure on debug page
  - Source code disclosure via backup files
  - Authentication bypass via information disclosure

## Access control
  - Unprotected admin functionality
  - Unprotected admin functionality with unpredictable URL
  - User role controlled by request parameter
  - User role can be modified in user profile
  - User ID controlled by request parameter
  - User ID controlled by request parameter, with unpredictable user IDs
  - User ID controlled by request parameter with data leakage in redirect
  - User ID controlled by request parameter with password disclosure

## Insecure direct object references
  - URL-based access control can be circumvented
  - Method-based access control can be circumvented
  - Multi-step process with no access control on one step
  - Referer-based access control

## XXE injection
  - Exploiting XXE using external entities to retrieve files
  - Exploiting XXE to perform SSRF attacks
