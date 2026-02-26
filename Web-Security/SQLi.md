# SQL Injection (SQLi)

## Definition
SQL Injection is a vulnerability that allows attackers to manipulate backend SQL queries through user input.

---

## Basic Example

Vulnerable query:
```
SELECT * FROM users WHERE username = '$user' AND password = '$pass';
```
Payload:
```
' OR 1=1 --
```
---

## Types of SQLi

### 1. Error-Based
Database errors reveal information.

### 2. Union-Based
Extract data using UNION SELECT.

Example:
```
' UNION SELECT null, database() --
```
### 3. Blind SQLi
No visible error output.

- Boolean-based
- Time-based

Example:
```
' AND SLEEP(5) --
```
---

## Impact
- Authentication bypass
- Data extraction
- Database deletion
- Remote code execution (rare but possible)

---

## Enumeration Steps

1. Identify injectable parameter
2. Determine number of columns
3. Extract database name
4. Extract tables
5. Extract sensitive data

---

## Prevention

- Prepared statements
- Parameterized queries
- ORM usage
- Least privilege database accounts

