# Understand Login Guard

## 1. What is a login log?

A login log is a record of someone trying to access an account. Each row says when the attempt happened, which account it targeted, where it came from and whether it worked.

An **IP address** identifies a network source. Several people can share one public IP, so it does not always identify one person.

## 2. What are we looking for?

Repeated failures in a short time can be worth investigating. Someone might be guessing a password, or a normal user might have forgotten it. The tool highlights the pattern; a person still needs to decide what happened.

The default rule is: **at least five failures from the same IP within five minutes**.

## 3. What is a rolling window?

Think of looking back five minutes whenever another failure arrives. The window moves with the latest event rather than starting only at clock times such as 09:00 and 09:05.

For example, failures at 09:03, 09:04, 09:05, 09:06 and 09:07 belong to one four-minute span. They match the default rule even though they cross 09:05.

## 4. Follow the sample

Run:

```bash
python login_guard.py samples/login_events.csv
```

1. There are 12 valid rows.
2. Four attempts succeed and eight fail.
3. IP `203.0.113.10` fails five times between 09:01 and 09:04.
4. That IP matches the rule and appears once in the report.
5. IP `198.51.100.50` fails at 09:00 and 09:10. Those attempts are too far apart for the default five-minute window, and there are only two failures.

## 5. Change one setting

Run:

```bash
python login_guard.py samples/login_events.csv --threshold 2 --window-minutes 10
```

You should now see **two flagged IP addresses**. The two failures from `198.51.100.50` count because they are exactly ten minutes apart, and the rule includes both boundaries.

Try explaining this result before opening the code.

## 6. Understand the Python ideas

| Idea | How it is used |
| --- | --- |
| Function | A named block that performs one task, such as reading a file |
| Dictionary | Stores an event with names such as `username` and `status` |
| List | Holds all valid events |
| Loop | Checks each event in turn |
| `datetime` | Represents time so the program can compare events |
| Queue (`deque`) | Keeps recent failures and removes old ones from the front |
| Exception | Reports a problem such as an invalid IP or missing file |
| Unit test | Checks that a known input produces the expected result |

## 7. Describe the project honestly

"Login Guard is an AI-assisted Python learning project that reads CSV login events and flags repeated failures from one IP in a rolling time window. It produces text or JSON reports and includes tests. I use it to learn log analysis and understand simple detection rules."

Practise explaining `read_events()`, the moving time window, and why a match does not prove an attack. Only claim you understand or implemented parts you can explain.
