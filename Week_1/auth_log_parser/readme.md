# Auth Log Parser

A lightweight Linux authentication log parser written in C.
This project is part of a broader Purple Team learning path focused on low‑level programming, log analysis, and understanding real-world attack footprints.

## 🎯 Purpose

- Strengthen C fundamentals (file I/O, buffers, string handling).

- Understand how Linux authentication logs are structured.

- Learn to detect patterns related to SSH activity and privilege escalation.

- Build practical Blue Team reflexes through real log parsing.

## 🧠 What It Does (Tier 1)

- Reads /var/log/auth.log line by line.

✔️ Counts occurences for these events:

    - Failed password

    - Accepted password

    - Invalid user

    - sudo:

## 📌 Future Improvements (Tier 2+)

- Count SSH failures / detect brute force attempts.

- Extract and aggregate IP addresses.

- Generate a simple alert-style report.

- Add timestamp parsing and JSON export.

## 💡 Learning Goals

- Practice safe C coding and parsing strategies.

- Recognize common authentication patterns and anomalies.

- Build a foundation for future DFIR, reverse engineering, and Purple Team tooling.