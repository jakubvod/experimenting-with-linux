#🛠️ PROJECTS

## SSH & SUDO LOG ANALYZER
- A security tool that automatically parses system authentication logs to identify potential breach attempts.
- Scans auth.log file using Regular Expressions to detect failed SSH login attempts and unauthorized sudo executions.
  
**What it does:** It digs through the system `auth.log` and pulls out failed login attempts.

**Why I made it:** I wanted to practice using **Regular Expressions** (Regex) in Python and try to write a script in Bash.

**How it works:** The **Python** script does the parsing and counting attempts. The **Bash** script acts as a "wrapper" that makes sure you have the right permissions to read the logs before starting the analysis.

> Technologies: Python 3.12.3, Bash, Regular Expressions (Regex).

> ⚠️ Note: It only works in specific `auth.log` format (I've tested it on my Linux Mint) + it currently assumes the logs file is located at `/var/log/auth.log`.

# 🔧 Setup
