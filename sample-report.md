# 🛡️ Shadow AI Exposure Report (Sample)

**Target:** `demo-dataset/`  
**Scan Date:** 2026-03-04 13:00:00  
**Files Scanned:** 6  
**Total Indicators Found:** 9  

---

## 📊 Executive Summary
This report identifies potential "Shadow AI" usage—unauthorized or unmanaged AI integration that can lead to data leakage, regulatory non-compliance, or security vulnerabilities.

| Category | Indicator Type | Count | Severity |
| :--- | :--- | :--- | :--- |
| GitHub PAT | api key | 1 | 🔴 CRITICAL |
| OpenAI Project | api key | 1 | 🔴 CRITICAL |
| openai | library | 2 | 🟡 MEDIUM |
| langchain | library | 1 | 🟡 MEDIUM |
| hardcoded_prompt | prompt | 4 | ⚪ LOW |

---

## 🔍 Detailed Findings

### 🚨 CRITICAL (Immediate Action Required)
- **OpenAI Project** in `demo-dataset/.env:2`
  > `OPENAI_API_KEY=[REDACTED OpenAI Project KEY]`

- **GitHub PAT** in `demo-dataset/.env:3`
  > `GITHUB_TOKEN=[REDACTED GitHub PAT KEY]`

### MEDIUM
- **openai** in `demo-dataset/app.py:1`
  > `import openai`

- **langchain** in `demo-dataset/app.py:2`
  > `from langchain import PromptTemplate`

### LOW
- **hardcoded_prompt** in `demo-dataset/app.py:8`
  > `SYSTEM_PROMPT = "You are a helpful assistant."`

---

## 💡 Recommendations
1. **Rotate & remove exposed secrets** immediately.
2. **Implement an AI Acceptable Use Policy (AUP)** for employees.
3. **Continuous monitoring**: run scanning on every commit in CI/CD.

*Sample output for demonstration purposes.*
