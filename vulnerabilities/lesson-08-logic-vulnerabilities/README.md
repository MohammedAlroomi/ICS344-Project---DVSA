📌 Project Title

ICS-344 – DVSA Vulnerability Discovery and Remediation
Lesson #8: Logic Vulnerability (Race Condition)

⸻

📖 Overview

This project demonstrates and fixes a race condition vulnerability in the DVSA (Damn Vulnerable Serverless Application) order-processing workflow.

The vulnerability allows an attacker to:
	•	Modify an order while billing is in progress
	•	Create a mismatch between paid amount and final order contents

⸻

⚠️ Vulnerability Summary
	•	Type: Logic Vulnerability (Race Condition / TOCTOU)
	•	Affected Components:
	•	API Gateway
	•	AWS Lambda (order_billing.py, update_order.py)
	•	DynamoDB (DVSA-ORDERS-DB)

❌ Problem

The system:
	•	Reads order state
	•	Processes billing
	•	Allows concurrent update requests

👉 No locking → order can be modified during billing

⸻

💥 Exploit Scenario
	1.	Create order with 1 item
	2.	Add shipping
	3.	Send billing + update requests simultaneously
	4.	Update changes quantity to 5 items
	5.	Billing processes original value

👉 Result:
	•	User pays for 1 item
	•	Receives 5 items

⸻

🧪 Reproduction (Simplified)

# Create order
curl -X POST "$API" ...

# Add shipping
curl -X POST "$API" ...

# Run race condition
billing & update &
wait

Observed:

Billing → error / partial processing
Update → {"status":"ok","msg":"cart updated"}


⸻

🛠️ Fix Implementation

✔ Change 1 – Billing Lock

File: order_billing.py

ConditionExpression="orderStatus = :open_status"

👉 Ensures billing only proceeds if order is still open.

⸻

✔ Change 2 – Update Protection

File: update_order.py

ConditionExpression="orderStatus = :open_status"

👉 Prevents updates after billing starts.

⸻

✅ Verification After Fix

✔ Test 1 – Attack Fails

{"status":"err","msg":"invalid state transition"}

✔ Update rejected after billing

⸻

✔ Test 2 – Normal Flow Works

{"status":"ok","msg":"cart updated"}
{"status":"ok","msg":"address updated"}

✔ Legitimate workflow unaffected

⸻

📊 Evidence
	•	✔ Terminal outputs (race condition + fix verification)
	•	✔ DynamoDB record (itemList vs orderStatus)
	•	✔ Lambda code screenshots
	•	✔ CloudWatch logs (optional)

⸻

🧠 Key Security Concepts
	•	Race Conditions
	•	TOCTOU (Time-of-Check to Time-of-Use)
	•	Serverless concurrency risks
	•	DynamoDB conditional writes
	•	Atomic state validation

⸻

🔐 Mitigation Strategy
	•	Enforce state transitions
	•	Use DynamoDB ConditionExpression
	•	Apply defense in depth
	•	Prevent modification after billing starts

⸻

🎥 Demo Video

The demo video shows:
	1.	Vulnerability exploitation
	2.	DynamoDB evidence
	3.	Code fix
	4.	Verification after fix

⸻

⚙️ Environment
	•	AWS Lambda
	•	API Gateway
	•	DynamoDB
	•	DVSA (OWASP)

⸻

🚀 How to Run

export API="your-api-url"
export TOKEN="your-jwt"

bash race_test.sh


⸻

📚 Lessons Learned
	•	Logic flaws can be as dangerous as injection attacks
	•	Serverless systems require explicit concurrency control
	•	Database-level validation is critical for security

⸻

