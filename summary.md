# Summary 

## GitHub Repository
https://github.com/foppens/tatou

## GitHub Pull Action Workflow
https://github.com/foppens/tatou/pull/1
---

## Test cases
Create Watermark API Tests
	•	Happy path watermark creation
    •	Unsupported method
    •	Watermark not applicable
    •	Document not found
    •	File missing on disk


Read Watermark API Tests
	•	Happy path watermark extraction
	•	Document not found
	•	File missing on disk
	•	Watermark extraction failure
	•	Missing Required Fields
	•	Unsupported watermark method
	•	Forbidden access for non-owner
	•	Wrong Key

## Test & Coverage Command

The following command was used to run the unit tests and generate the HTML
branch coverage report for the **create-watermark** and **read-watermark** routes:

```bash
TEST_MODE=1 pytest \
  server/test/API/test_create_watermark_api.py \
  server/test/API/test_read_watermark_api.py \
  --cov=src.server \
  --cov-report=html:coverage-watermark

