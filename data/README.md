# Dataset directory

Place the PhiUSIIL Phishing URL NLP Dataset here:

**Filename expected**: `PhiUSIIL_Phishing_URL_NLP_Dataset.csv`

**Source**: The PhiUSIIL (Phishing URL Identification System using Integrated Information Linguistics) dataset.

## Important Notes

- The training script (`scripts/train_url_model.py`) will auto-detect URL and label columns.
- Only URL-structural features are computed — no webpage fetching is performed.
- If the dataset is not present, the backend will operate in rule-only mode (the ML model will be unavailable). This is clearly communicated in API responses.

## Column Detection

The training script looks for columns named (case-insensitive): `url`, `urls`, `link`, `address` for the URL column, and `label`, `class`, `phishing`, `status`, `type`, `result` for the label column.

If your column names differ, update `url_col` and `label_col` manually in `scripts/train_url_model.py`.
