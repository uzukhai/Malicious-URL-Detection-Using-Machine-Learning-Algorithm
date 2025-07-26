import joblib
import pandas as pd
from urllib.parse import urlparse, urlunparse
import tldextract
from extract import extract_features
import sys
import re
import string

# Load trained model and label encoder
rf_model = joblib.load("random_forest_model.pkl")
label_encoder = joblib.load("label_encoder.pkl")

# Load new URLs for prediction (Replace "new_urls.csv" with your actual file)
#new_df = pd.read_csv("predict.csv", dtype={"url": str, "type": str}, low_memory=False)  

# Extract features
#X_new = new_df["url"].apply(extract_features).tolist()
#url = "https://www.cybersecurity.my/"
url = sys.argv[1]
def is_url(c):
    try:
        result = urlparse(c)
        return all([result.scheme, result.netloc])
    except:
        return False
if is_url(str(url)) == False:
    print(f"Invalid URL format.")
else:
    def normalize_url(url):
        parsed = urlparse(url)
        # Remove trailing slash ONLY if it's the only path
        path = '' if parsed.path == '/' else parsed.path
        normalized = urlunparse(parsed._replace(path=path))
        return normalized

    features = extract_features(normalize_url(url.strip()))

    # Predict
    predictions = rf_model.predict([features])

    # Convert numeric predictions back to labels
    predicted_labels = label_encoder.inverse_transform(predictions)

    # Display results
    """new_df["predicted_type"] = predicted_labels
    print(new_df[["url", "predicted_type"]])

    # Save predictions to CSV
    new_df.to_csv("predictions.csv", index=False)
    print("Predictions saved to 'predictions.csv'.")
    """
    print(f"{predicted_labels[0]}")