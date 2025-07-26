import pandas as pd
import joblib
import tldextract
from extract import extract_features
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import LabelEncoder
import time

# Load dataset
df = pd.read_csv("urldata.csv", dtype={"url": str, "label": str}, low_memory=False)

# Clean URLs
df.loc[df['url'] == 'http://ladiesfirst-privileges[.]com/656465/d5678h9.exe', 'url'] = 'http://ladiesfirst-privileges.com/656465/d5678h9.exe'

"""select = df.query("label == 'benign'")
mod = []
ind = []
index = -1
for sel in select['url']:
    index += 1
    sub, dom, suf = tldextract.extract(sel).subdomain, tldextract.extract(sel).domain, tldextract.extract(sel).suffix
    if not sel.endswith(f"{sub}.{dom}.{suf}"):
        continue
    else:
        df.loc[index, 'url'] = sel + "/"""

# Extract features from URLs
X = df["url"].apply(extract_features).tolist()
y = df["label"]

# Encode target labels
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)

# Split the data
X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.3, random_state=42)

start_time = time.time()
# Train the Random Forest model
rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
rf.fit(X_train, y_train)
end_time = time.time()
elapsed_time = end_time - start_time

# Evaluate the model
y_pred = rf.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Model Accuracy: {accuracy:.4f}")

# Save the trained model and label encoder
joblib.dump(rf, "random_forest_model.pkl")
joblib.dump(label_encoder, "label_encoder.pkl")
print("Model and label encoder saved.")
minutes, seconds = divmod(elapsed_time, 60)
print(f"\n⏱️ Training completed in {int(minutes)} min {seconds:.4f} sec.")

# Check for problematic URLs
"""bad_count = 0
for url in df['url']:
    try:
        if not url.startswith("http"):
            _ = urlparse("http://" + str(url))
    except ValueError:
        bad_count += 1

print(f"Number of problematic URLs: {bad_count}")
"""