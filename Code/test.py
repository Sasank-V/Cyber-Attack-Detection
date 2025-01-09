import joblib
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt
from train import CyberAttackDetector

# Load the saved model
detector = joblib.load('./cyber_attack_detector.joblib')
print("Model loaded successfully!")

# Load and preprocess the testing dataset
test_df = pd.read_csv('../Test Dataset/train_test_network.csv')
X_test_processed = detector.preprocess_data(test_df, training=False)
y_test = test_df['type']

# Make predictions
predictions = detector.predict(X_test_processed)

# Evaluate the model
report = classification_report(y_test, predictions)
cm = confusion_matrix(y_test, predictions)

print("\nClassification Report:")
print(report)

# Plot confusion matrix
plt.figure(figsize=(10, 8))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
plt.title('Confusion Matrix')
plt.ylabel('True Label')
plt.xlabel('Predicted Label')
plt.tight_layout()
plt.show()
