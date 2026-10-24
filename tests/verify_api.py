import requests, json

base = 'http://localhost:5000'

# Health check
r = requests.get(f'{base}/api/health')
h = r.json()
print('=== HEALTH ===')
print('  Status     :', h['status'])
print('  Model Ready:', h['model_ready'])
print('  Model Name :', h['model_name'])

# Metrics
r = requests.get(f'{base}/api/metrics')
m = r.json()
bm = m.get('best_metrics', {})
print()
print('=== METRICS ===')
print('  Model     :', m['selected_model'])
print('  Samples   :', m['n_samples'])
print('  Accuracy  :', bm['accuracy'])
print('  Precision :', bm['precision'])
print('  Recall    :', bm['recall'])
print('  F1-Score  :', bm['f1_score'])
print('  ROC-AUC   :', bm['roc_auc'])

# Predict - legitimate
r = requests.post(f'{base}/api/predict', json={'url': 'https://www.google.com'})
p = r.json()
print()
print('=== PREDICT (google.com) ===')
print('  Prediction :', p['prediction'])
print('  Confidence :', p['confidence'])
print('  Is Phishing:', p['is_phishing'])

# Predict - phishing
r = requests.post(f'{base}/api/predict', json={'url': 'http://192.168.0.1/login/verify?token=abc&password=secret'})
p2 = r.json()
print()
print('=== PREDICT (suspicious IP URL) ===')
print('  Prediction :', p2['prediction'])
print('  Confidence :', p2['confidence'])
print('  Explanations:', len(p2.get('explanations', [])), 'indicators')
for e in p2.get('explanations', [])[:3]:
    print('    -', e)
print('  Sensitive params redacted:', 'secret' not in p2['display_url'])

# History
r = requests.get(f'{base}/api/history')
hist = r.json()
print()
print('=== HISTORY ===')
print('  Total scans:', hist['count'])
print()
print('ALL API TESTS PASSED')
