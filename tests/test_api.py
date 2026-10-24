"""
tests/test_api.py
Integration tests for the Flask REST API.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import json
import sqlite3
import tempfile
import threading
import time
import pytest

# Configure test database before importing app
os.environ['TESTING'] = '1'


@pytest.fixture(scope="module")
def client():
    """Create a Flask test client."""
    # Patch DB path to use a temp file
    import app as flask_app

    # Use a temp DB for tests
    tmp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
    tmp_db.close()
    flask_app.DB_PATH = flask_app.Path(tmp_db.name)

    flask_app.init_db()
    flask_app.load_model()  # loads model if available, else None

    flask_app.app.config['TESTING'] = True
    with flask_app.app.test_client() as c:
        yield c

    # Cleanup
    os.unlink(tmp_db.name)


class TestHealthEndpoint:
    def test_health_returns_200(self, client):
        res = client.get('/api/health')
        assert res.status_code == 200

    def test_health_json_keys(self, client):
        res = client.get('/api/health')
        data = json.loads(res.data)
        assert 'status' in data
        assert 'model_ready' in data
        assert 'timestamp' in data

    def test_health_status_ok(self, client):
        res = client.get('/api/health')
        data = json.loads(res.data)
        assert data['status'] == 'ok'


class TestPredictEndpoint:
    def test_predict_requires_json(self, client):
        res = client.post('/api/predict',
                          data='not json',
                          content_type='text/plain')
        assert res.status_code == 415

    def test_predict_empty_url(self, client):
        res = client.post('/api/predict',
                          json={'url': ''},
                          content_type='application/json')
        assert res.status_code == 400

    def test_predict_missing_url(self, client):
        res = client.post('/api/predict',
                          json={},
                          content_type='application/json')
        assert res.status_code == 400

    def test_predict_url_too_long(self, client):
        res = client.post('/api/predict',
                          json={'url': 'http://a.com/' + 'x' * 2500},
                          content_type='application/json')
        assert res.status_code == 400

    def test_predict_valid_url_no_model(self, client):
        """When no model is trained, should return 503 or 200 with features."""
        res = client.post('/api/predict',
                          json={'url': 'https://google.com'},
                          content_type='application/json')
        # Either 200 (with model) or 503 (no model) is acceptable
        assert res.status_code in (200, 503)
        data = json.loads(res.data)
        assert 'status' in data

    def test_predict_valid_url_returns_features(self, client):
        res = client.post('/api/predict',
                          json={'url': 'https://google.com'},
                          content_type='application/json')
        data = json.loads(res.data)
        # If model ready, features should be present
        if data.get('status') == 'ok':
            assert 'features' in data
            assert 'display_url' in data
            assert 'disclaimer' in data

    def test_predict_phishing_url_structure(self, client):
        """Test that phishing URL returns correct structure."""
        res = client.post('/api/predict',
                          json={'url': 'http://192.168.0.1/login/verify?token=abc'},
                          content_type='application/json')
        data = json.loads(res.data)
        if data.get('status') == 'ok':
            assert 'prediction' in data
            assert 'confidence' in data
            assert 'explanations' in data
            assert 'is_phishing' in data
            assert isinstance(data['is_phishing'], bool)

    def test_predict_https_url(self, client):
        res = client.post('/api/predict',
                          json={'url': 'https://github.com/login'},
                          content_type='application/json')
        assert res.status_code in (200, 503)

    def test_predict_http_url(self, client):
        res = client.post('/api/predict',
                          json={'url': 'http://example.com/page'},
                          content_type='application/json')
        assert res.status_code in (200, 503)

    def test_predict_ip_url(self, client):
        res = client.post('/api/predict',
                          json={'url': 'http://192.168.1.1/admin'},
                          content_type='application/json')
        assert res.status_code in (200, 503)
        data = json.loads(res.data)
        if data.get('status') == 'ok' and 'features' in data:
            assert data['features']['is_ip_address'] == 1

    def test_predict_suspicious_word_url(self, client):
        res = client.post('/api/predict',
                          json={'url': 'http://phish.xyz/login/verify/secure'},
                          content_type='application/json')
        assert res.status_code in (200, 503)
        data = json.loads(res.data)
        if data.get('status') == 'ok' and 'features' in data:
            assert data['features']['has_suspicious_word'] == 1

    def test_predict_url_without_scheme(self, client):
        """URL without scheme should be auto-prefixed."""
        res = client.post('/api/predict',
                          json={'url': 'google.com'},
                          content_type='application/json')
        assert res.status_code in (200, 503)

    def test_predict_sensitive_params_redacted(self, client):
        """Passwords in query params should be redacted in display_url."""
        res = client.post('/api/predict',
                          json={'url': 'http://example.com/?password=secret123'},
                          content_type='application/json')
        data = json.loads(res.data)
        if 'display_url' in data:
            assert 'secret123' not in data['display_url']

    def test_predict_url_with_newline_rejected(self, client):
        res = client.post('/api/predict',
                          json={'url': 'http://example.com\nmalicious'},
                          content_type='application/json')
        assert res.status_code == 400


class TestMetricsEndpoint:
    def test_metrics_returns_valid_status(self, client):
        res = client.get('/api/metrics')
        assert res.status_code in (200, 503)
        data = json.loads(res.data)
        assert 'status' in data

    def test_metrics_with_model_has_keys(self, client):
        res = client.get('/api/metrics')
        data = json.loads(res.data)
        if data['status'] == 'ok':
            assert 'selected_model' in data
            assert 'best_metrics' in data
            assert 'all_model_results' in data
            assert 'feature_names' in data

    def test_metrics_without_model_returns_503(self, client):
        """When no model is trained, should return 503 with helpful message."""
        import app as flask_app
        original = flask_app._metadata
        flask_app._metadata = None
        try:
            res = client.get('/api/metrics')
            assert res.status_code == 503
            data = json.loads(res.data)
            assert data['status'] == 'no_model'
            assert 'message' in data
        finally:
            flask_app._metadata = original


class TestHistoryEndpoint:
    def test_history_get_returns_200(self, client):
        res = client.get('/api/history')
        assert res.status_code == 200

    def test_history_has_list(self, client):
        res = client.get('/api/history')
        data = json.loads(res.data)
        assert 'history' in data
        assert isinstance(data['history'], list)

    def test_history_has_count(self, client):
        res = client.get('/api/history')
        data = json.loads(res.data)
        assert 'count' in data

    def test_history_limit_param(self, client):
        res = client.get('/api/history?limit=5')
        assert res.status_code == 200

    def test_history_delete_clears(self, client):
        # First add some data via predict (may or may not succeed)
        client.post('/api/predict', json={'url': 'http://test-history.com'},
                    content_type='application/json')

        res = client.delete('/api/history')
        assert res.status_code == 200
        data = json.loads(res.data)
        assert data['status'] == 'ok'

        # Verify empty
        res2 = client.get('/api/history')
        data2 = json.loads(res2.data)
        assert data2['count'] == 0

    def test_history_saves_after_scan(self, client):
        """After a successful scan, history count should increase."""
        # Clear first
        client.delete('/api/history')

        import app as flask_app
        if not flask_app.model_ready():
            pytest.skip("Model not trained — history save requires model.")

        client.post('/api/predict',
                    json={'url': 'https://example.com/test'},
                    content_type='application/json')
        res = client.get('/api/history')
        data = json.loads(res.data)
        assert data['count'] >= 1


class TestTrainEndpoint:
    def test_train_requires_json(self, client):
        res = client.post('/api/train', data='not json', content_type='text/plain')
        assert res.status_code == 415

    def test_train_missing_dataset_returns_404(self, client):
        res = client.post('/api/train',
                          json={'dataset': 'data/nonexistent.csv', 'target_column': 'label'},
                          content_type='application/json')
        assert res.status_code == 404

    def test_train_path_traversal_blocked(self, client):
        res = client.post('/api/train',
                          json={'dataset': '../secret.csv', 'target_column': 'label'},
                          content_type='application/json')
        assert res.status_code in (403, 404)

    def test_train_absolute_path_blocked(self, client):
        res = client.post('/api/train',
                          json={'dataset': 'C:/Windows/secret.csv', 'target_column': 'label'},
                          content_type='application/json')
        assert res.status_code in (403, 404)


class TestPageRoutes:
    def test_home_page(self, client):
        res = client.get('/')
        assert res.status_code == 200
        assert b'PhishGuard' in res.data

    def test_scanner_page(self, client):
        res = client.get('/scanner')
        assert res.status_code == 200

    def test_performance_page(self, client):
        res = client.get('/performance')
        assert res.status_code == 200

    def test_history_page(self, client):
        res = client.get('/history')
        assert res.status_code == 200

    def test_about_page(self, client):
        res = client.get('/about')
        assert res.status_code == 200
